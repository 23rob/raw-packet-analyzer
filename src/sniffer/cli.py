"""Command-line entry point: ``sudo python -m sniffer -i eth0 -c 10``.

This module is the only place that knows about ``argparse`` and exit codes.
Capture, parsing, the threaded pipeline and output sinks live in their own
modules. That separation (thin I/O shell, pure core) is what let Milestone 4
add threads and JSON logging without touching a single parser.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Sequence

from sniffer import __version__
from sniffer.alerts import (
    AlertDispatcher,
    AlertOutput,
    ConsoleAlertOutput,
    DetectorSink,
    JsonAlertOutput,
)
from sniffer.capture import RawSocketCapture
from sniffer.detection import DetectionConfig, Detector, HealthMonitor
from sniffer.exceptions import SnifferError
from sniffer.pipeline import DEFAULT_QUEUE_SIZE, DEFAULT_WORKERS, Pipeline, Sink
from sniffer.sinks import ConsoleSink, JsonLinesSink

logger = logging.getLogger("sniffer")

# Exit codes. 0 = success; 1 = expected failure (permissions, bad interface);
# 130 = interrupted by Ctrl+C (128 + SIGINT's number, 2, a Unix convention).
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130

_SUPERVISOR_TICK_S = 0.5
_HEALTH_INTERVAL_S = 5.0  # how often the main thread checks for packet loss


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="Raw-socket packet sniffer and traffic analyzer.",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="interface to capture on, e.g. eth0 (default: all interfaces)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=_positive_int,
        default=None,
        help="stop after this many frames (default: run until Ctrl+C)",
    )
    parser.add_argument(
        "-p",
        "--promiscuous",
        action="store_true",
        help="put the interface in promiscuous mode (requires -i)",
    )
    parser.add_argument(
        "-e",
        "--ethernet",
        action="store_true",
        help="also show the Ethernet and full IPv4 layers for IP packets",
    )
    parser.add_argument(
        "-x",
        "--hexdump",
        action="store_true",
        help="print a hex dump of each frame",
    )
    parser.add_argument(
        "--hexdump-bytes",
        type=int,
        default=64,
        metavar="N",
        help="bytes to show per hex dump (default: 64)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=_positive_int,
        default=DEFAULT_WORKERS,
        help=f"decoder threads (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--queue-size",
        type=_positive_int,
        default=DEFAULT_QUEUE_SIZE,
        metavar="N",
        help=f"max frames buffered between threads (default: {DEFAULT_QUEUE_SIZE})",
    )
    parser.add_argument(
        "-j",
        "--json",
        metavar="PATH",
        help="append every packet as a JSON line to PATH",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="no per-packet console output (useful with --json)",
    )
    parser.add_argument(
        "--stats",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="log pipeline health every SECONDS (default: off)",
    )
    _add_detection_arguments(parser)
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable debug logging"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def _add_detection_arguments(parser: argparse.ArgumentParser) -> None:
    defaults = DetectionConfig()
    group = parser.add_argument_group("threat detection (Milestone 5)")
    group.add_argument(
        "--no-detect", action="store_true", help="disable the detection engine"
    )
    group.add_argument(
        "--alerts",
        metavar="PATH",
        help="append every alert as a JSON line to PATH",
    )
    group.add_argument(
        "--window",
        type=_positive_float,
        default=defaults.window_s,
        metavar="SECONDS",
        help=f"sliding window for rate rules (default: {defaults.window_s:g})",
    )
    group.add_argument(
        "--syn-threshold",
        type=_positive_int,
        default=defaults.syn_flood_threshold,
        metavar="N",
        help="SYNs to one ip:port per window that count as a flood "
        f"(default: {defaults.syn_flood_threshold})",
    )
    group.add_argument(
        "--scan-ports",
        type=_positive_int,
        default=defaults.vertical_scan_ports,
        metavar="N",
        help="distinct ports on one host per window that count as a scan "
        f"(default: {defaults.vertical_scan_ports})",
    )
    group.add_argument(
        "--scan-hosts",
        type=_positive_int,
        default=defaults.horizontal_scan_hosts,
        metavar="N",
        help="distinct hosts on one port per window that count as a sweep "
        f"(default: {defaults.horizontal_scan_hosts})",
    )
    group.add_argument(
        "--cooldown",
        type=float,
        default=defaults.cooldown_s,
        metavar="SECONDS",
        help="minimum time between repeats of the same alert "
        f"(default: {defaults.cooldown_s:g})",
    )


def _build_detection(
    args: argparse.Namespace,
) -> tuple[AlertDispatcher, DetectorSink] | None:
    if args.no_detect:
        return None
    config = DetectionConfig(
        window_s=args.window,
        syn_flood_threshold=args.syn_threshold,
        vertical_scan_ports=args.scan_ports,
        horizontal_scan_hosts=args.scan_hosts,
        cooldown_s=args.cooldown,
    )
    outputs: list[AlertOutput] = [ConsoleAlertOutput()]
    if args.alerts is not None:
        outputs.append(JsonAlertOutput(args.alerts))
    dispatcher = AlertDispatcher(outputs)
    return dispatcher, DetectorSink(Detector(config), dispatcher)


def _build_sinks(args: argparse.Namespace) -> list[Sink]:
    sinks: list[Sink] = []
    if not args.quiet:
        sinks.append(
            ConsoleSink(
                show_ethernet=args.ethernet,
                hexdump_bytes=args.hexdump_bytes if args.hexdump else None,
            )
        )
    if args.json is not None:
        sinks.append(JsonLinesSink(args.json))
    return sinks


def run(args: argparse.Namespace) -> int:
    """Run the threaded pipeline. Returns a process exit code.

    The main thread only supervises: it waits in short slices so it stays
    responsive to Ctrl+C (Python delivers signals to the main thread only),
    prints periodic stats, checks sensor health, and turns Ctrl+C into a
    clean drain.
    """
    detection = _build_detection(args)
    try:
        return _run_pipeline(args, detection)
    finally:
        if detection is not None:
            dispatcher, detector_sink = detection
            logger.info("detection: %s", detector_sink.detector.stats.summary())
            dispatcher.close()


def _run_pipeline(
    args: argparse.Namespace,
    detection: tuple[AlertDispatcher, DetectorSink] | None,
) -> int:
    sinks = _build_sinks(args)
    health: HealthMonitor | None = None
    if detection is not None:
        sinks.append(detection[1])
        health = HealthMonitor()
    with RawSocketCapture(
        interface=args.interface, promiscuous=args.promiscuous
    ) as capture:
        pipeline = Pipeline(
            capture,
            sinks,
            workers=args.workers,
            queue_size=args.queue_size,
            count=args.count,
        )
        logger.info(
            "Capturing on %s%s with %d decoder thread(s), detection %s. "
            "Press Ctrl+C to stop.",
            args.interface or "all interfaces",
            " (promiscuous)" if args.promiscuous else "",
            args.workers,
            "off" if detection is None else "on",
        )
        pipeline.start()
        interrupted = False
        now = time.monotonic()
        next_report = now + args.stats if args.stats else None
        next_health = now + _HEALTH_INTERVAL_S
        try:
            while not pipeline.wait(timeout=_SUPERVISOR_TICK_S):
                now = time.monotonic()
                if next_report is not None and now >= next_report:
                    logger.info("stats: %s", pipeline.stats().summary())
                    next_report += args.stats
                if health is not None and detection is not None and now >= next_health:
                    stats = pipeline.stats()
                    detection[0].emit(
                        health.check(
                            stats.captured, stats.queue_dropped, stats.kernel_drops
                        )
                    )
                    next_health = now + _HEALTH_INTERVAL_S
        except KeyboardInterrupt:
            interrupted = True
            logger.info("Stopping: draining queued packets...")
        pipeline.stop()
        stats = pipeline.stats()

    logger.info("final: %s", stats.summary())
    if pipeline.error is not None:
        if isinstance(pipeline.error, SnifferError):
            raise pipeline.error
        raise SnifferError(f"Capture failed: {pipeline.error}") from pipeline.error
    return EXIT_INTERRUPTED if interrupted else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run, and convert errors into clean exit codes."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    try:
        return run(args)
    except SnifferError as exc:
        # Expected, user-fixable problems: no traceback, just the reason.
        logger.error("%s", exc)
        logger.debug("Details:", exc_info=True)  # full chain with -v
        return EXIT_ERROR
    except KeyboardInterrupt:
        # A second Ctrl+C during the drain lands here. The `with` block has
        # already closed the socket, so promiscuous mode is off.
        logger.info("Stopped by user.")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
