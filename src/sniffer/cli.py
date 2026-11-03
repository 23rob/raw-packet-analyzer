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
from sniffer.capture import RawSocketCapture
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


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
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
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable debug logging"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


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
    prints periodic health stats, and turns Ctrl+C into a clean drain.
    """
    with RawSocketCapture(
        interface=args.interface, promiscuous=args.promiscuous
    ) as capture:
        pipeline = Pipeline(
            capture,
            _build_sinks(args),
            workers=args.workers,
            queue_size=args.queue_size,
            count=args.count,
        )
        logger.info(
            "Capturing on %s%s with %d decoder thread(s). Press Ctrl+C to stop.",
            args.interface or "all interfaces",
            " (promiscuous)" if args.promiscuous else "",
            args.workers,
        )
        pipeline.start()
        interrupted = False
        next_report = time.monotonic() + args.stats if args.stats else None
        try:
            while not pipeline.wait(timeout=_SUPERVISOR_TICK_S):
                if next_report is not None and time.monotonic() >= next_report:
                    logger.info("stats: %s", pipeline.stats().summary())
                    next_report += args.stats
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
