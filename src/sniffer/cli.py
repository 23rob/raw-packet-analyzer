"""Command-line entry point: ``sudo python -m sniffer -i eth0 -c 10``.

This module is the only place that knows about ``argparse``, ``print`` and
exit codes. Capture and parsing live in their own modules and know nothing
about the terminal. That separation (thin I/O shell, pure core) is what lets
us test the core without a terminal or root, and later swap the output for
a JSON log or a threaded pipeline without touching the parsers.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from datetime import datetime, timezone

from sniffer import __version__
from sniffer.capture import PacketType, RawFrame, RawSocketCapture
from sniffer.decode import Transport, decode_frame
from sniffer.exceptions import PacketParseError, SnifferError
from sniffer.protocols.ipv4 import IPv4Packet
from sniffer.protocols.tcp import TCPSegment
from sniffer.protocols.udp import UDPDatagram
from sniffer.utils.hexdump import hexdump

logger = logging.getLogger("sniffer")

# Exit codes. 0 = success; 1 = expected failure (permissions, bad interface);
# 130 = interrupted by Ctrl+C (128 + SIGINT's number, 2, a Unix convention).
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130


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
        type=int,
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
        "-v", "--verbose", action="store_true", help="enable debug logging"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def _checksum_label(valid: bool | None, pkttype: int) -> str:
    """Turn a checksum result into ``ok``, ``BAD``, ``offload`` or ``n/a``.

    Checksum offload: the kernel copies outgoing packets to sniffers BEFORE
    the NIC finishes the TCP/UDP checksum (the field holds only the partial
    pseudo-header sum, the kernel's CHECKSUM_PARTIAL state). So a "bad"
    checksum on an OUTGOING packet is expected, not an attack. Labelling it
    honestly avoids a flood of false alarms.
    """
    if valid is None:
        return "n/a"
    if valid:
        return "ok"
    return "offload" if pkttype == PacketType.OUTGOING else "BAD"


def _endpoint(ip: IPv4Packet, transport: Transport | None) -> str:
    """``a.b.c.d:port -> e.f.g.h:port``, or bare addresses without ports."""
    if isinstance(transport, (TCPSegment, UDPDatagram)):
        return f"{ip.src}:{transport.src_port} -> {ip.dst}:{transport.dst_port}"
    return f"{ip.src} -> {ip.dst}"


def format_frame(index: int, frame: RawFrame, *, show_ethernet: bool = False) -> str:
    """Render one captured frame as a single summary line.

    All protocol logic lives in ``decode_frame``. This function only turns
    the decoded layers into text, so it is the only part that changes when
    the output format changes (to JSON logs in Milestone 4, for example).
    """
    ts = datetime.fromtimestamp(frame.timestamp, tz=timezone.utc).strftime(
        "%H:%M:%S.%f"
    )
    prefix = f"#{index:<5} {ts} {frame.interface:<8} {frame.direction:<9}"
    try:
        pkt = decode_frame(frame.data)
    except PacketParseError as exc:
        # A malformed frame must never crash a sniffer: log it and move on.
        # Attackers send malformed packets precisely to crash parsers.
        return f"{prefix} <malformed: {exc}>"

    ip = pkt.ip
    if ip is None:
        return f"{prefix} {pkt.ethernet.summary()}"

    ip_chk = _checksum_label(ip.checksum_valid, frame.pkttype)
    parts = [prefix, _endpoint(ip, pkt.transport), ip.protocol_name]
    if pkt.transport is not None:
        parts.append(pkt.transport.summary())
        l4_chk = (
            "partial"
            if pkt.transport_checksum_partial
            else _checksum_label(pkt.transport_checksum_valid, frame.pkttype)
        )
    elif pkt.transport_error is not None:
        parts.append(f"<malformed {ip.protocol_name}: {pkt.transport_error}>")
        l4_chk = "n/a"
    else:
        l4_chk = "n/a"
    if ip.is_fragment:
        parts.append(f"frag@{ip.fragment_offset}{'+MF' if ip.more_fragments else ''}")
    parts.append(f"ttl={ip.ttl} chk={ip_chk}/{l4_chk}")
    line = " ".join(parts)
    if show_ethernet:
        line += f"\n{'':>41}{pkt.ethernet.summary()}"
        line += f"\n{'':>41}{ip.summary()}"
    return line


def run(args: argparse.Namespace) -> int:
    """Capture loop. Returns a process exit code."""
    with RawSocketCapture(
        interface=args.interface, promiscuous=args.promiscuous
    ) as capture:
        logger.info(
            "Capturing on %s%s. Press Ctrl+C to stop.",
            args.interface or "all interfaces",
            " (promiscuous)" if args.promiscuous else "",
        )
        for index, frame in enumerate(capture.frames(args.count), start=1):
            print(format_frame(index, frame, show_ethernet=args.ethernet))
            if args.hexdump:
                print(hexdump(frame.data, max_bytes=args.hexdump_bytes), end="\n\n")
    return EXIT_OK


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
        # The `with` block has already closed the socket by the time we
        # get here, so promiscuous mode is already off.
        logger.info("Stopped by user.")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
