"""Demonstrate the detection engine end-to-end, with no network at all.

This feeds pre-built packet *bytes* through the real pipeline and detector,
exactly as if they had come off a socket, and prints the alerts. It sends no
traffic anywhere: every "packet" is a byte string constructed in memory, so
it is safe to run as an unprivileged user on any machine::

    python examples/detection_demo.py

It exists to show the wiring (capture -> decode -> detector -> alert) works
together, not just rule by rule in the unit tests. The scenarios below use
documentation/test IP ranges (RFC 5737) so nothing resembles a real host.
"""

from __future__ import annotations

import socket
import struct
import sys
from collections.abc import Iterator

sys.path.insert(0, "src")

from sniffer.alerts import AlertDispatcher, ConsoleAlertOutput, DetectorSink
from sniffer.capture import KernelStats, RawFrame
from sniffer.detection import DetectionConfig, Detector
from sniffer.pipeline import Pipeline

# Minimal in-file frame builders (the test helpers aren't importable here).
_ETH = bytes.fromhex("02fc0000000502fc00000001") + struct.pack("!H", 0x0800)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return int(~total & 0xFFFF)


def _frame(src: str, dst: str, sport: int, dport: int, flags: int) -> RawFrame:
    src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 1024, 0, 0)
    pseudo = struct.pack("!4s4sxBH", src_b, dst_b, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]
    ihl_tl = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src_b, dst_b
    )
    ip = ihl_tl[:10] + struct.pack("!H", _checksum(ihl_tl)) + ihl_tl[12:]
    return RawFrame(_ETH + ip + tcp, timestamp=0.0, interface="demo", pkttype=0)


class ScriptedSource:
    """A FrameSource that replays a fixed list of frames, then idles."""

    def __init__(self, frames: list[RawFrame]) -> None:
        self._frames: Iterator[RawFrame] = iter(frames)

    def recv(self) -> RawFrame | None:
        """Return the next scripted frame, or None once they run out."""
        return next(self._frames, None)

    def kernel_stats(self) -> KernelStats | None:
        """No kernel stats for a scripted source."""
        return None


def scenario(title: str, frames: list[RawFrame], config: DetectionConfig) -> None:
    """Run one batch of frames through a fresh pipeline and print alerts."""
    print(f"\n=== {title} ({len(frames)} packets) ===")
    dispatcher = AlertDispatcher([ConsoleAlertOutput(sys.stdout)])
    detector = Detector(config)
    pipeline = Pipeline(ScriptedSource(frames), [DetectorSink(detector, dispatcher)])
    pipeline.start()
    pipeline.stop()
    dispatcher.close()
    print(f"    {detector.stats.summary()}")


def main() -> int:
    """Run three detection scenarios through the real pipeline."""
    victim = "198.51.100.10"

    # Each spoofed source is a distinct documentation-range address.
    def src(i: int) -> str:
        return socket.inet_ntoa(struct.pack("!I", 0xCB000100 + i))

    flood = [_frame(src(i), victim, 40000, 80, 0x02) for i in range(300)]
    scenario("Spoofed SYN flood", flood, DetectionConfig(syn_flood_threshold=100))

    scan = [_frame("203.0.113.5", victim, 50000, port, 0x02) for port in range(1, 60)]
    scenario("Vertical port scan", scan, DetectionConfig(vertical_scan_ports=20))

    xmas = [_frame("203.0.113.9", victim, 50000, 80, 0x29)]
    scenario("Xmas probe (single packet)", xmas, DetectionConfig())
    return 0


if __name__ == "__main__":
    sys.exit(main())
