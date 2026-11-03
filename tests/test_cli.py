"""Tests for frame formatting in the CLI (the layered decode path)."""

from __future__ import annotations

import struct

from sniffer.capture import PacketType, RawFrame
from sniffer.cli import format_frame
from tests.packets import build_ipv4

MACS = bytes.fromhex("02fc0000000502fc00000001")


def frame(payload: bytes, ethertype: int = 0x0800, pkttype: int = 0) -> RawFrame:
    data = MACS + struct.pack("!H", ethertype) + payload
    return RawFrame(data=data, timestamp=0.0, interface="eth0", pkttype=pkttype)


def test_ipv4_frame_shows_ip_summary() -> None:
    line = format_frame(1, frame(build_ipv4()))
    assert "192.0.2.2 -> 160.79.104.10 TCP" in line
    assert "chk=ok" in line


def test_non_ip_frame_shows_ethernet_summary() -> None:
    line = format_frame(1, frame(b"\x00" * 28, ethertype=0x0806))
    assert "ARP" in line


def test_outgoing_bad_checksum_labelled_offload() -> None:
    bad = build_ipv4(checksum=0)
    assert "chk=offload" in format_frame(1, frame(bad, pkttype=PacketType.OUTGOING))
    assert "chk=BAD" in format_frame(1, frame(bad, pkttype=PacketType.HOST))


def test_malformed_ip_does_not_raise() -> None:
    line = format_frame(1, frame(b"\x45\x00"))
    assert "<malformed:" in line


def test_show_ethernet_adds_mac_line() -> None:
    line = format_frame(1, frame(build_ipv4()), show_ethernet=True)
    assert "02:fc:00:00:00:01 -> 02:fc:00:00:00:05" in line
