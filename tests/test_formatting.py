"""Tests for console formatting of decoded packets."""

from __future__ import annotations

from sniffer.capture import PacketType, RawFrame
from sniffer.formatting import format_frame
from tests.packets import build_frame, build_icmp, build_ipv4, build_tcp, build_udp
from tests.test_tcp import REAL_SYN

LOOPBACK = bytes([127, 0, 0, 1])


def frame(data: bytes, pkttype: int = PacketType.HOST) -> RawFrame:
    return RawFrame(data=data, timestamp=0.0, interface="eth0", pkttype=pkttype)


def test_tcp_line_shows_ports_flags_and_checksums() -> None:
    line = format_frame(1, frame(build_frame(build_ipv4(payload=build_tcp()))))
    assert "192.0.2.2:51234 -> 160.79.104.10:443 TCP [SYN]" in line
    assert "ttl=64 chk=ok/ok" in line


def test_udp_and_icmp_lines() -> None:
    udp = build_frame(build_ipv4(protocol=17, payload=build_udp(payload=b"x")))
    assert "192.0.2.2:53 -> 160.79.104.10:40000 UDP len=1" in format_frame(
        1, frame(udp)
    )
    icmp = build_frame(build_ipv4(protocol=1, payload=build_icmp()))
    assert "ICMP ECHO_REQUEST id=1 seq=7" in format_frame(1, frame(icmp))


def test_non_ip_frame_shows_ethernet_summary() -> None:
    line = format_frame(1, frame(build_frame(b"\x00" * 28, ethertype=0x0806)))
    assert "ARP" in line


def test_bad_l4_checksum_labels_depend_on_direction() -> None:
    data = build_frame(build_ipv4(payload=build_tcp(checksum=0x1234)))
    assert "chk=ok/BAD" in format_frame(1, frame(data, PacketType.HOST))
    assert "chk=ok/offload" in format_frame(1, frame(data, PacketType.OUTGOING))


def test_checksum_partial_label() -> None:
    data = build_frame(build_ipv4(payload=REAL_SYN, src=LOOPBACK, dst=LOOPBACK))
    assert "chk=ok/partial" in format_frame(1, frame(data, PacketType.HOST))


def test_malformed_tcp_keeps_ip_info() -> None:
    line = format_frame(1, frame(build_frame(build_ipv4(payload=b"\x00" * 4))))
    assert "192.0.2.2 -> 160.79.104.10 TCP <malformed TCP:" in line


def test_malformed_ip_does_not_raise() -> None:
    assert "<malformed:" in format_frame(1, frame(build_frame(b"\x45\x00")))


def test_fragment_marker() -> None:
    data = build_frame(build_ipv4(flags_frag=0x2005, payload=bytes(16)))
    assert "frag@40+MF" in format_frame(1, frame(data))


def test_show_ethernet_adds_layers() -> None:
    line = format_frame(
        1, frame(build_frame(build_ipv4(payload=build_tcp()))), show_ethernet=True
    )
    assert "02:fc:00:00:00:01 -> 02:fc:00:00:00:05" in line
    assert "id=0xe3f3" in line
