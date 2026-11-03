"""Tests for the layered decode pipeline and transport checksums."""

from __future__ import annotations

from sniffer.decode import decode_frame
from sniffer.protocols.icmp import ICMPMessage
from sniffer.protocols.tcp import TCPSegment
from sniffer.protocols.udp import UDPDatagram
from sniffer.utils.checksum import pseudo_header, transport_checksum
from tests.packets import (
    DST_IP,
    SRC_IP,
    build_frame,
    build_icmp,
    build_ipv4,
    build_tcp,
    build_udp,
)
from tests.test_tcp import REAL_SYN

LOOPBACK = bytes([127, 0, 0, 1])


def test_pseudo_header_layout() -> None:
    ph = pseudo_header(SRC_IP, DST_IP, 6, 40)
    assert len(ph) == 12
    assert ph == SRC_IP + DST_IP + b"\x00\x06\x00\x28"


def test_tcp_frame_decodes_with_valid_checksum() -> None:
    pkt = decode_frame(build_frame(build_ipv4(payload=build_tcp(payload=b"x"))))
    assert isinstance(pkt.transport, TCPSegment)
    assert pkt.transport_checksum_valid is True
    assert not pkt.transport_checksum_partial


def test_udp_and_icmp_dispatch() -> None:
    udp = decode_frame(
        build_frame(build_ipv4(protocol=17, payload=build_udp(payload=b"q")))
    )
    assert isinstance(udp.transport, UDPDatagram)
    assert udp.transport_checksum_valid is True
    icmp = decode_frame(build_frame(build_ipv4(protocol=1, payload=build_icmp())))
    assert isinstance(icmp.transport, ICMPMessage)
    assert icmp.transport_checksum_valid is True


def test_corrupted_payload_fails_tcp_checksum() -> None:
    seg = bytearray(build_tcp(payload=b"hello"))
    seg[-1] ^= 0xFF
    pkt = decode_frame(build_frame(build_ipv4(payload=bytes(seg))))
    assert pkt.transport_checksum_valid is False
    assert not pkt.transport_checksum_partial


def test_misdelivered_packet_fails_checksum() -> None:
    # Concept check question 2: same segment, different destination IP.
    seg = build_tcp(dst_ip=DST_IP)
    pkt = decode_frame(build_frame(build_ipv4(payload=seg, dst=bytes([10, 0, 0, 9]))))
    assert pkt.ip is not None and pkt.ip.checksum_valid  # IP layer is fine
    assert pkt.transport_checksum_valid is False  # pseudo-header catches it


def test_real_loopback_syn_is_checksum_partial() -> None:
    packet = build_ipv4(payload=REAL_SYN, src=LOOPBACK, dst=LOOPBACK)
    pkt = decode_frame(build_frame(packet))
    assert pkt.transport_checksum_valid is False
    assert pkt.transport_checksum_partial  # 0xfe30 == pseudo-header sum


def test_udp_zero_checksum_is_not_checked() -> None:
    pkt = decode_frame(
        build_frame(build_ipv4(protocol=17, payload=build_udp(checksum=0)))
    )
    assert pkt.transport_checksum_valid is None


def test_udp_computed_zero_is_sent_as_ffff() -> None:
    # Find a payload whose checksum computes to zero, then check 0xFFFF verifies.
    for i in range(70000):
        payload = i.to_bytes(4, "big")
        dgram = build_udp(payload=payload, checksum=0)
        if transport_checksum(SRC_IP, DST_IP, 17, dgram) == 0:
            break
    else:
        raise AssertionError("no payload with a zero checksum found")
    pkt = decode_frame(
        build_frame(build_ipv4(protocol=17, payload=build_udp(payload=payload)))
    )
    assert isinstance(pkt.transport, UDPDatagram)
    assert pkt.transport.checksum == 0xFFFF
    assert pkt.transport_checksum_valid is True


def test_non_first_fragment_is_not_parsed_as_tcp() -> None:
    packet = build_ipv4(flags_frag=0x2005, payload=build_tcp())
    pkt = decode_frame(build_frame(packet))
    assert pkt.ip is not None
    assert pkt.transport is None


def test_first_fragment_parsed_but_checksum_unverifiable() -> None:
    packet = build_ipv4(flags_frag=0x2000, payload=build_tcp())
    pkt = decode_frame(build_frame(packet))
    assert isinstance(pkt.transport, TCPSegment)
    assert pkt.transport_checksum_valid is None


def test_malformed_tcp_keeps_ip_layer() -> None:
    pkt = decode_frame(build_frame(build_ipv4(payload=b"\x00" * 10)))
    assert pkt.ip is not None
    assert pkt.transport is None
    assert pkt.transport_error is not None


def test_other_protocol_has_no_transport() -> None:
    pkt = decode_frame(build_frame(build_ipv4(protocol=47, payload=b"gre")))
    assert pkt.ip is not None and pkt.transport is None


def test_non_ip_frame() -> None:
    pkt = decode_frame(build_frame(b"\x00" * 28, ethertype=0x0806))
    assert pkt.ip is None
