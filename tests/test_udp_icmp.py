"""Tests for the UDP and ICMP parsers."""

from __future__ import annotations

import pytest

from sniffer.exceptions import PacketParseError
from sniffer.protocols.icmp import ICMPType, parse_icmp
from sniffer.protocols.udp import parse_udp
from tests.packets import build_icmp, build_udp


def test_udp_basic() -> None:
    udp = parse_udp(build_udp(payload=b"hello"))
    assert (udp.src_port, udp.dst_port) == (53, 40000)
    assert udp.length == 13
    assert udp.payload == b"hello"
    assert not udp.truncated


def test_udp_length_trims_extra_bytes() -> None:
    udp = parse_udp(build_udp(payload=b"hi") + b"\x00\x00\x00")
    assert udp.payload == b"hi"


def test_udp_truncated_flagged() -> None:
    udp = parse_udp(build_udp(payload=bytes(100))[:50])
    assert udp.truncated
    assert len(udp.payload) == 42


def test_udp_length_below_eight_raises() -> None:
    with pytest.raises(PacketParseError, match="minimum is 8"):
        parse_udp(build_udp(length=7))


def test_udp_too_short_raises() -> None:
    with pytest.raises(PacketParseError):
        parse_udp(b"\x00" * 7)


def test_icmp_echo_request() -> None:
    msg = parse_icmp(build_icmp(payload=b"ping-data"))
    assert msg.type == ICMPType.ECHO_REQUEST
    assert msg.echo_id_seq == (1, 7)
    assert msg.checksum_valid
    assert not msg.is_error
    assert "ECHO_REQUEST id=1 seq=7" in msg.summary()


def test_icmp_port_unreachable_is_error() -> None:
    msg = parse_icmp(build_icmp(icmp_type=3, code=3, rest=bytes(4)))
    assert msg.is_error
    assert msg.echo_id_seq is None
    assert "(port)" in msg.summary()


def test_icmp_bad_checksum() -> None:
    assert not parse_icmp(build_icmp(checksum=0x1234)).checksum_valid


def test_icmp_unknown_type_name() -> None:
    assert parse_icmp(build_icmp(icmp_type=42, rest=bytes(4))).type_name == "TYPE-42"


def test_icmp_too_short_raises() -> None:
    with pytest.raises(PacketParseError):
        parse_icmp(b"\x08\x00\x00")
