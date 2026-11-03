"""Tests for the IPv4 parser, built from hand-crafted headers."""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from sniffer.exceptions import PacketParseError
from sniffer.protocols.ipv4 import (
    OPT_LSRR,
    OPT_NOP,
    OPT_RECORD_ROUTE,
    IPProtocol,
    parse_ipv4,
    parse_options,
    protocol_name,
)
from tests.packets import build_ipv4

# Frame #2 from the Milestone 1 live capture: 20-byte header + 32-byte TCP.
REAL_PACKET = bytes.fromhex(
    "45000034e3f340004006 8c74 c0000202a04f680a".replace(" ", "")
) + bytes(32)


def test_parses_real_captured_header() -> None:
    ip = parse_ipv4(REAL_PACKET)
    assert ip.version == 4
    assert ip.ihl == 5
    assert ip.header_length == 20
    assert ip.total_length == 52
    assert ip.identification == 0xE3F3
    assert ip.dont_fragment and not ip.more_fragments and not ip.reserved_flag
    assert ip.fragment_offset == 0
    assert ip.ttl == 64
    assert ip.protocol == IPProtocol.TCP
    assert ip.checksum == 0x8C74
    assert ip.checksum_valid
    assert ip.src == IPv4Address("192.0.2.2")
    assert ip.dst == IPv4Address("160.79.104.10")
    assert len(ip.payload) == 32
    assert not ip.truncated


def test_dscp_and_ecn_split() -> None:
    # TOS 0xB9 = 1011 1001 -> DSCP 101110 (46, "EF", used for VoIP), ECN 01
    ip = parse_ipv4(build_ipv4(tos=0xB9))
    assert ip.dscp == 46
    assert ip.ecn == 1


def test_concept_check_0x2005() -> None:
    # The Milestone 2 concept check: MF set, offset 5 blocks = 40 bytes.
    ip = parse_ipv4(build_ipv4(flags_frag=0x2005, payload=bytes(16)))
    assert not ip.dont_fragment
    assert ip.more_fragments
    assert ip.fragment_offset == 40
    assert ip.is_fragment
    assert not ip.is_first_fragment  # so no TCP header inside


def test_last_fragment_is_still_a_fragment() -> None:
    ip = parse_ipv4(build_ipv4(flags_frag=0x0010))  # MF=0, offset 16*8
    assert ip.is_fragment
    assert ip.fragment_offset == 128


def test_evil_bit() -> None:
    ip = parse_ipv4(build_ipv4(flags_frag=0x8000))
    assert ip.reserved_flag
    assert "EVIL" in ip.summary()


def test_bad_checksum_is_reported_not_raised() -> None:
    ip = parse_ipv4(build_ipv4(checksum=0xDEAD))
    assert not ip.checksum_valid
    assert "chk=BAD" in ip.summary()


def test_ethernet_padding_is_trimmed() -> None:
    # A 20-byte header + 6 bytes of data, padded by Ethernet with zeros.
    packet = build_ipv4(payload=b"abcdef") + b"\x00" * 20
    ip = parse_ipv4(packet)
    assert ip.payload == b"abcdef"


def test_truncated_capture_is_flagged() -> None:
    packet = build_ipv4(payload=bytes(100))[:60]
    ip = parse_ipv4(packet)
    assert ip.truncated
    assert len(ip.payload) == 40


def test_total_length_zero_accepted_for_big_tcp_super_packet() -> None:
    # BIG TCP: a GSO/GRO packet over 65,535 bytes carries total_length 0.
    ip = parse_ipv4(build_ipv4(payload=bytes(70_000), total_length=0))
    assert len(ip.payload) == 70_000
    assert not ip.truncated


def test_total_length_zero_rejected_on_normal_sized_packet() -> None:
    # On an ordinary packet a zero length is malformed, not BIG TCP.
    with pytest.raises(PacketParseError, match="smaller"):
        parse_ipv4(build_ipv4(payload=bytes(10), total_length=0))


def test_options_are_parsed() -> None:
    # NOP, NOP, then a 7-byte Record Route option, then END padding = 12 bytes
    rr = bytes([OPT_RECORD_ROUTE, 7, 4, 0, 0, 0, 0])
    options = bytes([OPT_NOP, OPT_NOP]) + rr + b"\x00" * 3
    ip = parse_ipv4(build_ipv4(options=options, payload=b"x"))
    assert ip.ihl == 8
    assert ip.option_types == (OPT_NOP, OPT_NOP, OPT_RECORD_ROUTE, 0)
    assert ip.payload == b"x"
    assert ip.checksum_valid
    assert not ip.has_source_route


def test_source_route_option_detected() -> None:
    lsrr = bytes([OPT_LSRR, 7, 4, 10, 0, 0, 1, 0])  # 7-byte option + END
    ip = parse_ipv4(build_ipv4(options=lsrr))
    assert ip.has_source_route


@pytest.mark.parametrize(
    "options",
    [
        bytes([OPT_RECORD_ROUTE]),  # missing length byte
        bytes([OPT_RECORD_ROUTE, 0, 0, 0]),  # length 0: infinite-loop bait
        bytes([OPT_RECORD_ROUTE, 1, 0, 0]),  # length below 2
        bytes([OPT_RECORD_ROUTE, 40, 0, 0]),  # runs past the end
    ],
)
def test_malformed_options_raise(options: bytes) -> None:
    with pytest.raises(PacketParseError):
        parse_options(options)


@pytest.mark.parametrize("length", [0, 1, 19])
def test_too_short_raises(length: int) -> None:
    with pytest.raises(PacketParseError):
        parse_ipv4(REAL_PACKET[:length])


def test_wrong_version_raises() -> None:
    bad = bytes([0x65]) + REAL_PACKET[1:]
    with pytest.raises(PacketParseError, match="version"):
        parse_ipv4(bad)


def test_ihl_below_five_raises() -> None:
    bad = bytes([0x44]) + REAL_PACKET[1:]
    with pytest.raises(PacketParseError, match="IHL"):
        parse_ipv4(bad)


def test_ihl_beyond_buffer_raises() -> None:
    bad = bytes([0x4F]) + REAL_PACKET[1:30]  # claims 60 bytes, has 30
    with pytest.raises(PacketParseError, match="Truncated"):
        parse_ipv4(bad)


def test_total_length_smaller_than_header_raises() -> None:
    with pytest.raises(PacketParseError, match="smaller"):
        parse_ipv4(build_ipv4(total_length=10))


def test_protocol_names() -> None:
    assert protocol_name(17) == "UDP"
    assert protocol_name(253) == "PROTO-253"
