"""Unit tests for the Ethernet parser, using hand-built frames (no root needed)."""

from __future__ import annotations

import struct

import pytest

from sniffer.exceptions import PacketParseError
from sniffer.protocols.ethernet import (
    ETH_HEADER_LEN,
    EtherType,
    ethertype_name,
    format_mac,
    parse_ethernet,
)

DST = bytes.fromhex("ffffffffffff")
SRC = bytes.fromhex("001122334455")


def make_frame(ethertype: int, payload: bytes = b"", dst: bytes = DST) -> bytes:
    """Build a frame the same way a NIC would put it on the wire."""
    return struct.pack("!6s6sH", dst, SRC, ethertype) + payload


def test_header_length_is_14() -> None:
    assert ETH_HEADER_LEN == 14


def test_parses_ipv4_frame() -> None:
    frame = parse_ethernet(make_frame(0x0800, b"\x45\x00"))
    assert frame.dst == "ff:ff:ff:ff:ff:ff"
    assert frame.src == "00:11:22:33:44:55"
    assert frame.ethertype == EtherType.IPV4
    assert frame.payload == b"\x45\x00"
    assert frame.vlan_id is None


def test_ethertype_is_big_endian() -> None:
    # The warm-up question as a test: bytes 08 00 must mean 0x0800, not 0x0008.
    raw = SRC + SRC + b"\x08\x00"
    assert parse_ethernet(raw).ethertype == 2048


def test_broadcast_and_multicast_bits() -> None:
    bcast = parse_ethernet(make_frame(0x0806))
    assert bcast.is_broadcast and bcast.is_multicast
    mcast = parse_ethernet(make_frame(0x0800, dst=bytes.fromhex("01005e000001")))
    assert mcast.is_multicast and not mcast.is_broadcast
    ucast = parse_ethernet(make_frame(0x0800, dst=SRC))
    assert not ucast.is_multicast


def test_vlan_tag_is_unwrapped() -> None:
    # TCI = PCP 5 (bits 15-13), DEI 0, VID 100 -> 0b101_0_000001100100 = 0xA064
    tag = struct.pack("!HH", 0xA064, 0x86DD)
    frame = parse_ethernet(make_frame(0x8100, tag + b"payload"))
    assert frame.vlan_id == 100
    assert frame.ethertype == EtherType.IPV6
    assert frame.payload == b"payload"


@pytest.mark.parametrize("length", [0, 1, 13])
def test_short_frame_raises(length: int) -> None:
    with pytest.raises(PacketParseError):
        parse_ethernet(b"\x00" * length)


def test_truncated_vlan_tag_raises() -> None:
    with pytest.raises(PacketParseError):
        parse_ethernet(make_frame(0x8100, b"\x00\x01"))


def test_ethertype_names() -> None:
    assert ethertype_name(0x0800) == "IPV4 (0x0800)"
    assert ethertype_name(0x1234) == "UNKNOWN (0x1234)"
    assert ethertype_name(0x0026) == "802.3 length=38"


def test_format_mac_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        format_mac(b"\x00" * 5)
