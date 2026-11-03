"""Tests for the TCP parser."""

from __future__ import annotations

import struct

import pytest

from sniffer.exceptions import PacketParseError
from sniffer.protocols.tcp import (
    OPT_MSS,
    OPT_NOP,
    OPT_SACK_PERMITTED,
    OPT_TIMESTAMP,
    OPT_WSCALE,
    TCPFlag,
    format_flags,
    parse_tcp,
    parse_tcp_options,
)
from tests.packets import build_tcp

# A real SYN captured on Linux loopback during Milestone 3 testing
# (IPv4 header stripped). Options: MSS, SACK_PERM, TS, NOP, WSCALE.
REAL_SYN = bytes.fromhex(
    "d6189705f25a948000000000a002ffd7fe3000000204ffd70402080a6040da39000000000103030a"
)


def test_parses_real_linux_syn() -> None:
    tcp = parse_tcp(REAL_SYN)
    assert tcp.src_port == 54808
    assert tcp.dst_port == 38661
    assert tcp.flags == TCPFlag.SYN
    assert tcp.data_offset == 10
    assert tcp.header_length == 40
    assert tcp.payload == b""
    opts = tcp.options
    # Linux's signature option order, the basis of passive OS fingerprinting.
    assert opts.kinds == (
        OPT_MSS,
        OPT_SACK_PERMITTED,
        OPT_TIMESTAMP,
        OPT_NOP,
        OPT_WSCALE,
    )
    assert opts.mss == 65495  # loopback MTU 65536 - 40 bytes of headers
    assert opts.window_scale == 10
    assert opts.sack_permitted
    assert opts.timestamp == (0x6040DA39, 0)


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (0x02, "SYN"),
        (0x12, "SYN|ACK"),  # concept check question 1
        (0x29, "FIN|PSH|URG"),  # ... and the Xmas scan
        (0x00, "NONE"),  # NULL scan
        (0x14, "ACK|RST"),
        (0xC2, "SYN|ECE|CWR"),  # ECN-capable SYN
    ],
)
def test_flag_formatting(flags: int, expected: str) -> None:
    assert format_flags(flags) == expected


def test_flag_helpers() -> None:
    tcp = parse_tcp(build_tcp(flags=TCPFlag.SYN | TCPFlag.ACK, ack=5))
    assert tcp.has(TCPFlag.SYN) and tcp.has(TCPFlag.ACK)
    assert not tcp.has(TCPFlag.FIN)
    assert "ack=5" in tcp.summary()


def test_payload_follows_options() -> None:
    options = bytes([OPT_NOP, OPT_NOP, OPT_NOP, OPT_NOP])
    tcp = parse_tcp(build_tcp(options=options, payload=b"GET /", flags=0x18))
    assert tcp.header_length == 24
    assert tcp.payload == b"GET /"


def test_reserved_bits_extracted() -> None:
    raw = bytearray(build_tcp())
    raw[12] |= 0x0F
    assert parse_tcp(bytes(raw)).reserved == 0x0F


@pytest.mark.parametrize("length", [0, 10, 19])
def test_too_short_raises(length: int) -> None:
    with pytest.raises(PacketParseError):
        parse_tcp(build_tcp()[:length])


def test_data_offset_below_five_raises() -> None:
    raw = bytearray(build_tcp())
    raw[12] = 4 << 4
    with pytest.raises(PacketParseError, match="data offset"):
        parse_tcp(bytes(raw))


def test_data_offset_beyond_buffer_raises() -> None:
    raw = bytearray(build_tcp())
    raw[12] = 15 << 4  # claims 60 bytes, only 20 present
    with pytest.raises(PacketParseError, match="Truncated"):
        parse_tcp(bytes(raw))


@pytest.mark.parametrize(
    "options",
    [
        bytes([OPT_MSS]),
        bytes([OPT_MSS, 0, 0, 0]),
        bytes([OPT_MSS, 1, 0, 0]),
        bytes([OPT_MSS, 30, 0, 0]),
    ],
)
def test_malformed_options_raise(options: bytes) -> None:
    with pytest.raises(PacketParseError):
        parse_tcp_options(options)


def test_wrong_sized_known_option_is_not_decoded() -> None:
    # An MSS option with 3 data bytes is ignored rather than misread.
    opts = parse_tcp_options(bytes([OPT_MSS, 5, 1, 2, 3]) + b"\x00" * 3)
    assert opts.mss is None
    assert opts.kinds[0] == OPT_MSS


def test_mss_decoded() -> None:
    opts = parse_tcp_options(bytes([OPT_MSS, 4]) + struct.pack("!H", 1460))
    assert opts.mss == 1460
