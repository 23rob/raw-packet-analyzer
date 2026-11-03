"""Shared test helpers: build valid packets from parts, byte by byte."""

from __future__ import annotations

import struct

from sniffer.utils.checksum import internet_checksum, transport_checksum


def build_ipv4(  # noqa: PLR0913 - a packet builder legitimately has many knobs
    *,
    payload: bytes = b"",
    src: bytes = bytes([192, 0, 2, 2]),
    dst: bytes = bytes([160, 79, 104, 10]),
    protocol: int = 6,
    ttl: int = 64,
    flags_frag: int = 0x4000,
    identification: int = 0xE3F3,
    tos: int = 0,
    options: bytes = b"",
    total_length: int | None = None,
    checksum: int | None = None,
) -> bytes:
    """Return an IPv4 header + payload with a correct checksum by default."""
    ihl = 5 + len(options) // 4
    if total_length is None:
        total_length = ihl * 4 + len(payload)
    header = (
        struct.pack(
            "!BBHHHBBH4s4s",
            (4 << 4) | ihl,  # version in the high nibble, IHL in the low one
            tos,
            total_length,
            identification,
            flags_frag,
            ttl,
            protocol,
            0,  # checksum placeholder: must be zero while computing it
            src,
            dst,
        )
        + options
    )
    if checksum is None:
        checksum = internet_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


SRC_IP = bytes([192, 0, 2, 2])
DST_IP = bytes([160, 79, 104, 10])


def build_tcp(  # noqa: PLR0913
    *,
    src_port: int = 51234,
    dst_port: int = 443,
    seq: int = 1000,
    ack: int = 0,
    flags: int = 0x02,
    window: int = 64240,
    options: bytes = b"",
    payload: bytes = b"",
    checksum: int | None = None,
    src_ip: bytes = SRC_IP,
    dst_ip: bytes = DST_IP,
) -> bytes:
    """Return a TCP segment whose checksum is valid for src_ip/dst_ip."""
    data_offset = 5 + len(options) // 4
    segment = (
        struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            ack,
            data_offset << 4,
            flags,
            window,
            0,
            0,
        )
        + options
        + payload
    )
    if checksum is None:
        checksum = transport_checksum(src_ip, dst_ip, 6, segment)
    return segment[:16] + struct.pack("!H", checksum) + segment[18:]


def build_udp(  # noqa: PLR0913
    *,
    src_port: int = 53,
    dst_port: int = 40000,
    payload: bytes = b"",
    length: int | None = None,
    checksum: int | None = None,
    src_ip: bytes = SRC_IP,
    dst_ip: bytes = DST_IP,
) -> bytes:
    """Return a UDP datagram whose checksum is valid for src_ip/dst_ip."""
    if length is None:
        length = 8 + len(payload)
    datagram = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    if checksum is None:
        checksum = transport_checksum(src_ip, dst_ip, 17, datagram) or 0xFFFF
    return datagram[:6] + struct.pack("!H", checksum) + datagram[8:]


def build_icmp(
    *,
    icmp_type: int = 8,
    code: int = 0,
    rest: bytes = b"\x00\x01\x00\x07",
    payload: bytes = b"",
    checksum: int | None = None,
) -> bytes:
    """Return an ICMP message with a valid checksum by default."""
    msg = struct.pack("!BBH4s", icmp_type, code, 0, rest) + payload
    if checksum is None:
        checksum = internet_checksum(msg)
    return msg[:2] + struct.pack("!H", checksum) + msg[4:]


def build_frame(ip_packet: bytes, ethertype: int = 0x0800) -> bytes:
    """Wrap an IP packet (or any payload) in an Ethernet header."""
    return (
        bytes.fromhex("02fc0000000502fc00000001")
        + struct.pack("!H", ethertype)
        + ip_packet
    )
