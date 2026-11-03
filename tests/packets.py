"""Shared test helpers: build valid packets from parts, byte by byte."""

from __future__ import annotations

import struct

from sniffer.utils.checksum import internet_checksum


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
