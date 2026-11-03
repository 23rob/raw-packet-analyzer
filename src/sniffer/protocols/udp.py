"""Layer 4: UDP datagram decoding (RFC 768).

The whole header is four 16-bit fields::

     0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |   Source Port   |    Dest Port    |
    +--------+--------+--------+--------+
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    |          data octets ...
    +-----------------------------------+

``Length`` counts header *and* data, so the minimum legal value is 8.
On IPv4 a checksum of 0 means "the sender did not compute one" (RFC 768).
If a real computed checksum happens to be 0, the sender transmits 0xFFFF
instead. In one's complement arithmetic both are representations of zero.

UDP has no handshake and no connection state, so the source address is
trivial to spoof. That is why UDP services (DNS, NTP, memcached, SSDP) are
the engines of *reflection/amplification* DDoS: a small spoofed request
makes a server send a much larger reply to the victim.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from sniffer.exceptions import PacketParseError

_UDP_HEADER: Final = struct.Struct("!HHHH")
UDP_HEADER_LEN: Final[int] = _UDP_HEADER.size  # 8


@dataclass(frozen=True, slots=True)
class UDPDatagram:
    """A decoded UDP header plus its payload."""

    src_port: int
    dst_port: int
    length: int  # header + data, as claimed by the sender
    checksum: int  # 0 means "not computed" on IPv4
    payload: bytes
    truncated: bool

    def summary(self) -> str:
        """Short description of the UDP fields (ports are shown elsewhere)."""
        trunc = " TRUNCATED" if self.truncated else ""
        return f"len={len(self.payload)}{trunc}"


def parse_udp(data: bytes) -> UDPDatagram:
    """Decode a UDP header from the start of ``data`` (the IPv4 payload).

    Raises:
        PacketParseError: If the buffer is shorter than 8 bytes or the
            Length field is below the minimum.

    """
    if len(data) < UDP_HEADER_LEN:
        raise PacketParseError(
            f"UDP header too short: {len(data)} bytes, need {UDP_HEADER_LEN}"
        )
    src_port, dst_port, length, checksum = _UDP_HEADER.unpack_from(data, 0)
    if length < UDP_HEADER_LEN:
        raise PacketParseError(f"Invalid UDP length {length}: minimum is 8")

    # Same rule as IPv4: never read past what the length field allows, and
    # never past what we actually received.
    truncated = length > len(data)
    end = len(data) if truncated else length
    return UDPDatagram(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=checksum,
        payload=data[UDP_HEADER_LEN:end],
        truncated=truncated,
    )
