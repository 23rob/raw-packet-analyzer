"""ICMP message decoding (RFC 792).

Every ICMP message starts with the same 4 bytes, followed by 4 bytes whose
meaning depends on the type::

     0                   1                   2                   3
    +---------------+---------------+-------------------------------+
    |     Type      |     Code      |           Checksum            |
    +---------------+---------------+-------------------------------+
    |             Rest of header (type-specific)                    |
    +---------------------------------------------------------------+
    |      Data ...                                                 |

For echo request/reply, "rest of header" is Identifier (16) + Sequence (16).

ICMP *error* messages (types 3, 4, 5, 11, 12) carry, as their data, the IP
header plus the first 8 bytes of the packet that caused the error. Those 8
bytes are exactly the TCP/UDP ports. That is how your OS knows which socket
a "port unreachable" belongs to, and it is how a UDP port scan learns which
ports are closed.

Unlike TCP and UDP, the ICMP checksum covers only the ICMP message: no
pseudo-header.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from sniffer.exceptions import PacketParseError
from sniffer.utils.checksum import internet_checksum

_ICMP_HEADER: Final = struct.Struct("!BBH4s")
ICMP_HEADER_LEN: Final[int] = _ICMP_HEADER.size  # 8


class ICMPType(IntEnum):
    """Common ICMPv4 message types (IANA registry)."""

    ECHO_REPLY = 0
    DEST_UNREACHABLE = 3
    SOURCE_QUENCH = 4  # deprecated by RFC 6633
    REDIRECT = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP_REQUEST = 13
    TIMESTAMP_REPLY = 14


ERROR_TYPES: Final[frozenset[int]] = frozenset({3, 4, 5, 11, 12})

# Destination Unreachable (type 3) codes worth naming.
UNREACHABLE_CODES: Final[dict[int, str]] = {
    0: "net",
    1: "host",
    2: "protocol",
    3: "port",  # a closed UDP port answers with this
    4: "frag-needed",  # DF set but packet too big: Path MTU Discovery
    9: "net-prohibited",
    10: "host-prohibited",
    13: "admin-prohibited",  # a firewall filtered it
}


@dataclass(frozen=True, slots=True)
class ICMPMessage:
    """A decoded ICMP message."""

    type: int
    code: int
    checksum: int
    rest_of_header: bytes  # 4 type-specific bytes
    payload: bytes
    checksum_valid: bool

    @property
    def type_name(self) -> str:
        """Readable type name, e.g. ``"ECHO_REQUEST"``."""
        try:
            return ICMPType(self.type).name
        except ValueError:
            return f"TYPE-{self.type}"

    @property
    def is_error(self) -> bool:
        """True for error messages, which quote the offending packet."""
        return self.type in ERROR_TYPES

    @property
    def echo_id_seq(self) -> tuple[int, int] | None:
        """(identifier, sequence) for echo request/reply, else None."""
        if self.type in (ICMPType.ECHO_REQUEST, ICMPType.ECHO_REPLY):
            ident, seq = struct.unpack("!HH", self.rest_of_header)
            return ident, seq
        return None

    def summary(self) -> str:
        """Short description, e.g. ``ECHO_REQUEST id=1 seq=7 len=56``."""
        detail = ""
        echo = self.echo_id_seq
        if echo is not None:
            detail = f" id={echo[0]} seq={echo[1]}"
        elif self.type == ICMPType.DEST_UNREACHABLE:
            detail = f" ({UNREACHABLE_CODES.get(self.code, f'code {self.code}')})"
        else:
            detail = f" code={self.code}"
        return f"{self.type_name}{detail} len={len(self.payload)}"


def parse_icmp(data: bytes) -> ICMPMessage:
    """Decode an ICMP message (the whole IPv4 payload).

    Raises:
        PacketParseError: If the buffer is shorter than 8 bytes.

    """
    if len(data) < ICMP_HEADER_LEN:
        raise PacketParseError(
            f"ICMP message too short: {len(data)} bytes, need {ICMP_HEADER_LEN}"
        )
    icmp_type, code, checksum, rest = _ICMP_HEADER.unpack_from(data, 0)
    return ICMPMessage(
        type=icmp_type,
        code=code,
        checksum=checksum,
        rest_of_header=rest,
        payload=data[ICMP_HEADER_LEN:],
        # The checksum covers the entire ICMP message, header and data.
        checksum_valid=internet_checksum(data) == 0,
    )
