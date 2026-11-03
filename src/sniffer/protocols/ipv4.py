"""Layer 3: IPv4 header decoding (RFC 791).

Header layout (each row is 32 bits = 4 bytes)::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-------+-------+-----------+---+-------------------------------+
    |Version|  IHL  |   DSCP    |ECN|         Total Length          |  bytes 0-3
    +-------+-------+-----------+---+-----+-------------------------+
    |        Identification         |Flags|    Fragment Offset      |  bytes 4-7
    +---------------+---------------+-----+-------------------------+
    |      TTL      |   Protocol    |        Header Checksum        |  bytes 8-11
    +---------------+---------------+-------------------------------+
    |                        Source Address                         |  bytes 12-15
    +---------------------------------------------------------------+
    |                     Destination Address                       |  bytes 16-19
    +---------------------------------------------------------------+
    |              Options (0-40 bytes, only if IHL > 5)            |
    +---------------------------------------------------------------+

Security mindset: every length field in this header is chosen by whoever
built the packet, and that may be an attacker. Parsers that trusted these
fields caused real CVEs (out-of-bounds reads in IDS engines and in network
stacks such as Ripple20 and Amnesia:33). So we validate every length
against the number of bytes we actually received *before* slicing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv4Address
from typing import Final

from sniffer.exceptions import PacketParseError
from sniffer.utils.checksum import internet_checksum

# "!"  network byte order, no padding
# B B  version/IHL byte, DSCP/ECN byte          (1 + 1)
# H H  total length, identification             (2 + 2)
# H    flags (3 bits) + fragment offset (13)    (2)
# B B  TTL, protocol                            (1 + 1)
# H    header checksum                          (2)
# 4s4s source and destination addresses         (4 + 4)  = 20 bytes
_IPV4_HEADER: Final = struct.Struct("!BBHHHBBH4s4s")
IPV4_MIN_HEADER_LEN: Final[int] = _IPV4_HEADER.size  # 20
IPV4_MAX_HEADER_LEN: Final[int] = 15 * 4  # IHL is 4 bits, so at most 15 words

# Bit masks for the 16-bit flags + fragment offset field:
#   bit 15     bit 14   bit 13   bits 12..0
#   reserved   DF       MF       fragment offset (in 8-byte units)
_FLAG_RESERVED: Final[int] = 0x8000
_FLAG_DF: Final[int] = 0x4000
_FLAG_MF: Final[int] = 0x2000
_FRAG_OFFSET_MASK: Final[int] = 0x1FFF
FRAGMENT_UNIT: Final[int] = 8  # the offset counts 8-byte blocks

# IP option type numbers (IANA "IP Option Numbers" registry). The type byte
# itself is a bit field: copied flag (1) | class (2) | number (5).
OPT_END: Final[int] = 0  # End of Option List
OPT_NOP: Final[int] = 1  # No Operation (used as padding/alignment)
OPT_RECORD_ROUTE: Final[int] = 7
OPT_TIMESTAMP: Final[int] = 68
OPT_LSRR: Final[int] = 131  # Loose Source and Record Route
OPT_SSRR: Final[int] = 137  # Strict Source and Record Route
# Source routing lets the *sender* dictate the path, which can bypass
# firewalls and enable spoofing with return traffic. RFC 7126 recommends
# dropping these packets, so seeing one is a strong signal for Milestone 5.
SOURCE_ROUTE_OPTIONS: Final[frozenset[int]] = frozenset({OPT_LSRR, OPT_SSRR})


class IPProtocol(IntEnum):
    """Common values of the IPv4 Protocol field (IANA protocol numbers)."""

    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17
    GRE = 47
    ESP = 50
    AH = 51
    ICMPV6 = 58
    SCTP = 132


def protocol_name(number: int) -> str:
    """Return ``"TCP"`` for 6, or ``"PROTO-253"`` for unknown values."""
    try:
        return IPProtocol(number).name
    except ValueError:
        return f"PROTO-{number}"


@dataclass(frozen=True, slots=True)
class IPv4Packet:
    """A decoded IPv4 header plus its payload.

    Note ``fragment_offset`` is stored in **bytes** (already multiplied by
    8). Keeping wire units out of the public API avoids a whole class of
    off-by-8x bugs in later code.
    """

    version: int
    ihl: int  # header length in 32-bit words, as on the wire
    dscp: int  # Differentiated Services Code Point (QoS class)
    ecn: int  # Explicit Congestion Notification (2 bits)
    total_length: int  # header + payload, as claimed by the sender
    identification: int
    reserved_flag: bool  # must be 0 (RFC 3514 "evil bit" joke)
    dont_fragment: bool
    more_fragments: bool
    fragment_offset: int  # in bytes
    ttl: int
    protocol: int
    checksum: int  # as found in the packet
    checksum_valid: bool  # result of our RFC 1071 verification
    src: IPv4Address
    dst: IPv4Address
    options: bytes  # raw option bytes (empty when IHL == 5)
    option_types: tuple[int, ...]  # type byte of each option, in order
    payload: bytes  # bytes after the header, trimmed to total_length
    truncated: bool  # True if we received fewer bytes than total_length

    @property
    def header_length(self) -> int:
        """Header length in bytes (IHL * 4)."""
        return self.ihl * 4

    @property
    def is_fragment(self) -> bool:
        """True for any piece of a fragmented datagram.

        A datagram that was split has MF=1 on every piece except the last,
        and a non-zero offset on every piece except the first. So "MF set OR
        offset non-zero" catches all of them, including the last one.
        """
        return self.more_fragments or self.fragment_offset > 0

    @property
    def is_first_fragment(self) -> bool:
        """True if this packet starts at offset 0 of the original datagram.

        Only the first fragment contains the TCP/UDP header. Later fragments
        carry raw continuation bytes that must NOT be parsed as a header.
        """
        return self.fragment_offset == 0

    @property
    def has_source_route(self) -> bool:
        """True if the packet carries an LSRR or SSRR option."""
        return any(t in SOURCE_ROUTE_OPTIONS for t in self.option_types)

    @property
    def protocol_name(self) -> str:
        """Readable transport protocol name, e.g. ``"TCP"``."""
        return protocol_name(self.protocol)

    def summary(self) -> str:
        """One-line, human-readable description of the header."""
        flags = []
        if self.dont_fragment:
            flags.append("DF")
        if self.more_fragments:
            flags.append("MF")
        if self.reserved_flag:
            flags.append("EVIL")
        frag = f" frag@{self.fragment_offset}" if self.fragment_offset else ""
        flag_text = f" [{','.join(flags)}]" if flags else ""
        chk = "ok" if self.checksum_valid else "BAD"
        trunc = " TRUNCATED" if self.truncated else ""
        return (
            f"{self.src} -> {self.dst} {self.protocol_name} "
            f"ttl={self.ttl} len={self.total_length} id=0x{self.identification:04x}"
            f"{flag_text}{frag} chk={chk}{trunc}"
        )


def parse_options(options: bytes) -> tuple[int, ...]:
    """Walk the TLV-encoded options area and return each option's type.

    Format: single-byte options (END=0, NOP=1) have no length. Every other
    option is Type (1 byte), Length (1 byte, *including* type and length),
    then data. A length below 2, or one that runs past the end of the
    buffer, is malformed. Before checking for this, some parsers looped
    forever on a length of 0, a classic denial-of-service bug.
    """
    types: list[int] = []
    i = 0
    while i < len(options):
        opt_type = options[i]
        types.append(opt_type)
        if opt_type == OPT_END:
            break  # the rest is padding
        if opt_type == OPT_NOP:
            i += 1
            continue
        if i + 1 >= len(options):
            raise PacketParseError(f"IPv4 option {opt_type} missing length byte")
        opt_len = options[i + 1]
        if opt_len < 2 or i + opt_len > len(options):
            raise PacketParseError(f"IPv4 option {opt_type} has bad length {opt_len}")
        i += opt_len
    return tuple(types)


def parse_ipv4(data: bytes) -> IPv4Packet:
    """Decode an IPv4 header from the start of ``data``.

    Args:
        data: Bytes starting at the IPv4 header, usually
            ``EthernetFrame.payload``.

    Returns:
        An immutable ``IPv4Packet``.

    Raises:
        PacketParseError: If the buffer is too short, the version is not 4,
            or a length field is inconsistent.

    """
    # -- 1. Is there even room for the fixed 20-byte header? ---------------
    if len(data) < IPV4_MIN_HEADER_LEN:
        raise PacketParseError(
            f"IPv4 header too short: {len(data)} bytes, need {IPV4_MIN_HEADER_LEN}"
        )

    (
        ver_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        checksum,
        src_raw,
        dst_raw,
    ) = _IPV4_HEADER.unpack_from(data, 0)

    # -- 2. Split the packed bit fields ------------------------------------
    version = ver_ihl >> 4  # high nibble: shift it down
    ihl = ver_ihl & 0x0F  # low nibble: mask off the high one
    dscp = tos >> 2  # top 6 bits
    ecn = tos & 0x03  # bottom 2 bits

    if version != 4:
        raise PacketParseError(f"Not IPv4: version field is {version}")

    # -- 3. Validate the header length against reality ---------------------
    header_len = ihl * 4
    if ihl < 5:
        raise PacketParseError(f"Invalid IHL {ihl}: minimum is 5 (20 bytes)")
    if len(data) < header_len:
        raise PacketParseError(
            f"Truncated IPv4 header: IHL says {header_len} bytes, got {len(data)}"
        )

    # -- 4. Work out where the payload really ends -------------------------
    # Ethernet pads frames shorter than 60 bytes with zeros, so the buffer
    # can be LONGER than total_length. We must cut there, or the padding
    # would be read as payload data.
    #
    # total_length == 0 is a special case: with TSO/GSO or Linux "BIG TCP",
    # the kernel can hand a sniffer a super-packet whose real length does
    # not fit in 16 bits and sets this field to 0. Then the buffer is the
    # only source of truth.
    truncated = False
    if total_length == 0:
        end = len(data)
    elif total_length < header_len:
        raise PacketParseError(
            f"Total length {total_length} is smaller than header length {header_len}"
        )
    elif total_length > len(data):
        # Fewer bytes than claimed: the capture was cut short (or the
        # length is a lie). Keep what we have, but flag it.
        truncated = True
        end = len(data)
    else:
        end = total_length

    # -- 5. Verify the checksum over the header only -----------------------
    # Unlike TCP/UDP, the IPv4 checksum covers the header and NOT the
    # payload. Running RFC 1071 over the header *including* the stored
    # checksum yields 0 when it is intact.
    header = data[:header_len]
    checksum_valid = internet_checksum(header) == 0

    options = data[IPV4_MIN_HEADER_LEN:header_len]

    return IPv4Packet(
        version=version,
        ihl=ihl,
        dscp=dscp,
        ecn=ecn,
        total_length=total_length,
        identification=identification,
        # bool(x & MASK) is True if that one bit is set.
        reserved_flag=bool(flags_frag & _FLAG_RESERVED),
        dont_fragment=bool(flags_frag & _FLAG_DF),
        more_fragments=bool(flags_frag & _FLAG_MF),
        # Keep the low 13 bits, then convert 8-byte blocks to bytes.
        fragment_offset=(flags_frag & _FRAG_OFFSET_MASK) * FRAGMENT_UNIT,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        checksum_valid=checksum_valid,
        # IPv4Address accepts exactly 4 packed bytes, and gives us
        # .is_private, .is_multicast, etc. for free in Milestone 5.
        src=IPv4Address(src_raw),
        dst=IPv4Address(dst_raw),
        options=options,
        option_types=parse_options(options),
        payload=data[header_len:end],
        truncated=truncated,
    )
