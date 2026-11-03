"""Layer 4: TCP segment decoding (RFC 9293, which replaced RFC 793 in 2022).

Header layout (20 bytes without options)::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-------------------------------+-------------------------------+
    |          Source Port          |       Destination Port        |  0-3
    +-------------------------------+-------------------------------+
    |                        Sequence Number                        |  4-7
    +---------------------------------------------------------------+
    |                    Acknowledgment Number                      |  8-11
    +-------+-------+-+-+-+-+-+-+-+-+-------------------------------+
    | Data  |       |C|E|U|A|P|R|S|F|                               |
    | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |  12-15
    |       |       |R|E|G|K|H|T|N|N|                               |
    +-------+-------+-+-+-+-+-+-+-+-+-------------------------------+
    |           Checksum            |         Urgent Pointer        |  16-19
    +-------------------------------+-------------------------------+
    |                    Options (0-40 bytes)                       |
    +---------------------------------------------------------------+

Byte 12 holds Data Offset (high nibble) + 4 reserved bits.
Byte 13 holds the 8 flag bits, so ``flags & TCPFlag.SYN`` tests one flag.

Why flags matter for security: a normal connection only ever uses a few
combinations (SYN, SYN|ACK, ACK, PSH|ACK, FIN|ACK, RST, RST|ACK). Scanners
send impossible ones (no flags at all, FIN|PSH|URG, SYN|FIN) because a
closed port must answer them with RST while an open port stays silent
(RFC 9293, section 3.10.7.1), which leaks the port's state.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntFlag
from typing import Final

from sniffer.exceptions import PacketParseError

# H H   source port, destination port      (2 + 2)
# I I   sequence, acknowledgment numbers   (4 + 4)  "I" = unsigned 32-bit
# B B   data offset/reserved, flags        (1 + 1)
# H H H window, checksum, urgent pointer   (2 + 2 + 2)   = 20 bytes
_TCP_HEADER: Final = struct.Struct("!HHIIBBHHH")
TCP_MIN_HEADER_LEN: Final[int] = _TCP_HEADER.size  # 20

# TCP option kinds (IANA "TCP Option Kind Numbers").
OPT_EOL: Final[int] = 0  # End of Option List
OPT_NOP: Final[int] = 1  # No-Operation (padding)
OPT_MSS: Final[int] = 2  # Maximum Segment Size, only valid in SYN
OPT_WSCALE: Final[int] = 3  # Window Scale (RFC 7323), only valid in SYN
OPT_SACK_PERMITTED: Final[int] = 4  # Selective ACK allowed (RFC 2018)
OPT_SACK: Final[int] = 5
OPT_TIMESTAMP: Final[int] = 8  # RFC 7323

_MSS_DATA: Final = struct.Struct("!H")


class TCPFlag(IntFlag):
    """The 8 TCP control bits.

    ``IntFlag`` members combine with ``|`` and test with ``&``, exactly like
    the raw bits, but print with names. ``TCPFlag(0x12)`` is SYN|ACK.
    """

    FIN = 0x01  # sender has finished sending
    SYN = 0x02  # synchronize sequence numbers (connection start)
    RST = 0x04  # reset (abort) the connection
    PSH = 0x08  # push buffered data to the application now
    ACK = 0x10  # acknowledgment number field is valid
    URG = 0x20  # urgent pointer field is valid
    ECE = 0x40  # ECN echo (RFC 3168)
    CWR = 0x80  # congestion window reduced (RFC 3168)


# Display order, highest-level meaning first. We do not rely on str(IntFlag)
# because its format changed between Python 3.10 and 3.11.
_FLAG_ORDER: Final[tuple[TCPFlag, ...]] = (
    TCPFlag.SYN,
    TCPFlag.ACK,
    TCPFlag.FIN,
    TCPFlag.RST,
    TCPFlag.PSH,
    TCPFlag.URG,
    TCPFlag.ECE,
    TCPFlag.CWR,
)


def format_flags(flags: int) -> str:
    """Return e.g. ``"SYN|ACK"``, or ``"NONE"`` when no bit is set."""
    names = [f.name for f in _FLAG_ORDER if flags & f and f.name is not None]
    return "|".join(names) if names else "NONE"


@dataclass(frozen=True, slots=True)
class TCPOptions:
    """The decoded subset of TCP options we care about.

    ``kinds`` keeps every option kind in wire order. The *order* of options
    in a SYN is distinctive per OS (for example Linux sends
    MSS,SACK_PERM,TS,NOP,WSCALE), which is how passive fingerprinting tools
    like p0f identify an operating system without sending a single packet.
    """

    kinds: tuple[int, ...] = ()
    mss: int | None = None
    window_scale: int | None = None
    sack_permitted: bool = False
    timestamp: tuple[int, int] | None = None  # (TSval, TSecr)


@dataclass(frozen=True, slots=True)
class TCPSegment:
    """A decoded TCP header plus its payload."""

    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int  # header length in 32-bit words
    reserved: int  # the 4 reserved bits; must be 0
    flags: int  # raw flag byte; compare with TCPFlag members
    window: int
    checksum: int
    urgent_pointer: int
    options: TCPOptions
    payload: bytes

    @property
    def header_length(self) -> int:
        """Header length in bytes (data offset * 4)."""
        return self.data_offset * 4

    def has(self, flag: TCPFlag) -> bool:
        """Return True if ``flag`` is set."""
        return bool(self.flags & flag)

    @property
    def flag_names(self) -> str:
        """Readable flag list, e.g. ``"SYN|ACK"``."""
        return format_flags(self.flags)

    def summary(self) -> str:
        """Short description of the TCP fields (ports are shown elsewhere)."""
        ack = f" ack={self.ack}" if self.has(TCPFlag.ACK) else ""
        mss = f" mss={self.options.mss}" if self.options.mss is not None else ""
        return (
            f"[{self.flag_names}] seq={self.seq}{ack} win={self.window}"
            f"{mss} len={len(self.payload)}"
        )


def parse_tcp_options(raw: bytes) -> TCPOptions:
    """Decode the TLV options area. Same format as IPv4 options.

    Raises:
        PacketParseError: On a missing or impossible length byte.

    """
    kinds: list[int] = []
    mss: int | None = None
    wscale: int | None = None
    sack_ok = False
    timestamp: tuple[int, int] | None = None

    i = 0
    while i < len(raw):
        kind = raw[i]
        kinds.append(kind)
        if kind == OPT_EOL:
            break
        if kind == OPT_NOP:
            i += 1
            continue
        if i + 1 >= len(raw):
            raise PacketParseError(f"TCP option {kind} missing length byte")
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            raise PacketParseError(f"TCP option {kind} has bad length {length}")
        data = raw[i + 2 : i + length]
        # Each known option has a fixed size. We only decode it when the
        # size matches, so a crafted option can't make us misread memory.
        if kind == OPT_MSS and len(data) == 2:
            (mss,) = _MSS_DATA.unpack(data)
        elif kind == OPT_WSCALE and len(data) == 1:
            wscale = data[0]
        elif kind == OPT_SACK_PERMITTED and not data:
            sack_ok = True
        elif kind == OPT_TIMESTAMP and len(data) == 8:
            timestamp = struct.unpack("!II", data)
        i += length

    return TCPOptions(
        kinds=tuple(kinds),
        mss=mss,
        window_scale=wscale,
        sack_permitted=sack_ok,
        timestamp=timestamp,
    )


def parse_tcp(data: bytes) -> TCPSegment:
    """Decode a TCP header from the start of ``data`` (the IPv4 payload).

    Raises:
        PacketParseError: If the buffer is too short or Data Offset is
            invalid.

    """
    if len(data) < TCP_MIN_HEADER_LEN:
        raise PacketParseError(
            f"TCP header too short: {len(data)} bytes, need {TCP_MIN_HEADER_LEN}"
        )
    (
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved,
        flags,
        window,
        checksum,
        urgent,
    ) = _TCP_HEADER.unpack_from(data, 0)

    # Same nibble split as IPv4's version/IHL byte.
    data_offset = offset_reserved >> 4
    reserved = offset_reserved & 0x0F
    header_len = data_offset * 4

    if data_offset < 5:
        raise PacketParseError(f"Invalid TCP data offset {data_offset}: minimum is 5")
    if header_len > len(data):
        raise PacketParseError(
            f"Truncated TCP header: data offset says {header_len} bytes, "
            f"got {len(data)}"
        )

    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        reserved=reserved,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent_pointer=urgent,
        options=parse_tcp_options(data[TCP_MIN_HEADER_LEN:header_len]),
        payload=data[header_len:],
    )
