"""Layer 2: Ethernet II frame decoding.

What the bytes look like
------------------------
An ``AF_PACKET`` socket hands us the frame starting at the destination MAC.
The preamble, start-of-frame delimiter and the 4-byte CRC/FCS at the end are
consumed by the NIC hardware and never reach software::

     0                   6                   12      14
     +-------------------+-------------------+-------+---------------------+
     |  Destination MAC  |    Source MAC     | Type  |  Payload (46-1500)  |
     |     6 bytes       |     6 bytes       | 2 B   |  e.g. an IPv4 packet|
     +-------------------+-------------------+-------+---------------------+

If the frame carries an IEEE 802.1Q VLAN tag, 4 extra bytes sit between the
source MAC and the real EtherType::

     | Dst MAC | Src MAC | 0x8100 | TCI (PCP:3 DEI:1 VID:12) | Type | Payload |

The "Type" field is the **EtherType**. It tells us how to interpret the
payload: 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP, and so on. Values below
0x0600 (1536) are not an EtherType at all: they are an IEEE 802.3 *length*
field, used by older frame formats such as 802.3/LLC (for example, STP).

Design choice: this module is *pure*. It takes ``bytes`` and returns a
dataclass. It never touches a socket. That makes it trivially unit-testable
with hand-crafted frames and no root privileges.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from sniffer.exceptions import PacketParseError

# ---------------------------------------------------------------------------
# struct format strings
# ---------------------------------------------------------------------------
# "!"   -> network byte order (big-endian), and *no padding/alignment*.
#          Without "!" (or "<", ">", "="), struct uses the host's native
#          alignment rules and could insert padding bytes, silently breaking
#          the layout.
# "6s"  -> a 6-byte ``bytes`` object (the MAC address, kept as raw bytes).
# "H"   -> unsigned short, 2 bytes (the EtherType).
_ETH_HEADER: Final = struct.Struct("!6s6sH")
ETH_HEADER_LEN: Final[int] = _ETH_HEADER.size  # 14 bytes, computed, not hard-coded

# The 802.1Q tag after the TPID: TCI (2 bytes) + inner EtherType (2 bytes).
_VLAN_TAG: Final = struct.Struct("!HH")
VLAN_TAG_LEN: Final[int] = _VLAN_TAG.size  # 4 bytes

# Smallest legal EtherType. Anything lower is an 802.3 length field.
_ETHERTYPE_MIN: Final[int] = 0x0600

BROADCAST_MAC: Final[bytes] = b"\xff" * 6


class EtherType(IntEnum):
    """Common EtherType values (IEEE registry).

    ``IntEnum`` means members compare equal to plain ints
    (``EtherType.IPV4 == 0x0800`` is True) while still printing a readable
    name. That keeps the parser fast and the output friendly.
    """

    IPV4 = 0x0800
    ARP = 0x0806
    VLAN = 0x8100  # IEEE 802.1Q tag protocol identifier (TPID)
    IPV6 = 0x86DD
    QINQ = 0x88A8  # IEEE 802.1ad "double tagging" outer TPID
    LLDP = 0x88CC


def ethertype_name(value: int) -> str:
    """Return a readable label for an EtherType, e.g. ``"IPV4 (0x0800)"``."""
    if value < _ETHERTYPE_MIN:
        return f"802.3 length={value}"
    try:
        return f"{EtherType(value).name} (0x{value:04x})"
    except ValueError:
        return f"UNKNOWN (0x{value:04x})"


def format_mac(raw: bytes) -> str:
    """Convert 6 raw bytes into the familiar ``aa:bb:cc:dd:ee:ff`` form.

    ``bytes.hex(sep)`` (Python 3.8+) does the work in C, which is faster and
    clearer than ``":".join(f"{b:02x}" for b in raw)``.
    """
    if len(raw) != 6:
        raise ValueError(f"MAC address must be 6 bytes, got {len(raw)}")
    return raw.hex(":")


@dataclass(frozen=True, slots=True)
class EthernetFrame:
    """A decoded Ethernet II frame.

    ``frozen=True`` makes instances immutable. Once a packet is parsed, no
    other thread (Milestone 4) can modify it by accident, so it is safe to
    share across threads without locks.

    ``slots=True`` drops the per-instance ``__dict__``. That saves memory and
    speeds up attribute access, which matters when we create thousands of
    these objects per second.
    """

    dst_mac: bytes
    src_mac: bytes
    ethertype: int
    vlan_id: int | None
    payload: bytes

    @property
    def dst(self) -> str:
        """Destination MAC in colon-hex notation."""
        return format_mac(self.dst_mac)

    @property
    def src(self) -> str:
        """Source MAC in colon-hex notation."""
        return format_mac(self.src_mac)

    @property
    def is_broadcast(self) -> bool:
        """True when the frame is addressed to every host (ff:ff:ff:ff:ff:ff)."""
        return self.dst_mac == BROADCAST_MAC

    @property
    def is_multicast(self) -> bool:
        """True when the I/G bit (least significant bit of byte 0) is set.

        Bitwise lesson: ``0x01 & first_byte`` isolates bit 0. On the wire,
        Ethernet sends each byte least-significant-bit first, so this is
        literally the first bit transmitted. Switches use it to decide
        "unicast or group?" before the rest of the address arrives.
        Broadcast is a special case of multicast (all bits set).
        """
        return bool(self.dst_mac[0] & 0x01)

    def summary(self) -> str:
        """One-line, human-readable description of the frame."""
        vlan = f" vlan={self.vlan_id}" if self.vlan_id is not None else ""
        return (
            f"{self.src} -> {self.dst} "
            f"type={ethertype_name(self.ethertype)}{vlan} "
            f"payload={len(self.payload)}B"
        )


def parse_ethernet(data: bytes) -> EthernetFrame:
    """Decode the Ethernet header at the start of ``data``.

    Args:
        data: Raw bytes as returned by ``recvfrom`` on an ``AF_PACKET`` socket.

    Returns:
        An immutable ``EthernetFrame``. ``payload`` is everything after the
        header (and after the VLAN tag, if one was present).

    Raises:
        PacketParseError: If ``data`` is shorter than a complete header.

    """
    if len(data) < ETH_HEADER_LEN:
        raise PacketParseError(
            f"Ethernet frame too short: {len(data)} bytes, need {ETH_HEADER_LEN}"
        )

    # unpack_from reads at an offset without slicing first, so no copy of
    # the whole buffer is made just to read 14 bytes.
    dst_mac, src_mac, ethertype = _ETH_HEADER.unpack_from(data, 0)
    offset = ETH_HEADER_LEN
    vlan_id: int | None = None

    # 802.1Q: the "EtherType" we just read is really the TPID 0x8100, and the
    # real EtherType follows the 2-byte TCI. We only unwrap one tag here;
    # QinQ (two tags) is left as an exercise.
    if ethertype == EtherType.VLAN:
        if len(data) < offset + VLAN_TAG_LEN:
            raise PacketParseError("Truncated 802.1Q VLAN tag")
        tci, ethertype = _VLAN_TAG.unpack_from(data, offset)
        # TCI layout (16 bits): PCP (3) | DEI (1) | VID (12).
        # Masking with 0x0FFF keeps only the low 12 bits: the VLAN ID.
        vlan_id = tci & 0x0FFF
        offset += VLAN_TAG_LEN

    return EthernetFrame(
        dst_mac=dst_mac,
        src_mac=src_mac,
        ethertype=ethertype,
        vlan_id=vlan_id,
        # memoryview would avoid this copy; we keep bytes for simplicity and
        # immutability, and revisit the trade-off in Milestone 4.
        payload=data[offset:],
    )
