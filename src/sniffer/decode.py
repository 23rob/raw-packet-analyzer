"""Full decode pipeline: raw frame bytes to a layered ``DecodedPacket``.

Each layer's header has a "next protocol" field that tells us which parser
to run on its payload:

    Ethernet.ethertype --0x0800--> IPv4.protocol --6--> TCP
                                                 --17-> UDP
                                                 --1--> ICMP

This module owns that dispatch so the CLI (and, later, the threaded
pipeline and the detection engine) all receive the same structured object
instead of each re-implementing the chain.

Error policy: a malformed *outer* layer (Ethernet, IPv4) raises
``PacketParseError``, because without it nothing is usable. A malformed
*transport* header does not raise: we keep the valid IP layer and record the
problem in ``transport_error``. A malformed TCP header on a valid IP packet
is itself useful evidence for the detection engine.
"""

from __future__ import annotations

from dataclasses import dataclass

from sniffer.exceptions import PacketParseError
from sniffer.protocols.ethernet import EthernetFrame, EtherType, parse_ethernet
from sniffer.protocols.icmp import ICMPMessage, parse_icmp
from sniffer.protocols.ipv4 import IPProtocol, IPv4Packet, parse_ipv4
from sniffer.protocols.tcp import TCPSegment, parse_tcp
from sniffer.protocols.udp import UDPDatagram, parse_udp
from sniffer.utils.checksum import (
    MAX_PSEUDO_HEADER_LENGTH,
    ones_complement_sum,
    pseudo_header,
    transport_checksum,
)

Transport = TCPSegment | UDPDatagram | ICMPMessage


@dataclass(frozen=True, slots=True)
class DecodedPacket:
    """Every layer we managed to decode from one frame."""

    ethernet: EthernetFrame
    ip: IPv4Packet | None = None
    transport: Transport | None = None
    # None means "could not be checked": not IPv4, a fragment, a truncated
    # capture, or a UDP sender that chose not to compute a checksum.
    transport_checksum_valid: bool | None = None
    transport_error: str | None = None
    # True when the stored TCP/UDP checksum is exactly the un-inverted
    # pseudo-header sum: the kernel's CHECKSUM_PARTIAL state, meaning
    # "hardware (or the loopback driver) will finish this later".
    transport_checksum_partial: bool = False


def _verify_transport_checksum(ip: IPv4Packet, transport: Transport) -> bool | None:
    """Verify a TCP/UDP checksum over the pseudo-header and whole segment."""
    if ip.truncated or ip.is_fragment:
        # The checksum covers the entire original datagram. With only part
        # of it (snaplen cut, or one fragment), verification is impossible.
        return None
    if len(ip.payload) > MAX_PSEUDO_HEADER_LENGTH:
        # A BIG TCP super-packet (IPv4 total_length 0, buffer > 64 KiB) has
        # no checksum of its own: the NIC computes one per real packet after
        # splitting it. Its length also cannot fit the pseudo-header's
        # 16-bit field, so there is nothing meaningful to verify.
        return None
    if isinstance(transport, ICMPMessage):
        return transport.checksum_valid  # ICMP verifies itself, no pseudo-header
    if isinstance(transport, UDPDatagram) and transport.checksum == 0:
        return None  # RFC 768: zero means the sender skipped it
    return (
        transport_checksum(ip.src.packed, ip.dst.packed, ip.protocol, ip.payload) == 0
    )


def _is_partial_checksum(ip: IPv4Packet, transport: Transport) -> bool:
    """Detect a checksum left in the kernel's CHECKSUM_PARTIAL state.

    With offload, Linux writes only the folded pseudo-header sum into the
    checksum field and lets the NIC add the payload and invert the result.
    A sniffer sees the packet before that happens. We verified this live: a
    loopback SYN carried 0xfe30, exactly the pseudo-header sum for
    127.0.0.1 -> 127.0.0.1, TCP, 40 bytes.

    An attacker could forge this value, but the receiving stack would then
    drop the packet as corrupt, so it buys them nothing.
    """
    if not isinstance(transport, (TCPSegment, UDPDatagram)):
        return False
    pseudo = pseudo_header(ip.src.packed, ip.dst.packed, ip.protocol, len(ip.payload))
    return transport.checksum == ones_complement_sum(pseudo)


def decode_frame(data: bytes) -> DecodedPacket:
    """Decode Ethernet, then IPv4, then TCP/UDP/ICMP when present.

    Raises:
        PacketParseError: If the Ethernet or IPv4 header is malformed.

    """
    eth = parse_ethernet(data)
    if eth.ethertype != EtherType.IPV4:
        return DecodedPacket(ethernet=eth)

    ip = parse_ipv4(eth.payload)

    # Lesson from Milestone 2: only the first fragment carries the
    # transport header. Parsing a later fragment would decode garbage.
    if not ip.is_first_fragment:
        return DecodedPacket(ethernet=eth, ip=ip)

    transport: Transport | None
    try:
        if ip.protocol == IPProtocol.TCP:
            transport = parse_tcp(ip.payload)
        elif ip.protocol == IPProtocol.UDP:
            transport = parse_udp(ip.payload)
        elif ip.protocol == IPProtocol.ICMP:
            transport = parse_icmp(ip.payload)
        else:
            return DecodedPacket(ethernet=eth, ip=ip)
    except PacketParseError as exc:
        return DecodedPacket(ethernet=eth, ip=ip, transport_error=str(exc))

    valid = _verify_transport_checksum(ip, transport)
    return DecodedPacket(
        ethernet=eth,
        ip=ip,
        transport=transport,
        transport_checksum_valid=valid,
        transport_checksum_partial=valid is False
        and _is_partial_checksum(ip, transport),
    )
