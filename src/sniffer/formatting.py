"""Human-readable, one-line rendering of decoded packets for the console."""

from __future__ import annotations

from datetime import datetime, timezone

from sniffer.capture import PacketType, RawFrame
from sniffer.decode import Transport
from sniffer.events import PacketEvent
from sniffer.protocols.ipv4 import IPv4Packet
from sniffer.protocols.tcp import TCPSegment
from sniffer.protocols.udp import UDPDatagram


def checksum_label(valid: bool | None, pkttype: int) -> str:
    """Turn a checksum result into ``ok``, ``BAD``, ``offload`` or ``n/a``.

    Checksum offload: the kernel copies outgoing packets to sniffers BEFORE
    the NIC finishes the TCP/UDP checksum, so a "bad" checksum on an
    OUTGOING packet is expected, not an attack. Labelling it honestly avoids
    a flood of false alarms.
    """
    if valid is None:
        return "n/a"
    if valid:
        return "ok"
    return "offload" if pkttype == PacketType.OUTGOING else "BAD"


def _endpoint(ip: IPv4Packet, transport: Transport | None) -> str:
    """``a.b.c.d:port -> e.f.g.h:port``, or bare addresses without ports."""
    if isinstance(transport, (TCPSegment, UDPDatagram)):
        return f"{ip.src}:{transport.src_port} -> {ip.dst}:{transport.dst_port}"
    return f"{ip.src} -> {ip.dst}"


def format_event(event: PacketEvent, *, show_ethernet: bool = False) -> str:
    """Render one event as a single summary line (plus detail lines with -e)."""
    frame = event.frame
    ts = datetime.fromtimestamp(frame.timestamp, tz=timezone.utc).strftime(
        "%H:%M:%S.%f"
    )
    prefix = f"#{event.index:<5} {ts} {frame.interface:<8} {frame.direction:<9}"
    pkt = event.packet
    if pkt is None:
        # A malformed frame must never crash a sniffer: show it and move on.
        # Attackers send malformed packets precisely to crash parsers.
        return f"{prefix} <malformed: {event.error}>"

    ip = pkt.ip
    if ip is None:
        return f"{prefix} {pkt.ethernet.summary()}"

    ip_chk = checksum_label(ip.checksum_valid, frame.pkttype)
    parts = [prefix, _endpoint(ip, pkt.transport), ip.protocol_name]
    if pkt.transport is not None:
        parts.append(pkt.transport.summary())
        l4_chk = (
            "partial"
            if pkt.transport_checksum_partial
            else checksum_label(pkt.transport_checksum_valid, frame.pkttype)
        )
    elif pkt.transport_error is not None:
        parts.append(f"<malformed {ip.protocol_name}: {pkt.transport_error}>")
        l4_chk = "n/a"
    else:
        l4_chk = "n/a"
    if ip.is_fragment:
        parts.append(f"frag@{ip.fragment_offset}{'+MF' if ip.more_fragments else ''}")
    parts.append(f"ttl={ip.ttl} chk={ip_chk}/{l4_chk}")
    line = " ".join(parts)
    if show_ethernet:
        line += f"\n{'':>41}{pkt.ethernet.summary()}"
        line += f"\n{'':>41}{ip.summary()}"
    return line


def format_frame(index: int, frame: RawFrame, *, show_ethernet: bool = False) -> str:
    """Decode and render a raw frame (convenience wrapper for one-off use)."""
    return format_event(
        PacketEvent.from_frame(index, frame), show_ethernet=show_ethernet
    )
