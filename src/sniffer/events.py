"""``PacketEvent``: one captured frame plus everything we decoded from it.

This is the unit of work that flows from the decoder workers to the sinks
(console, JSON log, and the detection engine in Milestone 5). It is frozen,
so many threads can hold a reference to the same event without locks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sniffer.capture import RawFrame
from sniffer.decode import DecodedPacket, decode_frame
from sniffer.exceptions import PacketParseError
from sniffer.protocols.ethernet import ethertype_name
from sniffer.protocols.icmp import ICMPMessage
from sniffer.protocols.tcp import TCPSegment
from sniffer.protocols.udp import UDPDatagram

JSONValue = str | int | float | bool | None | list["JSONValue"] | dict[str, "JSONValue"]


def l4_checksum_status(packet: DecodedPacket) -> str:
    """Return ``ok``, ``bad``, ``partial`` or ``n/a`` for the transport layer."""
    if packet.transport_checksum_partial:
        return "partial"
    valid = packet.transport_checksum_valid
    if valid is None:
        return "n/a"
    return "ok" if valid else "bad"


@dataclass(frozen=True, slots=True)
class PacketEvent:
    """A captured frame and its decode result.

    ``index`` is the capture sequence number assigned by the single capture
    thread, so it reflects true arrival order even after multiple decoder
    workers have shuffled the events.
    """

    index: int
    frame: RawFrame
    packet: DecodedPacket | None  # None when the outer layers were malformed
    error: str | None = None

    @classmethod
    def from_frame(cls, index: int, frame: RawFrame) -> PacketEvent:
        """Decode ``frame``. Never raises for malformed packet data."""
        try:
            return cls(index=index, frame=frame, packet=decode_frame(frame.data))
        except PacketParseError as exc:
            return cls(index=index, frame=frame, packet=None, error=str(exc))

    @property
    def is_malformed(self) -> bool:
        """True if any layer failed to parse."""
        return self.error is not None or (
            self.packet is not None and self.packet.transport_error is not None
        )

    def to_dict(self) -> dict[str, JSONValue]:
        """Flatten the event into JSON-ready primitives (one SIEM record).

        Field names are stable and lower_snake_case so tools like Splunk or
        Elastic can index them without a custom parser.
        """
        frame = self.frame
        record: dict[str, JSONValue] = {
            "index": self.index,
            "ts": datetime.fromtimestamp(frame.timestamp, tz=timezone.utc).isoformat(),
            "interface": frame.interface,
            "direction": frame.direction,
            "length": len(frame.data),
        }
        if self.packet is None:
            record["error"] = self.error
            return record

        pkt = self.packet
        record["eth_src"] = pkt.ethernet.src
        record["eth_dst"] = pkt.ethernet.dst
        record["ethertype"] = ethertype_name(pkt.ethernet.ethertype)
        ip = pkt.ip
        if ip is None:
            return record

        record.update(
            {
                "src_ip": str(ip.src),
                "dst_ip": str(ip.dst),
                "protocol": ip.protocol_name,
                "ttl": ip.ttl,
                "ip_len": ip.total_length,
                "ip_id": ip.identification,
                "ip_checksum": "ok" if ip.checksum_valid else "bad",
                "df": ip.dont_fragment,
                "mf": ip.more_fragments,
                "frag_offset": ip.fragment_offset,
                "l4_checksum": l4_checksum_status(pkt),
            }
        )
        if ip.reserved_flag:
            record["evil_bit"] = True
        if ip.has_source_route:
            record["source_route"] = True
        if pkt.transport_error is not None:
            record["error"] = pkt.transport_error

        transport = pkt.transport
        if isinstance(transport, TCPSegment):
            record.update(
                {
                    "src_port": transport.src_port,
                    "dst_port": transport.dst_port,
                    "tcp_flags": transport.flag_names,
                    "seq": transport.seq,
                    "ack": transport.ack,
                    "window": transport.window,
                    "payload_len": len(transport.payload),
                    "tcp_options": list(transport.options.kinds),
                }
            )
            if transport.options.mss is not None:
                record["mss"] = transport.options.mss
        elif isinstance(transport, UDPDatagram):
            record.update(
                {
                    "src_port": transport.src_port,
                    "dst_port": transport.dst_port,
                    "payload_len": len(transport.payload),
                }
            )
        elif isinstance(transport, ICMPMessage):
            record.update(
                {
                    "icmp_type": transport.type,
                    "icmp_code": transport.code,
                    "icmp_name": transport.type_name,
                    "payload_len": len(transport.payload),
                }
            )
        return record
