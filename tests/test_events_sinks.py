"""Tests for PacketEvent serialisation and the output sinks."""

from __future__ import annotations

import io
import json
from pathlib import Path

from sniffer.capture import RawFrame
from sniffer.events import PacketEvent
from sniffer.sinks import ConsoleSink, JsonLinesSink
from tests.packets import build_frame, build_icmp, build_ipv4, build_tcp, build_udp


def event_for(data: bytes, index: int = 1) -> PacketEvent:
    frame = RawFrame(data=data, timestamp=1_700_000_000.5, interface="eth0", pkttype=0)
    return PacketEvent.from_frame(index, frame)


def test_tcp_event_to_dict() -> None:
    record = event_for(build_frame(build_ipv4(payload=build_tcp(flags=0x12)))).to_dict()
    assert record["src_ip"] == "192.0.2.2"
    assert record["dst_port"] == 443
    assert record["tcp_flags"] == "SYN|ACK"
    assert record["l4_checksum"] == "ok"
    assert record["ts"] == "2023-11-14T22:13:20.500000+00:00"
    json.dumps(record)  # must be serialisable


def test_udp_icmp_arp_and_malformed_records_serialise() -> None:
    frames = [
        build_frame(build_ipv4(protocol=17, payload=build_udp())),
        build_frame(build_ipv4(protocol=1, payload=build_icmp())),
        build_frame(b"\x00" * 28, ethertype=0x0806),
        b"\x00" * 3,
        build_frame(build_ipv4(payload=b"\x00" * 4)),
    ]
    records = [event_for(f).to_dict() for f in frames]
    for record in records:
        json.dumps(record)
    assert records[0]["protocol"] == "UDP"
    assert records[1]["icmp_name"] == "ECHO_REQUEST"
    assert records[2]["ethertype"] == "ARP (0x0806)"
    assert "error" in records[3]
    assert "error" in records[4] and records[4]["protocol"] == "TCP"


def test_malformed_detection() -> None:
    assert event_for(b"\x00").is_malformed
    assert event_for(build_frame(build_ipv4(payload=b"\x00" * 4))).is_malformed
    assert not event_for(build_frame(build_ipv4(payload=build_tcp()))).is_malformed


def test_flag_records_for_security_signals() -> None:
    evil = event_for(build_frame(build_ipv4(flags_frag=0x8000, payload=build_tcp())))
    assert evil.to_dict()["evil_bit"] is True


def test_json_lines_sink(tmp_path: Path) -> None:
    path = tmp_path / "packets.jsonl"
    sink = JsonLinesSink(path)
    sink.handle(event_for(build_frame(build_ipv4(payload=build_tcp())), index=1))
    sink.handle(event_for(build_frame(build_ipv4(payload=build_tcp())), index=2))
    sink.close()
    lines = path.read_text().splitlines()
    assert [json.loads(line)["index"] for line in lines] == [1, 2]


def test_console_sink_with_hexdump() -> None:
    out = io.StringIO()
    sink = ConsoleSink(hexdump_bytes=16, stream=out)
    sink.handle(event_for(build_frame(build_ipv4(payload=build_tcp()))))
    sink.close()
    text = out.getvalue()
    assert "TCP [SYN]" in text
    assert text.splitlines()[1].startswith("0000  02 fc")
