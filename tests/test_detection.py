"""Tests for the detection engine, driven by synthetic timestamped packets."""

from __future__ import annotations

import io
import json
import socket
import struct
import threading
from pathlib import Path

import pytest

from sniffer.alerts import (
    AlertDispatcher,
    ConsoleAlertOutput,
    DetectorSink,
    JsonAlertOutput,
)
from sniffer.capture import PacketType, RawFrame
from sniffer.detection import (
    Alert,
    BoundedLRU,
    Cooldown,
    DetectionConfig,
    Detector,
    DistinctWindow,
    HealthMonitor,
    RateWindow,
    Severity,
    invalid_flag_combo,
)
from sniffer.events import PacketEvent
from sniffer.exceptions import OutputError
from sniffer.protocols.tcp import TCPFlag
from sniffer.utils.checksum import ones_complement_sum, pseudo_header
from tests.packets import build_frame, build_ipv4, build_tcp, build_udp

ATTACKER = "203.0.113.66"
VICTIM = "198.51.100.10"

SYN = int(TCPFlag.SYN)
ACK = int(TCPFlag.ACK)


def ip(text: str) -> bytes:
    return socket.inet_aton(text)


def tcp_event(  # noqa: PLR0913
    *,
    ts: float = 1000.0,
    src: str = ATTACKER,
    dst: str = VICTIM,
    dst_port: int = 80,
    src_port: int = 40000,
    flags: int = SYN,
    pkttype: int = PacketType.HOST,
    ip_kwargs: dict[str, int | bytes] | None = None,
    tcp_checksum: int | None = None,
) -> PacketEvent:
    segment = build_tcp(
        src_port=src_port,
        dst_port=dst_port,
        flags=flags,
        src_ip=ip(src),
        dst_ip=ip(dst),
        checksum=tcp_checksum,
    )
    packet = build_ipv4(payload=segment, src=ip(src), dst=ip(dst), **(ip_kwargs or {}))  # type: ignore[arg-type]
    frame = RawFrame(
        build_frame(packet), timestamp=ts, interface="eth0", pkttype=pkttype
    )
    return PacketEvent.from_frame(0, frame)


def udp_event(*, ts: float, dst_port: int, dst: str = VICTIM) -> PacketEvent:
    datagram = build_udp(
        src_port=50000, dst_port=dst_port, src_ip=ip(ATTACKER), dst_ip=ip(dst)
    )
    packet = build_ipv4(payload=datagram, src=ip(ATTACKER), dst=ip(dst), protocol=17)
    frame = RawFrame(build_frame(packet), timestamp=ts, interface="eth0", pkttype=0)
    return PacketEvent.from_frame(0, frame)


def run(detector: Detector, events: list[PacketEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        alerts += detector.process(event)
    return alerts


def rules(alerts: list[Alert]) -> list[str]:
    return [a.rule for a in alerts]


# -- state containers -----------------------------------------------------------


class TestRateWindow:
    def test_counts_within_window(self) -> None:
        window = RateWindow(window_s=10.0)
        totals = [window.add(1000.0 + i * 0.1) for i in range(50)]
        assert totals[-1] == 50

    def test_old_buckets_expire(self) -> None:
        window = RateWindow(window_s=10.0)
        for _ in range(100):
            window.add(1000.0)
        # 11 s later the whole first bucket is outside the 10 s window.
        assert window.add(1011.0) == 1

    def test_memory_is_bounded_by_buckets_not_packets(self) -> None:
        window = RateWindow(window_s=10.0)
        for i in range(100_000):
            window.add(1000.0 + i / 10_000)  # 100k packets over 10 seconds
        assert len(window._buckets) <= 11


class TestDistinctWindow:
    def test_repeats_do_not_inflate_count(self) -> None:
        window = DistinctWindow(window_s=10.0, max_items=100)
        for _ in range(5):
            window.add("80/tcp", 1000.0)
        assert window.add("443/tcp", 1000.0) == 2

    def test_items_expire(self) -> None:
        window = DistinctWindow(window_s=10.0, max_items=100)
        window.add("a", 1000.0)
        window.add("b", 1005.0)
        assert window.add("c", 1012.0) == 2  # "a" is 12 s old

    def test_refresh_keeps_item_alive(self) -> None:
        window = DistinctWindow(window_s=10.0, max_items=100)
        window.add("a", 1000.0)
        window.add("b", 1001.0)
        window.add("a", 1009.0)  # seen again: moved to the back
        assert window.add("c", 1012.0) == 2  # "b" expired, "a" did not

    def test_max_items_caps_memory(self) -> None:
        window = DistinctWindow(window_s=10.0, max_items=50)
        counts = [window.add(str(i), 1000.0) for i in range(500)]
        assert max(counts) == 50


class TestBoundedLRU:
    def test_evicts_least_recently_used(self) -> None:
        lru: BoundedLRU[str, list[int]] = BoundedLRU(2, list)
        lru.get_or_create("a").append(1)
        lru.get_or_create("b")
        lru.get_or_create("a")  # touch "a": now "b" is the oldest
        lru.get_or_create("c")
        assert lru.evictions == 1
        assert lru.get_or_create("a") == [1]  # survived
        assert len(lru) == 2

    def test_random_key_spray_cannot_grow_memory(self) -> None:
        lru: BoundedLRU[int, int] = BoundedLRU(100, int)
        for key in range(10_000):
            lru.get_or_create(key)
        assert len(lru) == 100
        assert lru.evictions == 9_900


class TestCooldown:
    def test_suppresses_then_reports_repeats(self) -> None:
        cooldown = Cooldown(cooldown_s=60.0, max_keys=10)
        assert cooldown.check("k", 1000.0) == 0
        assert cooldown.check("k", 1010.0) is None
        assert cooldown.check("k", 1020.0) is None
        assert cooldown.check("k", 1061.0) == 2
        assert cooldown.suppressed == 2

    def test_keys_are_independent(self) -> None:
        cooldown = Cooldown(cooldown_s=60.0, max_keys=10)
        assert cooldown.check("a", 1000.0) == 0
        assert cooldown.check("b", 1000.0) == 0


# -- flag classification --------------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (0x00, "NULL (no flags)"),
        (0x03, "SYN+FIN"),
        (0x06, "SYN+RST"),
        (0x29, "XMAS (FIN+PSH+URG)"),
        (0x01, "FIN without ACK"),
        (0x08, "no ACK on a non-SYN segment"),
        (0x02, None),  # SYN
        (0x12, None),  # SYN+ACK
        (0xC2, None),  # SYN+ECE+CWR: ECN negotiation, legitimate
        (0x10, None),  # ACK
        (0x11, None),  # FIN+ACK: normal close
        (0x18, None),  # PSH+ACK: normal data
        (0x04, None),  # RST: legitimate without ACK
        (0x14, None),  # RST+ACK
    ],
)
def test_invalid_flag_combo(flags: int, expected: str | None) -> None:
    assert invalid_flag_combo(flags) == expected


# -- rules ------------------------------------------------------------------------


class TestSynFlood:
    def test_spoofed_flood_is_critical_and_keyed_on_victim(self) -> None:
        detector = Detector(DetectionConfig(syn_flood_threshold=100))
        events = [
            tcp_event(ts=1000.0 + i * 0.01, src=f"10.0.{i // 250}.{i % 250 + 1}")
            for i in range(150)
        ]
        alerts = run(detector, events)
        floods = [a for a in alerts if a.rule == "syn_flood"]
        assert len(floods) == 1  # cooldown: one alert, not 51
        flood = floods[0]
        assert flood.severity is Severity.CRITICAL
        assert flood.dst == f"{VICTIM}:80"
        assert flood.src is None  # spoofed: no single source to blame
        assert flood.details["spoofing_suspected"] is True
        assert flood.mitre == ("T1499.001",)

    def test_single_source_flood_is_high(self) -> None:
        detector = Detector(DetectionConfig(syn_flood_threshold=100))
        alerts = run(detector, [tcp_event(ts=1000 + i * 0.01) for i in range(100)])
        assert rules(alerts) == ["syn_flood"]
        assert alerts[0].severity is Severity.HIGH
        assert alerts[0].src == ATTACKER

    def test_slow_rate_does_not_alert(self) -> None:
        detector = Detector(DetectionConfig(syn_flood_threshold=100, window_s=10))
        # 200 SYNs, but one every 0.2 s: at most ~50 in any 10 s window.
        alerts = run(detector, [tcp_event(ts=1000 + i * 0.2) for i in range(200)])
        assert "syn_flood" not in rules(alerts)

    def test_syn_ack_is_not_counted(self) -> None:
        detector = Detector(DetectionConfig(syn_flood_threshold=10))
        alerts = run(detector, [tcp_event(flags=SYN | ACK) for _ in range(50)])
        assert alerts == []

    def test_cooldown_expiry_reports_suppressed_repeats(self) -> None:
        detector = Detector(DetectionConfig(syn_flood_threshold=10, cooldown_s=5))
        first = run(detector, [tcp_event(ts=1000 + i * 0.01) for i in range(20)])
        later = run(detector, [tcp_event(ts=1006 + i * 0.01) for i in range(5)])
        assert rules(first) == ["syn_flood"]
        assert rules(later) == ["syn_flood"]
        assert later[0].details["suppressed_repeats"] == 10

    def test_huge_flood_with_full_source_table_is_still_distributed(self) -> None:
        config = DetectionConfig(syn_flood_threshold=100, max_items_per_key=64)
        detector = Detector(config)
        events = [
            tcp_event(
                ts=1000 + i * 0.001, src=f"10.{i // 65536}.{i // 256 % 256}.{i % 256}"
            )
            for i in range(2_000)
        ]
        floods = [a for a in run(detector, events) if a.rule == "syn_flood"]
        assert floods[0].details["spoofing_suspected"] is True


class TestPortScan:
    def test_vertical_scan(self) -> None:
        detector = Detector(DetectionConfig(vertical_scan_ports=20))
        events = [tcp_event(ts=1000 + i * 0.01, dst_port=1 + i) for i in range(100)]
        alerts = run(detector, events)
        assert rules(alerts) == ["port_scan_vertical"]
        alert = alerts[0]
        assert alert.src == ATTACKER
        assert alert.dst == VICTIM
        assert alert.details["distinct_ports"] == 20
        assert alert.mitre == ("T1046",)

    def test_many_connections_to_one_port_is_not_a_scan(self) -> None:
        detector = Detector(DetectionConfig(vertical_scan_ports=20))
        events = [tcp_event(ts=1000 + i, src_port=40000 + i) for i in range(100)]
        assert run(detector, events) == []

    def test_horizontal_sweep(self) -> None:
        detector = Detector(DetectionConfig(horizontal_scan_hosts=30))
        events = [
            tcp_event(ts=1000 + i * 0.01, dst=f"198.51.100.{i + 1}", dst_port=22)
            for i in range(60)
        ]
        alerts = run(detector, events)
        assert rules(alerts) == ["port_scan_horizontal"]
        assert alerts[0].details["port"] == "22/tcp"
        assert "T1595.001" in alerts[0].mitre

    def test_udp_scan(self) -> None:
        detector = Detector(DetectionConfig(vertical_scan_ports=20))
        events = [udp_event(ts=1000 + i * 0.01, dst_port=1 + i) for i in range(25)]
        assert rules(run(detector, events)) == ["port_scan_vertical"]

    def test_stealth_scan_also_counts_ports(self) -> None:
        detector = Detector(DetectionConfig(vertical_scan_ports=20, cooldown_s=60))
        events = [
            tcp_event(ts=1000 + i * 0.01, dst_port=1 + i, flags=0x29) for i in range(25)
        ]
        found = rules(run(detector, events))
        assert found.count("tcp_invalid_flags") == 1  # cooled down after one
        assert "port_scan_vertical" in found

    def test_ports_spread_beyond_window_do_not_alert(self) -> None:
        detector = Detector(DetectionConfig(vertical_scan_ports=20, window_s=10))
        # A slow scan: one port every 2 s. Only ~5 ports per 10 s window.
        events = [tcp_event(ts=1000 + i * 2, dst_port=1 + i) for i in range(100)]
        assert run(detector, events) == []


class TestSignatures:
    def test_xmas_probe(self) -> None:
        alerts = Detector().process(tcp_event(flags=0x29))
        assert rules(alerts) == ["tcp_invalid_flags"]
        assert alerts[0].details["tcp_flags"] == "FIN|PSH|URG"

    def test_source_route_option(self) -> None:
        lsrr = bytes([131, 7, 4]) + ip("192.0.2.1") + b"\x01"  # LSRR + NOP pad
        event = tcp_event(flags=SYN | ACK, ip_kwargs={"options": lsrr})
        alerts = Detector().process(event)
        assert rules(alerts) == ["ip_source_route"]
        assert alerts[0].severity is Severity.HIGH

    def test_evil_bit(self) -> None:
        event = tcp_event(flags=ACK, ip_kwargs={"flags_frag": 0x8000})
        assert rules(Detector().process(event)) == ["ip_reserved_bit"]

    def test_tiny_first_fragment(self) -> None:
        # MF set, offset 0, and only 8 bytes of TCP: flags would be in the
        # next fragment. build_ipv4 lets us craft this by hand.
        tiny_tcp = struct.pack("!HHI", 40000, 80, 1)
        packet = build_ipv4(payload=tiny_tcp, flags_frag=0x2000)
        frame = RawFrame(
            build_frame(packet), timestamp=1.0, interface="eth0", pkttype=0
        )
        alerts = Detector().process(PacketEvent.from_frame(0, frame))
        assert "ip_tiny_fragment" in rules(alerts)


class TestEvasionAndHygiene:
    def test_bad_tcp_checksum_is_ignored(self) -> None:
        """Insertion attack: the target drops it, so the IDS must too."""
        detector = Detector()
        alerts = detector.process(tcp_event(flags=0x29, tcp_checksum=0x1234))
        assert alerts == []
        assert detector.stats.skipped_bad_checksum == 1

    def test_offloaded_partial_checksum_is_inspected(self) -> None:
        """CHECKSUM_PARTIAL is offload, not corruption: every loopback and
        locally generated packet is marked this way, so the detector must
        still inspect it (this was a real bug found in live loopback testing).
        """
        # Linux writes only the folded pseudo-header sum; the NIC finishes
        # the rest later. A sniffer sees the packet before that happens.
        src, dst = ip(ATTACKER), ip(VICTIM)
        segment = build_tcp(flags=0x29, src_ip=src, dst_ip=dst, checksum=0)
        partial = ones_complement_sum(pseudo_header(src, dst, 6, len(segment)))
        event = tcp_event(flags=0x29, tcp_checksum=partial)
        assert event.packet is not None
        assert event.packet.transport_checksum_partial is True
        detector = Detector()
        assert rules(detector.process(event)) == ["tcp_invalid_flags"]
        assert detector.stats.skipped_bad_checksum == 0

    def test_bad_ip_checksum_is_ignored(self) -> None:
        detector = Detector()
        event = tcp_event(flags=0x29, ip_kwargs={"checksum": 0x1234})
        assert detector.process(event) == []

    def test_outgoing_frames_are_skipped(self) -> None:
        detector = Detector()
        assert (
            detector.process(tcp_event(flags=0x29, pkttype=PacketType.OUTGOING)) == []
        )
        assert detector.stats.skipped_outgoing == 1

    def test_outgoing_can_be_inspected_when_configured(self) -> None:
        detector = Detector(DetectionConfig(ignore_outgoing=False))
        event = tcp_event(flags=0x29, pkttype=PacketType.OUTGOING)
        assert rules(detector.process(event)) == ["tcp_invalid_flags"]

    def test_event_clock_never_runs_backwards(self) -> None:
        detector = Detector(DetectionConfig(syn_flood_threshold=10))
        run(detector, [tcp_event(ts=2000.0)])
        # An NTP step sends time.time() back an hour. Without the monotonic
        # clock these SYNs would expire the existing state instantly.
        alerts = run(detector, [tcp_event(ts=1000.0) for _ in range(9)])
        assert rules(alerts) == ["syn_flood"]
        assert alerts[0].timestamp == 2000.0

    def test_state_tables_stay_bounded_under_spoofing(self) -> None:
        detector = Detector(DetectionConfig(max_tracked_keys=50))
        events = [
            tcp_event(
                ts=1000 + i * 0.001,
                src=f"10.0.{i // 256}.{i % 256}",
                dst_port=80 + i % 7,
            )
            for i in range(2_000)
        ]
        run(detector, events)
        stats = detector.stats
        assert stats.tracked_keys <= 4 * 50
        assert stats.evicted_keys > 0

    def test_invalid_config_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="syn_flood_threshold"):
            DetectionConfig(syn_flood_threshold=0)
        with pytest.raises(ValueError, match="window_s"):
            DetectionConfig(window_s=0)


# -- health monitor ---------------------------------------------------------------


class TestHealthMonitor:
    def make(self) -> HealthMonitor:
        return HealthMonitor(loss_threshold=0.01, min_packets=1000, clock=lambda: 5.0)

    def test_alerts_on_sustained_kernel_drops(self) -> None:
        monitor = self.make()
        alerts = monitor.check(captured=9_000, queue_dropped=0, kernel_drops=1_000)
        assert rules(alerts) == ["sensor_degraded"]
        assert alerts[0].details["loss_ratio"] == 0.1
        assert alerts[0].details["offered"] == 10_000
        assert alerts[0].severity is Severity.HIGH

    def test_massive_loss_is_critical(self) -> None:
        alerts = self.make().check(captured=1_000, queue_dropped=0, kernel_drops=99_000)
        assert alerts[0].severity is Severity.CRITICAL

    def test_queue_drops_count_too(self) -> None:
        alerts = self.make().check(captured=10_000, queue_dropped=500, kernel_drops=0)
        assert alerts[0].details["queue_drops"] == 500

    def test_uses_deltas_between_checks(self) -> None:
        monitor = HealthMonitor(min_packets=1000, cooldown_s=0, clock=lambda: 5.0)
        assert monitor.check(captured=9_000, queue_dropped=0, kernel_drops=1_000)
        # Next interval: 10k more frames, no new drops. Cumulative drops are
        # still 1,000, but the *rate* is now zero, so no alert.
        assert monitor.check(captured=19_000, queue_dropped=0, kernel_drops=1_000) == []

    def test_idle_link_never_alerts(self) -> None:
        assert self.make().check(captured=2, queue_dropped=0, kernel_drops=1) == []

    def test_low_loss_rate_does_not_alert(self) -> None:
        assert (
            self.make().check(captured=99_950, queue_dropped=0, kernel_drops=50) == []
        )


# -- alert outputs ------------------------------------------------------------------


def sample_alert() -> Alert:
    return Alert(
        rule="syn_flood",
        severity=Severity.HIGH,
        timestamp=0.0,
        summary="test flood",
        src="1.2.3.4",
        dst="5.6.7.8:80",
        mitre=("T1499.001",),
        details={"syn_count": 500, "suppressed_repeats": 3},
    )


def test_console_alert_output_format() -> None:
    stream = io.StringIO()
    ConsoleAlertOutput(stream).write(sample_alert())
    line = stream.getvalue()
    assert line.startswith("00:00:00 ALERT HIGH     syn_flood: test flood")
    assert "[T1499.001]" in line
    assert "(+3 repeats suppressed)" in line


def test_json_alert_output(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    output = JsonAlertOutput(path)
    output.write(sample_alert())
    output.close()
    record = json.loads(path.read_text())
    assert record["rule"] == "syn_flood"
    assert record["severity"] == "HIGH"
    assert record["ts"] == "1970-01-01T00:00:00+00:00"
    assert record["mitre"] == ["T1499.001"]
    assert record["details"]["syn_count"] == 500


def test_json_alert_output_bad_path(tmp_path: Path) -> None:
    with pytest.raises(OutputError, match="Cannot open alert log"):
        JsonAlertOutput(tmp_path / "missing" / "alerts.jsonl")


def test_dispatcher_is_safe_across_threads() -> None:
    stream = io.StringIO()
    dispatcher = AlertDispatcher([ConsoleAlertOutput(stream)])

    def spam() -> None:
        for _ in range(500):
            dispatcher.emit([sample_alert()])

    threads = [threading.Thread(target=spam) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    lines = stream.getvalue().splitlines()
    assert dispatcher.count == 2_000
    assert len(lines) == 2_000
    assert all(line.startswith("00:00:00 ALERT") for line in lines)


def test_detector_sink_emits_alerts() -> None:
    stream = io.StringIO()
    sink = DetectorSink(Detector(), AlertDispatcher([ConsoleAlertOutput(stream)]))
    sink.handle(tcp_event(flags=0x00))
    sink.close()
    assert "tcp_invalid_flags" in stream.getvalue()
