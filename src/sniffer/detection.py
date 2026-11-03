"""Milestone 5: the threat detection engine.

Three kinds of detection, and why a real IDS needs all three
-------------------------------------------------------------
1. **Signature (stateless)**: one packet is enough to decide. A TCP segment
   with no flags at all (a NULL scan) or with SYN and FIN together can't come
   from a correct TCP stack, so the packet itself is the evidence. Cheap and
   precise, but blind to anything that only looks bad *in aggregate*.
2. **Threshold (stateful)**: count something per key over a time window.
   One SYN is normal; 5,000 SYNs to the same port in 10 seconds is a flood.
   One connection attempt is normal; one source touching 100 different ports
   on a host is a scan. This needs memory, which is where the hard
   engineering is (see "Bounded state" below).
3. **Health / meta-detection**: alerts about the sensor itself. If the
   sniffer is dropping 30% of packets, every other rule is partly blind, and
   an analyst needs to know that before trusting a quiet dashboard. (That is
   the "sensor blinding" attack from the Milestone 4 Deep Dive.)

Event time, not wall-clock time
-------------------------------
Windows are measured with each frame's capture timestamp, not with
``time.time()`` at the moment the detector runs. Under load, events sit in
queues for a while; with wall-clock time a burst that arrived in 1 second but
was processed over 5 would look 5x slower than it really was. Event time also
makes the engine deterministic: tests feed timestamps and get exact results.
``time.time()`` can jump backwards (NTP corrections), so the detector keeps a
*monotonic* event clock: it never lets "now" move backwards.

Bounded state (the part attackers aim at)
-----------------------------------------
Every per-key table here has a hard size limit with least-recently-used
(LRU) eviction. Without one, a spoofed SYN flood with random source addresses
creates a new table entry per packet, and the detector itself becomes the
memory-exhaustion target (the same lesson as the bounded queues in
Milestone 4). ``collections.OrderedDict`` gives O(1) "move to end" and
"pop oldest", which is exactly an LRU cache. Evictions are counted, because
silently forgetting state is also a form of blindness.

Alert fatigue
-------------
A 60-second flood would otherwise produce one alert per packet past the
threshold: tens of thousands of identical lines that bury everything else.
Each (rule, entity) pair has a cooldown: after it fires, repeats are counted
but not emitted until the cooldown expires, and the next alert reports how
many were suppressed. This is the same idea as Snort's ``detection_filter``
and Suricata's ``threshold`` keywords.

MITRE ATT&CK mapping
--------------------
Every alert carries technique IDs so a SOC can pivot from an alert to the
adversary behaviour it represents:

* T1046     Network Service Discovery (port scans, stealth-flag probes)
* T1499.001 Endpoint Denial of Service: OS Exhaustion Flood (SYN floods)
* T1595.001 Active Scanning: Scanning IP Blocks (horizontal sweeps)
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Hashable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Final, Generic, TypeVar

from sniffer.capture import PacketType
from sniffer.events import JSONValue, PacketEvent
from sniffer.protocols.ipv4 import IPv4Packet
from sniffer.protocols.tcp import TCPFlag, TCPSegment
from sniffer.protocols.udp import UDPDatagram

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


class Severity(IntEnum):
    """How urgently a human should look. IntEnum, so severities compare."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True, slots=True)
class Alert:
    """One detection, ready for a console, a JSON file or a SIEM."""

    rule: str  # stable machine name, e.g. "syn_flood"
    severity: Severity
    timestamp: float  # event time of the packet that triggered it
    summary: str  # one human-readable sentence
    src: str | None = None
    dst: str | None = None
    mitre: tuple[str, ...] = ()
    details: dict[str, JSONValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, JSONValue]:
        """Flatten into JSON-ready primitives (one alert per JSON line)."""
        return {
            "ts": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "rule": self.rule,
            "severity": self.severity.name,
            "src": self.src,
            "dst": self.dst,
            "summary": self.summary,
            "mitre": list(self.mitre),
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Every tunable number in one place, with the reasoning for its default.

    Thresholds are a trade-off between false positives (alerting on a busy
    but healthy server) and false negatives (missing a slow attacker). The
    defaults suit a single host or a lab network. A production sensor would
    *baseline* normal traffic first and set thresholds above it.
    """

    # Sliding window length for every threshold rule.
    window_s: float = 10.0
    # Half-open connection attempts (SYN without ACK) to one ip:port per
    # window. A small web server rarely sees 20 new connections per second.
    syn_flood_threshold: int = 200
    # Distinct destination ports probed on one host by one source. Browsers
    # open many connections, but to the *same* few ports (80/443).
    vertical_scan_ports: int = 20
    # Distinct hosts probed on the same port by one source. Higher than the
    # port threshold, because legit tools (monitoring, backup agents)
    # legitimately touch many hosts on one port.
    horizontal_scan_hosts: int = 30
    # Minimum seconds between two alerts for the same rule and entity.
    cooldown_s: float = 60.0
    # Hard cap on keys in every state table (memory bound, see module doc).
    max_tracked_keys: int = 10_000
    # Cap on distinct items remembered per key (ports, hosts, sources).
    max_items_per_key: int = 1_024
    # Skip frames the kernel marks OUTGOING: our own traffic. On loopback
    # this also removes the duplicate copy of every packet (Milestone 1).
    ignore_outgoing: bool = True

    def __post_init__(self) -> None:
        """Reject impossible settings early, with a clear message."""
        for name in (
            "syn_flood_threshold",
            "vertical_scan_ports",
            "horizontal_scan_hosts",
            "max_tracked_keys",
            "max_items_per_key",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        # math.isfinite rejects inf and nan. Without this, --window inf would
        # pass "<= 0" yet make every rate-window bucket live forever, so a
        # long-running detector grows per-key state without bound despite the
        # key cap -- turning the detector into the memory-exhaustion target.
        if not math.isfinite(self.window_s) or self.window_s <= 0:
            raise ValueError("window_s must be a positive, finite number")
        if not math.isfinite(self.cooldown_s) or self.cooldown_s < 0:
            raise ValueError("cooldown_s must be a non-negative, finite number")


# ---------------------------------------------------------------------------
# State containers. Each is small, generic and unit-tested on its own.
# ---------------------------------------------------------------------------


class BoundedLRU(Generic[K, V]):
    """A dict with a size limit that evicts the least recently used key.

    ``get_or_create`` both reads and refreshes a key, so keys that keep
    receiving traffic stay, and idle keys age out first. An attacker who
    sprays random keys can only push out *other idle* state, never grow
    memory past ``max_keys``.
    """

    def __init__(self, max_keys: int, factory: Callable[[], V]) -> None:
        self._data: OrderedDict[K, V] = OrderedDict()
        self._max_keys = max_keys
        self._factory = factory
        self.evictions = 0

    def get_or_create(self, key: K) -> V:
        """Return the value for ``key``, creating it if needed."""
        value = self._data.get(key)
        if value is None:
            value = self._factory()
            self._data[key] = value
            if len(self._data) > self._max_keys:
                self._data.popitem(last=False)  # oldest = least recently used
                self.evictions += 1
        else:
            self._data.move_to_end(key)  # mark as most recently used
        return value

    def __len__(self) -> int:
        """Return the number of keys currently tracked."""
        return len(self._data)


class RateWindow:
    """Count events in the last ``window`` seconds, in O(buckets) memory.

    Storing one timestamp per event would be exact, but a flood of 100k
    packets/s over a 10 s window means a million floats *per key*. Instead
    we keep a short queue of (bucket_start, count) pairs, one per second
    with traffic. The answer is accurate to one bucket width, and memory per
    key is at most ``window / bucket`` entries no matter how fast packets
    arrive. Precision traded for a hard memory bound, on purpose.
    """

    __slots__ = ("_bucket_s", "_buckets", "_total", "_window_s")

    def __init__(self, window_s: float, bucket_s: float = 1.0) -> None:
        self._window_s = window_s
        self._bucket_s = min(bucket_s, window_s)
        self._buckets: deque[list[float]] = deque()  # [start, count] pairs
        self._total = 0

    def add(self, now: float, amount: int = 1) -> int:
        """Record ``amount`` events at time ``now``; return the window total."""
        start = now - (now % self._bucket_s)
        if self._buckets and self._buckets[-1][0] == start:
            self._buckets[-1][1] += amount
        else:
            self._buckets.append([start, float(amount)])
        self._total += amount
        self._expire(now)
        return self._total

    def _expire(self, now: float) -> None:
        cutoff = now - self._window_s
        # A bucket covers [start, start + bucket). Drop it once it is
        # entirely older than the window.
        while self._buckets and self._buckets[0][0] + self._bucket_s <= cutoff:
            _start, count = self._buckets.popleft()
            self._total -= int(count)


class DistinctWindow:
    """Count *distinct* items (ports, hosts) seen in the last ``window`` s.

    An OrderedDict maps item -> last time seen, ordered oldest first.
    Re-seeing an item moves it to the end, so expiry is just "pop from the
    front while too old": O(1) amortized per packet. ``max_items`` caps
    memory per key; once a scan has crossed the threshold we don't need to
    remember its 60,000th port.
    """

    __slots__ = ("_items", "_max_items", "_window_s")

    def __init__(self, window_s: float, max_items: int) -> None:
        self._window_s = window_s
        self._max_items = max_items
        self._items: OrderedDict[str, float] = OrderedDict()

    def add(self, item: str, now: float) -> int:
        """Record ``item`` at ``now``; return the distinct count in window."""
        self._items[item] = now
        self._items.move_to_end(item)
        cutoff = now - self._window_s
        while self._items:
            oldest_item, seen = next(iter(self._items.items()))
            if seen > cutoff and len(self._items) <= self._max_items:
                break
            del self._items[oldest_item]
        return len(self._items)

    def sample(self, limit: int = 10) -> list[str]:
        """Return up to ``limit`` most recent items (for alert details)."""
        return list(self._items)[-limit:]


class Cooldown:
    """Per-(rule, entity) alert suppression with a suppressed-repeat count."""

    def __init__(self, cooldown_s: float, max_keys: int) -> None:
        self._cooldown_s = cooldown_s
        # value: [last_alert_time, suppressed_since_then]
        self._state: BoundedLRU[Hashable, list[float]] = BoundedLRU(
            max_keys, lambda: [float("-inf"), 0.0]
        )
        self.suppressed = 0

    def check(self, key: Hashable, now: float) -> int | None:
        """Return suppressed-repeat count if an alert may fire, else None."""
        entry = self._state.get_or_create(key)
        if now - entry[0] < self._cooldown_s:
            entry[1] += 1
            self.suppressed += 1
            return None
        repeats = int(entry[1])
        entry[0], entry[1] = now, 0.0
        return repeats


# ---------------------------------------------------------------------------
# Helpers that classify one packet.
# ---------------------------------------------------------------------------

_XMAS: Final = TCPFlag.FIN | TCPFlag.PSH | TCPFlag.URG


def invalid_flag_combo(flags: int) -> str | None:  # noqa: PLR0911
    """Name the impossible TCP flag combination in ``flags``, if any.

    RFC 9293 says every segment after the initial SYN carries ACK, so the
    only legitimate segments *without* ACK are a SYN (connection start) and
    some RSTs. Everything else without ACK is crafted, and these crafted
    combinations are classic scanner probes (nmap -sN, -sF, -sX): a closed
    port answers with RST, an open one stays silent, and some old firewalls
    only filtered SYNs, so these slipped through.
    """
    ack = bool(flags & TCPFlag.ACK)
    syn = bool(flags & TCPFlag.SYN)
    if flags == 0:
        return "NULL (no flags)"
    if syn and flags & TCPFlag.FIN:
        return "SYN+FIN"  # "open and close at once"; also an OS fingerprint
    if syn and flags & TCPFlag.RST:
        return "SYN+RST"
    if not ack and (flags & _XMAS) == _XMAS:
        return "XMAS (FIN+PSH+URG)"  # "lit up like a Christmas tree"
    if not ack and flags & TCPFlag.FIN:
        return "FIN without ACK"
    if not (ack or syn or flags & TCPFlag.RST):
        return "no ACK on a non-SYN segment"
    return None


def is_connection_attempt(tcp: TCPSegment) -> bool:
    """Return True for a handshake's first packet: SYN set, ACK not set.

    ECE and CWR may also be set: SYN+ECE+CWR is how a client offers ECN
    (RFC 3168), so it is still a normal connection attempt.
    """
    return tcp.has(TCPFlag.SYN) and not (
        tcp.flags & (TCPFlag.ACK | TCPFlag.RST | TCPFlag.FIN)
    )


def _is_probe(tcp: TCPSegment) -> bool:
    """Packets a port scanner sends: SYNs plus the stealth flag combos."""
    return is_connection_attempt(tcp) or invalid_flag_combo(tcp.flags) is not None


# RFC 1858: a first fragment too small to hold the TCP flags (byte 13) can
# hide them in a second fragment, past a filter that only checks the first.
_TINY_FRAGMENT_BYTES: Final[int] = 16
# Fewer distinct sources than this is never called "distributed".
_MIN_FLOOD_SOURCES: Final[int] = 10


@dataclass(slots=True)
class DetectorStats:
    """Counters an operator needs to judge whether the detector can be trusted."""

    events: int = 0
    inspected: int = 0
    skipped_outgoing: int = 0
    skipped_bad_checksum: int = 0
    alerts: int = 0
    suppressed: int = 0
    evicted_keys: int = 0
    tracked_keys: int = 0

    def summary(self) -> str:
        """One-line operator view."""
        return (
            f"inspected={self.inspected}/{self.events} alerts={self.alerts} "
            f"suppressed={self.suppressed} "
            f"skipped(outgoing={self.skipped_outgoing}, "
            f"bad_checksum={self.skipped_bad_checksum}) "
            f"state(keys={self.tracked_keys}, evicted={self.evicted_keys})"
        )


class Detector:
    """Run every rule over a stream of PacketEvents.

    Not thread-safe by design: it is driven only by the pipeline's single
    sink thread (Milestone 4, rule 4), so its tables need no locks. That is
    a big reason for the single-writer design.
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = cfg = config if config is not None else DetectionConfig()
        window, items = cfg.window_s, cfg.max_items_per_key

        def distinct() -> DistinctWindow:
            return DistinctWindow(window, items)

        # syn_flood: key (dst_ip, dst_port) -> SYN rate, and distinct sources
        self._syn_rate: BoundedLRU[tuple[str, int], RateWindow] = BoundedLRU(
            cfg.max_tracked_keys, lambda: RateWindow(window)
        )
        self._syn_sources: BoundedLRU[tuple[str, int], DistinctWindow] = BoundedLRU(
            cfg.max_tracked_keys, distinct
        )
        # vertical scan: (src, dst) -> distinct "port/protocol" strings
        self._ports_per_host: BoundedLRU[tuple[str, str], DistinctWindow] = BoundedLRU(
            cfg.max_tracked_keys, distinct
        )
        # horizontal scan: (src, protocol, dst_port) -> distinct dst hosts
        self._hosts_per_port: BoundedLRU[tuple[str, str, int], DistinctWindow] = (
            BoundedLRU(cfg.max_tracked_keys, distinct)
        )
        self._cooldown = Cooldown(cfg.cooldown_s, cfg.max_tracked_keys)
        self._clock = float("-inf")  # monotonic event clock
        self._stats = DetectorStats()

    @property
    def stats(self) -> DetectorStats:
        """Current counters, including state-table size and evictions."""
        tables = (
            self._syn_rate,
            self._syn_sources,
            self._ports_per_host,
            self._hosts_per_port,
        )
        self._stats.evicted_keys = sum(t.evictions for t in tables)
        self._stats.tracked_keys = sum(len(t) for t in tables)
        self._stats.suppressed = self._cooldown.suppressed
        return self._stats

    # -- entry point -----------------------------------------------------------

    def process(self, event: PacketEvent) -> list[Alert]:
        """Inspect one event and return any alerts it triggers."""
        self._stats.events += 1
        packet = event.packet
        if packet is None or packet.ip is None:
            return []  # not IPv4, or an unparseable frame
        if self.config.ignore_outgoing and event.frame.pkttype == PacketType.OUTGOING:
            self._stats.skipped_outgoing += 1
            return []
        # Insertion-attack defense (Milestone 3 Deep Dive): a packet with a
        # bad checksum will be dropped by the real receiver. If we counted
        # it, an attacker could feed us packets the target never sees and
        # make us believe a different story.
        #
        # But CHECKSUM_PARTIAL ("partial") is NOT a bad checksum: it means
        # the NIC or the loopback driver will finish the sum later, and the
        # stored value only looks wrong to us. Every locally generated and
        # every loopback packet is marked this way, so treating partial as
        # "bad" would make the detector blind to all of it. Skip only a
        # checksum that is genuinely wrong (verified False, not offloaded).
        bad_transport = (
            packet.transport_checksum_valid is False
            and not packet.transport_checksum_partial
        )
        if not packet.ip.checksum_valid or bad_transport:
            self._stats.skipped_bad_checksum += 1
            return []

        self._stats.inspected += 1
        now = self._clock = max(self._clock, event.frame.timestamp)
        ip = packet.ip
        alerts = self._ip_anomalies(ip, now)
        transport = packet.transport
        if isinstance(transport, TCPSegment):
            alerts += self._tcp_rules(ip, transport, now)
        elif isinstance(transport, UDPDatagram):
            alerts += self._scan_rules(ip, "udp", transport.dst_port, now)
        self._stats.alerts += len(alerts)
        return alerts

    # -- rules -------------------------------------------------------------------

    def _emit(  # noqa: PLR0913 - an alert has many facets
        self,
        rule: str,
        entity: Hashable,
        now: float,
        *,
        severity: Severity,
        summary: str,
        src: str | None,
        dst: str | None,
        mitre: tuple[str, ...] = (),
        details: dict[str, JSONValue] | None = None,
    ) -> list[Alert]:
        """Build an alert unless (rule, entity) is still cooling down."""
        repeats = self._cooldown.check((rule, entity), now)
        if repeats is None:
            return []
        info: dict[str, JSONValue] = dict(details or {})
        if repeats:
            info["suppressed_repeats"] = repeats
        return [
            Alert(
                rule=rule,
                severity=severity,
                timestamp=now,
                summary=summary,
                src=src,
                dst=dst,
                mitre=mitre,
                details=info,
            )
        ]

    def _ip_anomalies(self, ip: IPv4Packet, now: float) -> list[Alert]:
        """Single-packet IP-layer signatures."""
        src, dst = str(ip.src), str(ip.dst)
        alerts: list[Alert] = []
        if ip.has_source_route:
            # LSRR/SSRR let the *sender* choose the path, which can route
            # around firewalls and let a spoofer receive replies. RFC 7126
            # recommends dropping them; no modern legit traffic uses them.
            alerts += self._emit(
                "ip_source_route",
                src,
                now,
                severity=Severity.HIGH,
                summary=f"IPv4 source-route option from {src}",
                src=src,
                dst=dst,
                details={"option_types": list(ip.option_types)},
            )
        if ip.reserved_flag:
            # RFC 3514 was an April Fools' joke, but a set reserved bit
            # still means the packet was hand-crafted by a tool.
            alerts += self._emit(
                "ip_reserved_bit",
                src,
                now,
                severity=Severity.LOW,
                summary=f"IPv4 reserved ('evil') bit set by {src}",
                src=src,
                dst=dst,
            )
        if (
            ip.more_fragments
            and ip.fragment_offset == 0
            and ip.protocol == 6  # TCP
            and len(ip.payload) < _TINY_FRAGMENT_BYTES
        ):
            alerts += self._emit(
                "ip_tiny_fragment",
                src,
                now,
                severity=Severity.MEDIUM,
                summary=(
                    f"Tiny first TCP fragment ({len(ip.payload)} bytes) "
                    f"from {src}: flags may be hidden in a later fragment"
                ),
                src=src,
                dst=dst,
                details={"payload_len": len(ip.payload), "rfc": "1858"},
            )
        return alerts

    def _tcp_rules(self, ip: IPv4Packet, tcp: TCPSegment, now: float) -> list[Alert]:
        src, dst = str(ip.src), str(ip.dst)
        alerts: list[Alert] = []

        combo = invalid_flag_combo(tcp.flags)
        if combo is not None:
            alerts += self._emit(
                "tcp_invalid_flags",
                (src, combo),
                now,
                severity=Severity.MEDIUM,
                summary=f"{combo} TCP probe {src} -> {dst}:{tcp.dst_port}",
                src=src,
                dst=f"{dst}:{tcp.dst_port}",
                mitre=("T1046",),
                details={
                    "tcp_flags": tcp.flag_names,
                    "flags_hex": f"0x{tcp.flags:02x}",
                },
            )

        if is_connection_attempt(tcp):
            alerts += self._syn_flood(src, dst, tcp.dst_port, now)
        if _is_probe(tcp):
            alerts += self._scan_rules(ip, "tcp", tcp.dst_port, now)
        return alerts

    def _syn_flood(self, src: str, dst: str, port: int, now: float) -> list[Alert]:
        """Too many half-open connection attempts to one service.

        Keyed on the *destination*, not the source: a spoofed flood uses a
        new random source address per packet, so no single source ever
        crosses a per-source threshold. The victim is the stable key.
        """
        key = (dst, port)
        syns = self._syn_rate.get_or_create(key).add(now)
        sources = self._syn_sources.get_or_create(key).add(src, now)
        if syns < self.config.syn_flood_threshold:
            return []
        # Many distinct sources at high rate = spoofed or distributed (DDoS).
        # One source = a single attacker, or a misbehaving client. The
        # source table is capped at max_items_per_key, so a full table also
        # counts as "many" (otherwise a 100k-SYN flood with 1,024 remembered
        # sources would look like a 1-in-100 ratio and be misclassified).
        many = min(syns // 4, self.config.max_items_per_key)
        distributed = sources > _MIN_FLOOD_SOURCES and sources >= many
        kind = "distributed/spoofed" if distributed else "single-source"
        return self._emit(
            "syn_flood",
            key,
            now,
            severity=Severity.CRITICAL if distributed else Severity.HIGH,
            summary=(
                f"SYN flood ({kind}) against {dst}:{port}: {syns} SYNs from "
                f"{sources} source(s) in {self.config.window_s:g}s"
            ),
            src=None if distributed else src,
            dst=f"{dst}:{port}",
            mitre=("T1499.001",),
            details={
                "syn_count": syns,
                "distinct_sources": sources,
                "window_s": self.config.window_s,
                "spoofing_suspected": distributed,
            },
        )

    def _scan_rules(
        self, ip: IPv4Packet, proto: str, port: int, now: float
    ) -> list[Alert]:
        """Vertical scan (many ports, one host) and horizontal (one port, many hosts).

        Keyed on the *source*: unlike a flood, a scanner needs the answers
        to come back, so it can't spoof its address (decoy scans like
        ``nmap -D`` add fake sources, but the real one is among them).
        """
        src, dst = str(ip.src), str(ip.dst)
        cfg = self.config
        alerts: list[Alert] = []

        ports = self._ports_per_host.get_or_create((src, dst))
        port_count = ports.add(f"{port}/{proto}", now)
        if port_count >= cfg.vertical_scan_ports:
            alerts += self._emit(
                "port_scan_vertical",
                (src, dst),
                now,
                severity=Severity.MEDIUM,
                summary=(
                    f"Port scan: {src} probed {port_count} ports on {dst} "
                    f"in {cfg.window_s:g}s"
                ),
                src=src,
                dst=dst,
                mitre=("T1046",),
                details={
                    "distinct_ports": port_count,
                    "recent_ports": list(ports.sample()),
                    "window_s": cfg.window_s,
                },
            )

        hosts = self._hosts_per_port.get_or_create((src, proto, port))
        host_count = hosts.add(dst, now)
        if host_count >= cfg.horizontal_scan_hosts:
            alerts += self._emit(
                "port_scan_horizontal",
                (src, proto, port),
                now,
                severity=Severity.MEDIUM,
                summary=(
                    f"Host sweep: {src} probed {port}/{proto} on {host_count} "
                    f"hosts in {cfg.window_s:g}s"
                ),
                src=src,
                dst=None,
                mitre=("T1046", "T1595.001"),
                details={
                    "distinct_hosts": host_count,
                    "port": f"{port}/{proto}",
                    "recent_hosts": list(hosts.sample()),
                    "window_s": cfg.window_s,
                },
            )
        return alerts


# ---------------------------------------------------------------------------
# Sensor health: the "who watches the watcher" rule.
# ---------------------------------------------------------------------------


class HealthMonitor:
    """Alert when the sensor is losing packets (it is partly blind).

    Runs on the main (supervisor) thread every few seconds, comparing two
    PipelineStats snapshots. Loss = kernel drops + queue drops since the
    last check, divided by everything offered since the last check.

    Why a *ratio over an interval* and not "any drop": a single drop during
    a burst is normal on any sensor, and alerting on it would train
    analysts to ignore the alert. A sustained loss rate is the signal. And
    the minimum packet count stops "1 of 3 packets dropped (33%!)" on an
    idle link from paging anyone.
    """

    def __init__(
        self,
        *,
        loss_threshold: float = 0.01,
        min_packets: int = 1_000,
        cooldown_s: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._loss_threshold = loss_threshold
        self._min_packets = min_packets
        self._cooldown = Cooldown(cooldown_s, max_keys=4)
        self._clock = clock
        self._last: tuple[int, int, int] = (0, 0, 0)

    def check(
        self, captured: int, queue_dropped: int, kernel_drops: int
    ) -> list[Alert]:
        """Compare cumulative counters with the previous call's values."""
        last_captured, last_queue, last_kernel = self._last
        self._last = (captured, queue_dropped, kernel_drops)
        d_captured = captured - last_captured
        d_queue = queue_dropped - last_queue
        d_kernel = kernel_drops - last_kernel
        # Frames the kernel dropped never reached `captured`; frames the
        # queue dropped did. So offered = captured + kernel drops.
        offered = d_captured + d_kernel
        lost = d_queue + d_kernel
        if offered < self._min_packets or offered == 0:
            return []
        ratio = lost / offered
        if ratio < self._loss_threshold:
            return []
        now = self._clock()
        if self._cooldown.check("sensor", now) is None:
            return []
        severity = Severity.CRITICAL if ratio >= 0.5 else Severity.HIGH
        return [
            Alert(
                rule="sensor_degraded",
                severity=severity,
                timestamp=now,
                summary=(
                    f"Sensor is dropping {ratio:.1%} of traffic "
                    f"({lost} of {offered} frames): detections are incomplete"
                ),
                details={
                    "loss_ratio": round(ratio, 4),
                    "offered": offered,
                    "kernel_drops": d_kernel,
                    "queue_drops": d_queue,
                },
            )
        ]
