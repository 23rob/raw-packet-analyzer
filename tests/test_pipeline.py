"""Tests for the threaded pipeline, driven by a fake frame source."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator

import pytest

from sniffer.capture import KernelStats, RawFrame
from sniffer.events import PacketEvent
from sniffer.exceptions import InsufficientPrivilegesError
from sniffer.pipeline import Counter, Pipeline
from tests.packets import build_frame, build_ipv4, build_tcp

TIMEOUT = 5.0


def tcp_frame(i: int = 0) -> RawFrame:
    data = build_frame(build_ipv4(payload=build_tcp(seq=i)))
    return RawFrame(data=data, timestamp=float(i), interface="eth0", pkttype=0)


class FakeSource:
    """Hands out prepared frames, then behaves like an idle socket."""

    def __init__(self, frames: list[RawFrame], *, kernel_drops: int = 0) -> None:
        self._frames: Iterator[RawFrame] = iter(frames)
        self._kernel = KernelStats(packets=len(frames), drops=kernel_drops)
        self._kernel_read = False

    def recv(self) -> RawFrame | None:
        frame = next(self._frames, None)
        if frame is None:
            time.sleep(0.01)  # idle tick, like a socket timeout
        return frame

    def kernel_stats(self) -> KernelStats | None:
        # Like PACKET_STATISTICS: report once, then reset to zero.
        if self._kernel_read:
            return KernelStats(0, 0)
        self._kernel_read = True
        return self._kernel


class ListSink:
    def __init__(self) -> None:
        self.events: list[PacketEvent] = []
        self.closed = False

    def handle(self, event: PacketEvent) -> None:
        self.events.append(event)

    def close(self) -> None:
        self.closed = True


class BlockingSink(ListSink):
    """Blocks until released, to simulate a slow consumer."""

    def __init__(self) -> None:
        super().__init__()
        self.release = threading.Event()

    def handle(self, event: PacketEvent) -> None:
        self.release.wait(TIMEOUT)
        super().handle(event)


def test_processes_every_frame_with_count() -> None:
    sink = ListSink()
    pipeline = Pipeline(FakeSource([tcp_frame(i) for i in range(50)]), [sink], count=50)
    pipeline.start()
    assert pipeline.wait(TIMEOUT)
    pipeline.stop()
    stats = pipeline.stats()
    assert stats.captured == 50
    assert stats.processed == 50
    assert stats.queue_dropped == 0
    assert sorted(e.index for e in sink.events) == list(range(1, 51))
    assert sink.closed


def test_request_stop_drains_and_finishes() -> None:
    sink = ListSink()
    pipeline = Pipeline(FakeSource([tcp_frame(i) for i in range(10)]), [sink])
    pipeline.start()
    deadline = time.monotonic() + TIMEOUT
    while pipeline.stats().processed < 10 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert pipeline.stop(TIMEOUT)
    assert len(sink.events) == 10


def test_idle_pipeline_stops_promptly() -> None:
    pipeline = Pipeline(FakeSource([]), [ListSink()])
    pipeline.start()
    started = time.monotonic()
    assert pipeline.stop(TIMEOUT)
    assert time.monotonic() - started < 1.0


def test_full_queue_sheds_load_and_accounting_balances() -> None:
    # One worker, tiny queues, and a sink that is stuck: the capture thread
    # must drop (and count) instead of blocking.
    sink = BlockingSink()
    frames = [tcp_frame(i) for i in range(200)]
    pipeline = Pipeline(FakeSource(frames), [sink], workers=1, queue_size=2, count=200)
    pipeline.start()
    deadline = time.monotonic() + TIMEOUT
    while pipeline.stats().captured < 200 and time.monotonic() < deadline:
        time.sleep(0.01)
    sink.release.set()
    assert pipeline.wait(TIMEOUT)
    pipeline.stop()
    stats = pipeline.stats()
    assert stats.captured == 200
    assert stats.queue_dropped > 0
    # The invariant: every captured frame was either dropped or processed.
    assert stats.captured == stats.queue_dropped + stats.processed


def test_kernel_stats_accumulate() -> None:
    pipeline = Pipeline(
        FakeSource([tcp_frame()], kernel_drops=7), [ListSink()], count=1
    )
    pipeline.start()
    assert pipeline.wait(TIMEOUT)
    pipeline.stop()
    assert pipeline.stats().kernel_drops == 7
    assert pipeline.stats().kernel_drops == 7  # reading again doesn't lose it


def test_malformed_frames_are_counted_not_fatal() -> None:
    bad = RawFrame(data=b"\x00" * 5, timestamp=0.0, interface="eth0", pkttype=0)
    sink = ListSink()
    pipeline = Pipeline(FakeSource([bad, tcp_frame()]), [sink], count=2)
    pipeline.start()
    assert pipeline.wait(TIMEOUT)
    pipeline.stop()
    assert pipeline.stats().malformed == 1
    assert len(sink.events) == 2


def test_failing_sink_does_not_stop_pipeline() -> None:
    class ExplodingSink(ListSink):
        def handle(self, event: PacketEvent) -> None:
            raise RuntimeError("disk full")

    good = ListSink()
    pipeline = Pipeline(
        FakeSource([tcp_frame(i) for i in range(5)]), [ExplodingSink(), good], count=5
    )
    pipeline.start()
    assert pipeline.wait(TIMEOUT)
    pipeline.stop()
    assert len(good.events) == 5
    assert pipeline.stats().sink_errors == 5


def test_capture_error_is_reported_and_pipeline_ends() -> None:
    class BrokenSource(FakeSource):
        def recv(self) -> RawFrame | None:
            raise InsufficientPrivilegesError("no CAP_NET_RAW")

    pipeline = Pipeline(BrokenSource([]), [ListSink()])
    pipeline.start()
    assert pipeline.wait(TIMEOUT)
    pipeline.stop()
    assert isinstance(pipeline.error, InsufficientPrivilegesError)


@pytest.mark.parametrize(("workers", "size"), [(0, 10), (1, 0)])
def test_invalid_configuration(workers: int, size: int) -> None:
    with pytest.raises(ValueError):
        Pipeline(FakeSource([]), [], workers=workers, queue_size=size)


def test_counter_is_thread_safe_under_heavy_switching() -> None:
    # Force the interpreter to switch threads as often as possible, which
    # makes an unlocked read-modify-write lose increments quickly.
    counter = Counter()
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [
            threading.Thread(
                target=lambda: [counter.increment() for _ in range(20_000)]
            )
            for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(old)
    assert counter.value == 160_000
