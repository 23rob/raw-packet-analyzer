"""Multi-threaded capture pipeline: producer, decoder workers, single sink.

::

    [capture thread] --put_nowait--> raw_queue (bounded) --get--> [decoder x N]
      recvfrom only        full? -> queue_dropped += 1                  |
                                                         PacketEvent (frozen)
                                                                       | put (blocks)
                                                                       v
                                    event_queue (bounded) --> [sink thread]
                                                   console / JSON / detector

Design rules, and why
---------------------
1. **Exactly one place drops packets: the capture thread.** It uses
   ``put_nowait`` and counts every drop. It must never block, because a
   blocked capture thread stops calling ``recvfrom`` and the kernel starts
   dropping silently instead.
2. **Everything downstream uses backpressure, not drops.** Workers block on
   a full event queue, which slows them down, which fills the raw queue,
   which makes the capture thread shed load at the one place we measure.
3. **Bounded queues only.** An unbounded queue turns a traffic flood into a
   memory-exhaustion attack on the sniffer itself.
4. **One sink thread (single writer).** Console output, the JSON file and
   (in Milestone 5) the detector's state are touched by one thread only, so
   they need no locks at all.
5. **Shutdown by sentinel.** The capture thread puts one sentinel per worker
   into the raw queue. Each worker exits when it sees one, and the *last*
   worker to exit forwards a single sentinel to the sink thread. Every packet
   already queued is still processed: nothing is lost on a clean stop.

About the GIL, with numbers: CPython releases it during blocking system
calls such as ``recvfrom`` and ``queue.get``, so capture and decoding do
overlap. But pure-Python decoding never runs on two cores at once, and every
extra thread competes with the capture thread for the GIL. In a loopback
flood benchmark (about 10 million frames offered in 4 seconds) the pipeline
captured roughly 79k frames with 1 worker, 70k with 2 and 55k with 4: more
threads, *less* throughput. So the default is 1 worker. Real scaling means
kernel-side filtering (BPF), PACKET_MMAP ring buffers, multiprocessing or
the free-threaded CPython build, all of which fit this structure without
changing the parsers.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from sniffer.capture import KernelStats, RawFrame
from sniffer.events import PacketEvent

logger = logging.getLogger(__name__)

DEFAULT_WORKERS: Final[int] = 1  # measured: more threads = less throughput (GIL)
DEFAULT_QUEUE_SIZE: Final[int] = 10_000


class FrameSource(Protocol):
    """Anything that yields raw frames: the real socket, or a test fake.

    Using a ``Protocol`` (structural typing) means the pipeline depends on
    behaviour, not on the RawSocketCapture class. Tests can drive the whole
    pipeline without root or a network.
    """

    def recv(self) -> RawFrame | None:
        """Return one frame, or None if nothing arrived before a timeout."""
        ...

    def kernel_stats(self) -> KernelStats | None:
        """Return (and reset) kernel counters, or None if unavailable."""
        ...


class Sink(Protocol):
    """A consumer of decoded events. Only ever called from the sink thread."""

    def handle(self, event: PacketEvent) -> None:
        """Process one event."""
        ...

    def close(self) -> None:
        """Flush and release resources."""
        ...


class Counter:
    """A thread-safe integer counter.

    ``self.x += 1`` compiles to LOAD_ATTR, BINARY_OP, STORE_ATTR: a separate
    read, add and write. If another thread runs between the read and the
    write, both threads store the same new value and one increment is lost.

    Subtlety measured while building this (see examples/race_demo.py): since
    CPython 3.10 the interpreter only hands the GIL to another thread at
    certain checkpoints (function calls, loop back-edges), so a bare
    ``+= 1`` on an int rarely loses updates *in practice*. Put any call
    between the read and the write, run on the free-threaded build, or use
    another Python implementation, and updates vanish (the demo loses a third
    or more).
    Correctness must never depend on an interpreter detail, so we lock.
    """

    __slots__ = ("_lock", "_value")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value = 0

    def increment(self, amount: int = 1) -> int:
        """Add ``amount`` atomically and return the new value."""
        with self._lock:
            self._value += amount
            return self._value

    @property
    def value(self) -> int:
        """Current value (an int read is atomic, but we lock for clarity)."""
        with self._lock:
            return self._value


@dataclass(frozen=True, slots=True)
class PipelineStats:
    """A consistent-enough snapshot of the pipeline's counters.

    Invariant once the pipeline has fully stopped:
    ``captured == queue_dropped + processed``.
    """

    elapsed: float
    captured: int  # frames read from the socket
    queue_dropped: int  # frames shed because the raw queue was full
    decoded: int  # frames turned into PacketEvents by workers
    malformed: int  # events where some layer failed to parse
    processed: int  # events fully handled by the sink thread
    sink_errors: int  # exceptions raised by sinks (logged, not fatal)
    kernel_packets: int  # cumulative, from PACKET_STATISTICS
    kernel_drops: int  # cumulative silent drops in the kernel
    raw_queue_depth: int
    event_queue_depth: int

    @property
    def packets_per_second(self) -> float:
        """Average capture rate since start."""
        return self.captured / self.elapsed if self.elapsed > 0 else 0.0

    def summary(self) -> str:
        """One-line operator view of pipeline health."""
        return (
            f"captured={self.captured} ({self.packets_per_second:.0f} pps) "
            f"processed={self.processed} malformed={self.malformed} "
            f"queue_dropped={self.queue_dropped} kernel_drops={self.kernel_drops} "
            f"queues={self.raw_queue_depth}/{self.event_queue_depth}"
        )


class _Sentinel:
    """Type of the "poison pill" object that tells a consumer to exit."""


_SENTINEL: Final = _Sentinel()


class Pipeline:
    """Own the pipeline's threads and queues.

    Typical use::

    pipeline = Pipeline(source, [ConsoleSink()], workers=2)
    pipeline.start()
    while not pipeline.wait(timeout=0.5):
        ...  # main thread stays free to handle Ctrl+C and print stats
    pipeline.stop()
    """

    def __init__(
        self,
        source: FrameSource,
        sinks: Sequence[Sink],
        *,
        workers: int = DEFAULT_WORKERS,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        count: int | None = None,
    ) -> None:
        if workers < 1:
            raise ValueError("workers must be at least 1")
        if queue_size < 1:
            raise ValueError("queue_size must be at least 1")
        self._source = source
        self._sinks = list(sinks)
        self._worker_count = workers
        self._count = count

        # queue.Queue = collections.deque + one Lock + Condition variables
        # (not_empty / not_full). Every put/get is atomic across threads.
        self._raw_queue: queue.Queue[tuple[int, RawFrame] | _Sentinel] = queue.Queue(
            maxsize=queue_size
        )
        self._event_queue: queue.Queue[PacketEvent | _Sentinel] = queue.Queue(
            maxsize=queue_size
        )

        self._stop_event = threading.Event()
        self._started_at = 0.0
        self.error: BaseException | None = None  # set if the capture failed

        self._captured = Counter()
        self._queue_dropped = Counter()
        self._decoded = Counter()
        self._malformed = Counter()
        self._processed = Counter()
        self._sink_errors = Counter()
        self._workers_alive = Counter()
        self._kernel_lock = threading.Lock()
        self._kernel_packets = 0
        self._kernel_drops = 0

        self._capture_thread = threading.Thread(
            target=self._capture_loop, name="capture", daemon=True
        )
        self._worker_threads = [
            threading.Thread(target=self._decode_loop, name=f"decoder-{i}", daemon=True)
            for i in range(workers)
        ]
        self._sink_thread = threading.Thread(
            target=self._sink_loop, name="sink", daemon=True
        )
        # daemon=True is only a safety net so a hung thread can't keep the
        # process alive forever. Normal shutdown joins every thread.

    # -- public API ----------------------------------------------------------

    def start(self) -> None:
        """Start all threads. Consumers first, so nothing waits on them."""
        self._started_at = time.monotonic()
        self._workers_alive.increment(self._worker_count)
        self._sink_thread.start()
        for thread in self._worker_threads:
            thread.start()
        self._capture_thread.start()

    def request_stop(self) -> None:
        """Ask the capture thread to stop. Queued packets are still drained."""
        self._stop_event.set()

    def wait(self, timeout: float | None = None) -> bool:
        """Block until every packet has been processed. True when finished."""
        self._sink_thread.join(timeout)
        return not self._sink_thread.is_alive()

    def stop(self, timeout: float = 10.0) -> bool:
        """Request a stop, wait for the drain, then close the sinks."""
        self.request_stop()
        finished = self.wait(timeout)
        if not finished:
            logger.warning("Pipeline did not drain within %.1fs", timeout)
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:
                logger.exception("Error closing sink %r", sink)
        return finished

    def stats(self) -> PipelineStats:
        """Collect a snapshot of every counter, including the kernel's."""
        kernel = self._source.kernel_stats() if not self._capture_done() else None
        with self._kernel_lock:
            if kernel is not None:
                # PACKET_STATISTICS resets on every read, so we accumulate.
                self._kernel_packets += kernel.packets
                self._kernel_drops += kernel.drops
            kernel_packets, kernel_drops = self._kernel_packets, self._kernel_drops
        return PipelineStats(
            elapsed=time.monotonic() - self._started_at if self._started_at else 0.0,
            captured=self._captured.value,
            queue_dropped=self._queue_dropped.value,
            decoded=self._decoded.value,
            malformed=self._malformed.value,
            processed=self._processed.value,
            sink_errors=self._sink_errors.value,
            kernel_packets=kernel_packets,
            kernel_drops=kernel_drops,
            raw_queue_depth=self._raw_queue.qsize(),
            event_queue_depth=self._event_queue.qsize(),
        )

    # -- thread bodies ---------------------------------------------------------

    def _capture_done(self) -> bool:
        return self._started_at > 0 and not self._capture_thread.is_alive()

    def _capture_loop(self) -> None:
        """Drain the socket as fast as possible and never block (producer)."""
        try:
            while not self._stop_event.is_set():
                frame = self._source.recv()  # wakes up every timeout tick
                if frame is None:
                    continue
                index = self._captured.increment()
                try:
                    self._raw_queue.put_nowait((index, frame))
                except queue.Full:
                    # Load shedding: count it and get straight back to
                    # recvfrom, so the kernel buffer keeps draining.
                    self._queue_dropped.increment()
                if self._count is not None and index >= self._count:
                    break
        except BaseException as exc:  # noqa: BLE001 - reported via self.error
            self.error = exc
            logger.debug("Capture thread failed", exc_info=True)
        finally:
            # Final kernel counters before the socket can go away. A failure
            # here must not stop the sentinels below from being sent.
            try:
                self.stats()
            except OSError:
                logger.debug("Could not read final kernel stats", exc_info=True)
            # One poison pill per worker. Blocking put is fine here: the
            # workers are alive and draining the queue.
            for _ in range(self._worker_count):
                self._raw_queue.put(_SENTINEL)

    def _decode_loop(self) -> None:
        """Turn raw frames into PacketEvents (consumer and producer)."""
        try:
            while True:
                item = self._raw_queue.get()
                if isinstance(item, _Sentinel):
                    break
                index, frame = item
                event = PacketEvent.from_frame(index, frame)
                self._decoded.increment()
                if event.is_malformed:
                    self._malformed.increment()
                # Blocking put = backpressure toward the capture thread.
                self._event_queue.put(event)
        finally:
            # The last worker out tells the sink thread to finish.
            if self._workers_alive.increment(-1) == 0:
                self._event_queue.put(_SENTINEL)

    def _sink_loop(self) -> None:
        """Feed events to every sink. The only thread that touches sinks."""
        while True:
            item = self._event_queue.get()
            if isinstance(item, _Sentinel):
                break
            for sink in self._sinks:
                try:
                    sink.handle(item)
                except Exception:
                    # One bad sink (a full disk, a broken pipe) must not
                    # stop the capture. Count it and log the first ones.
                    if self._sink_errors.increment() <= 3:
                        logger.exception("Sink %r failed", sink)
            self._processed.increment()
