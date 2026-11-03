"""Demonstrate a lost-update race condition and the lock that fixes it.

Run:  python examples/race_demo.py

Eight threads each add 1 to a shared counter 20,000 times, so the correct
total is 160,000. The unsafe version reads the value, calls a function, then
writes the sum back. Another thread can run in between, and its update gets
overwritten.
"""

from __future__ import annotations

import sys
import threading

THREADS = 8
INCREMENTS = 20_000


def one() -> int:
    """Return 1. The call gives the interpreter a chance to switch threads."""
    return 1


class UnsafeCounter:
    """Read-modify-write with no lock."""

    def __init__(self) -> None:
        self.value = 0

    def increment(self) -> None:
        """Add one, unsafely."""
        self.value = self.value + one()


class SafeCounter(UnsafeCounter):
    """The same operation, guarded by a lock."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()

    def increment(self) -> None:
        """Add one while holding the lock."""
        with self._lock:
            self.value = self.value + one()


def hammer(counter: UnsafeCounter) -> int:
    """Run THREADS threads that each increment INCREMENTS times."""

    def work() -> None:
        for _ in range(INCREMENTS):
            counter.increment()

    threads = [threading.Thread(target=work) for _ in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return counter.value


def main() -> None:
    """Compare the two counters."""
    sys.setswitchinterval(1e-6)  # switch threads as often as possible
    expected = THREADS * INCREMENTS
    for counter in (UnsafeCounter(), SafeCounter()):
        total = hammer(counter)
        lost = expected - total
        print(f"{type(counter).__name__:<14} total={total:>7}  lost={lost}")


if __name__ == "__main__":
    main()
