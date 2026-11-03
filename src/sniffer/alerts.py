"""Alert delivery: where detections go, and the one place that needs a lock.

Two threads produce alerts:

* the **sink thread** runs the packet rules (``DetectorSink``), and
* the **main thread** runs the sensor-health check every few seconds.

The packet pipeline avoided locks with the single-writer rule, but here two
writers share the same outputs, so ``AlertDispatcher`` serializes them with
one ``threading.Lock``. The critical section is tiny (format one line, write
it), and alerts are rare compared with packets, so contention is negligible.
Knowing *when* a lock is cheap is as important as knowing when to avoid one.

Alerts go to stderr by default, separate from the per-packet lines on
stdout, so ``sniffer -q 2> alerts.txt`` or ``sniffer | less`` behave well.
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, TextIO

from sniffer.detection import Alert, Detector
from sniffer.events import PacketEvent
from sniffer.exceptions import OutputError


class AlertOutput(Protocol):
    """Anything that can record an alert."""

    def write(self, alert: Alert) -> None:
        """Record one alert."""
        ...

    def close(self) -> None:
        """Flush and release resources."""
        ...


class ConsoleAlertOutput:
    """One readable line per alert, e.g. ``ALERT HIGH syn_flood: ...``."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr

    def write(self, alert: Alert) -> None:
        """Print the alert."""
        when = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc)
        mitre = f" [{', '.join(alert.mitre)}]" if alert.mitre else ""
        repeats = alert.details.get("suppressed_repeats")
        extra = f" (+{repeats} repeats suppressed)" if repeats else ""
        print(
            f"{when:%H:%M:%S} ALERT {alert.severity.name:<8} {alert.rule}: "
            f"{alert.summary}{mitre}{extra}",
            file=self._stream,
            flush=True,  # alerts must never sit in a buffer
        )

    def close(self) -> None:
        """Flush the stream."""
        self._stream.flush()


class JsonAlertOutput:
    """Append alerts as JSON Lines (same format as the packet log)."""

    def __init__(self, path: str | Path) -> None:
        try:
            self._file = Path(path).open("a", encoding="utf-8", buffering=1)  # noqa: SIM115
        except OSError as exc:
            raise OutputError(
                f"Cannot open alert log {str(path)!r}: {exc.strerror}"
            ) from exc

    def write(self, alert: Alert) -> None:
        """Write one compact JSON line."""
        self._file.write(json.dumps(alert.to_dict(), separators=(",", ":")) + "\n")

    def close(self) -> None:
        """Close the file."""
        self._file.close()


class AlertDispatcher:
    """Fan alerts out to every output. Safe to call from several threads."""

    def __init__(self, outputs: Sequence[AlertOutput]) -> None:
        self._outputs = list(outputs)
        self._lock = threading.Lock()
        self.count = 0

    def emit(self, alerts: Sequence[Alert]) -> None:
        """Deliver ``alerts`` to every output, atomically per alert."""
        for alert in alerts:
            with self._lock:  # one alert's lines never interleave
                self.count += 1
                for output in self._outputs:
                    output.write(alert)

    def close(self) -> None:
        """Close every output."""
        with self._lock:
            for output in self._outputs:
                output.close()


class DetectorSink:
    """Pipeline sink that runs the detector on the single sink thread.

    Plugging detection in as just another ``Sink`` means the pipeline did not
    change at all for Milestone 5. That is the payoff of the ``Sink``
    Protocol from Milestone 4.
    """

    def __init__(self, detector: Detector, dispatcher: AlertDispatcher) -> None:
        self.detector = detector
        self._dispatcher = dispatcher

    def handle(self, event: PacketEvent) -> None:
        """Run every rule over the event and emit any alerts."""
        alerts = self.detector.process(event)
        if alerts:
            self._dispatcher.emit(alerts)

    def close(self) -> None:
        """Nothing to do: the dispatcher is shared, so its owner closes it."""
