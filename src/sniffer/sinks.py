"""Event sinks: where decoded packets go. All run on the single sink thread."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from sniffer.events import PacketEvent
from sniffer.formatting import format_event
from sniffer.utils.hexdump import hexdump


class ConsoleSink:
    """Print one summary line per packet (optionally with a hex dump).

    With several decoder workers, lines can appear slightly out of order.
    The ``#index`` column is the capture order, so you can see it happen.
    """

    def __init__(
        self,
        *,
        show_ethernet: bool = False,
        hexdump_bytes: int | None = None,
        stream: TextIO | None = None,
    ) -> None:
        self._show_ethernet = show_ethernet
        self._hexdump_bytes = hexdump_bytes
        self._stream = stream if stream is not None else sys.stdout

    def handle(self, event: PacketEvent) -> None:
        """Print the event."""
        print(format_event(event, show_ethernet=self._show_ethernet), file=self._stream)
        if self._hexdump_bytes is not None:
            dump = hexdump(event.frame.data, max_bytes=self._hexdump_bytes)
            print(dump, end="\n\n", file=self._stream)

    def close(self) -> None:
        """Flush stdout."""
        self._stream.flush()


class JsonLinesSink:
    """Append one JSON object per line (the "JSON Lines" / NDJSON format).

    Why JSON Lines: each line is a complete record, so the file can be
    tailed live, appended forever, split anywhere, and ingested directly by
    Splunk, Elastic, Loki or ``jq``. A single big JSON array has none of
    those properties.
    """

    def __init__(self, path: str | Path) -> None:
        # buffering=1 means line-buffered: each record reaches the OS as soon
        # as its newline is written, so `tail -f` sees it immediately and a
        # crash loses at most the line being written.
        self._file = Path(path).open("a", encoding="utf-8", buffering=1)  # noqa: SIM115

    def handle(self, event: PacketEvent) -> None:
        """Write the event as one compact JSON line."""
        self._file.write(json.dumps(event.to_dict(), separators=(",", ":")) + "\n")

    def close(self) -> None:
        """Flush and close the file."""
        self._file.close()
