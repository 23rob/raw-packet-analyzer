"""A classic ``hexdump -C`` / Wireshark-style byte viewer.

Example output for 20 bytes::

    0000  ff ff ff ff ff ff 00 11  22 33 44 55 08 00 45 00  |........"3DU..E.|
    0010  00 54 00 00                                       |.T..|

Left column: offset in hex. Middle: each byte as two hex digits, split in two
groups of 8 for readability. Right: printable ASCII, with ``.`` for anything
that is not printable. Seeing the bytes this way is how you learn to *read*
a packet before you parse it.
"""

from __future__ import annotations

from typing import Final

_BYTES_PER_LINE: Final[int] = 16
_HALF: Final[int] = _BYTES_PER_LINE // 2
_PRINTABLE_LOW: Final[int] = 0x20  # space
_PRINTABLE_HIGH: Final[int] = 0x7E  # tilde


def _to_ascii(chunk: bytes) -> str:
    """Map each byte to its ASCII char, or ``.`` if it is not printable."""
    return "".join(
        chr(b) if _PRINTABLE_LOW <= b <= _PRINTABLE_HIGH else "." for b in chunk
    )


def hexdump(data: bytes, max_bytes: int | None = None) -> str:
    """Return a multi-line hex + ASCII rendering of ``data``.

    Args:
        data: The bytes to render.
        max_bytes: If given, render at most this many bytes and add a note
            saying how many were left out. Useful for 1500-byte frames.

    """
    shown = data if max_bytes is None else data[:max_bytes]
    lines: list[str] = []
    for offset in range(0, len(shown), _BYTES_PER_LINE):
        chunk = shown[offset : offset + _BYTES_PER_LINE]
        left = chunk[:_HALF].hex(" ")
        right = chunk[_HALF:].hex(" ")
        # Each byte is "xx " (3 chars), minus the trailing space = 23 chars
        # for a full group of 8. The ":<23" format pads short final lines
        # with spaces so the ASCII column stays aligned.
        hex_part = f"{left:<23}  {right:<23}"
        lines.append(f"{offset:04x}  {hex_part}  |{_to_ascii(chunk)}|")
    if max_bytes is not None and len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines)
