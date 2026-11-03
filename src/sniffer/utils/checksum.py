"""The Internet checksum (RFC 1071), used by IPv4, ICMP, TCP and UDP.

The algorithm in plain words
----------------------------
1. Treat the data as a sequence of 16-bit big-endian words. If the length is
   odd, pretend there is one extra zero byte at the end.
2. Add all the words together with ordinary integer addition.
3. "Fold" the carries: anything above 16 bits is added back into the low 16
   bits, repeatedly, until the sum fits in 16 bits. This is what makes it a
   *one's complement* sum (end-around carry) instead of a normal sum.
4. Invert every bit (one's complement). That is the checksum.

Why verification checks for zero
--------------------------------
The sender stores the checksum C in the header. C is defined as ``~S``, where
S is the folded sum of everything else. When the receiver adds *everything*
including C, it gets ``S + ~S = 0xFFFF`` (all ones). Inverting that gives 0.
So: run the same function over the received header, and 0 means "valid".

Worked example from RFC 1071 section 3::

    words  0x0001 + 0xF203 + 0xF4F5 + 0xF6F7 = 0x2DDF0
    fold   0xDDF0 + 0x2 = 0xDDF2
    invert ~0xDDF2 & 0xFFFF = 0x220D   <- the checksum

Interview fact: the one's complement sum is *byte-order independent*
(RFC 1071, section 2B). Summing byte-swapped words gives a byte-swapped
result, so fast implementations skip the conversion entirely. We use
explicit big-endian words for clarity.

Weakness worth knowing: because addition is commutative, swapping two
16-bit words does not change the checksum, so it cannot catch reordering.
It is a cheap error detector, not a security control. Anyone who modifies a
packet can trivially recompute it.
"""

from __future__ import annotations

import struct
from typing import Final

_MASK16: Final[int] = 0xFFFF


def ones_complement_sum(data: bytes) -> int:
    """Return the folded 16-bit one's complement sum of ``data``."""
    if len(data) % 2:
        data += b"\x00"  # step 1: pad odd lengths (padding is not sent)
    word_count = len(data) // 2
    # "!{n}H" unpacks n big-endian unsigned 16-bit words in a single C call,
    # far faster than a Python loop calling int.from_bytes on each pair.
    words: tuple[int, ...] = struct.unpack(f"!{word_count}H", data)
    total = sum(words)
    # Step 3: fold. A single fold is not always enough: 0x1FFFF folds to
    # 0x10000, which still carries. The loop runs at most twice in practice.
    while total >> 16:
        total = (total & _MASK16) + (total >> 16)
    return total


def internet_checksum(data: bytes) -> int:
    """Return the RFC 1071 checksum of ``data``.

    To *compute* a checksum, call this with the checksum field zeroed.
    To *verify* one, call it over the data as received: 0 means valid.
    """
    return ~ones_complement_sum(data) & _MASK16
