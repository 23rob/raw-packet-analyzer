"""Custom exception hierarchy for the sniffer.

Why a custom hierarchy instead of letting ``OSError`` bubble up?

1. The CLI can catch *one* base class (``SnifferError``) and turn every
   expected failure into a clean, human-readable message instead of a
   traceback.
2. Each subclass carries intent. ``InsufficientPrivilegesError`` tells the
   caller "re-run with sudo", while ``InterfaceError`` says "you typed the
   wrong interface name". A raw ``OSError(errno=1)`` says neither.
3. The original low-level exception is kept via ``raise ... from exc`` so
   debugging information is never thrown away (exception chaining).
"""

from __future__ import annotations


class SnifferError(Exception):
    """Base class for every error this package raises on purpose."""


class UnsupportedPlatformError(SnifferError):
    """Raised when the OS does not provide the raw socket API we need.

    Milestone 1 targets Linux ``AF_PACKET``. Windows (``SIO_RCVALL``) and
    macOS (BPF) need different backends.
    """


class InsufficientPrivilegesError(SnifferError):
    """Raised when the process lacks ``CAP_NET_RAW`` (usually: not root)."""


class InterfaceError(SnifferError):
    """Raised when a network interface name does not exist or cannot be used."""


class PacketParseError(SnifferError):
    """Raised when a byte buffer is too short or malformed for a header."""
