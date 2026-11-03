"""Layer 0 of our program: getting raw frames out of the Linux kernel.

How this works
--------------
``socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`` asks the kernel for a copy
of every frame, inbound *and* outbound, on every interface (or on one
interface, if we ``bind`` to it). The copy is taken in the kernel's packet
tap, *before* the IP stack, so we see the full Ethernet header.

* ``AF_PACKET``  - address family "packet": talk to the link layer directly.
* ``SOCK_RAW``   - include the link-layer header in what we receive.
                   (``SOCK_DGRAM`` here would strip it, "cooked" mode.)
* ``ETH_P_ALL``  - protocol filter 0x0003, "all EtherTypes". The kernel
                   stores this in ``sll_protocol``, which is in network byte
                   order, so we must convert it with ``htons``.

``htons`` vs ``ntohs``: both swap the two bytes on a little-endian CPU and do
nothing on a big-endian one, so they produce the same number. ``htons``
("host to network") is the *semantically* correct name here because we are
sending a value *to* the kernel in network order. Many tutorials write
``ntohs(0x0003)``; it works, but it reads backwards.

Privileges
----------
Creating this socket requires the ``CAP_NET_RAW`` capability. Root has it.
Without it, ``socket()`` fails with ``EPERM`` and Python raises
``PermissionError``, which we translate into ``InsufficientPrivilegesError``
with a helpful message.

Promiscuous mode
----------------
By default the NIC drops unicast frames addressed to other MACs. We can ask
the kernel to put the NIC in promiscuous mode *for the lifetime of this
socket* with ``setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, ...)``. This is
better than ``ip link set eth0 promisc on`` because the kernel reference-
counts it and turns it off automatically when our socket closes, even if
we crash. That needs ``CAP_NET_ADMIN`` as well.
"""

from __future__ import annotations

import errno
import socket
import struct
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from types import TracebackType
from typing import Final

from sniffer.exceptions import (
    InsufficientPrivilegesError,
    InterfaceError,
    SnifferError,
    UnsupportedPlatformError,
)

# ---------------------------------------------------------------------------
# Constants from Linux headers. Python's socket module does not export all of
# them, so we define them here with their source documented.
# ---------------------------------------------------------------------------
ETH_P_ALL: Final[int] = 0x0003  # <linux/if_ether.h>: every protocol
SOL_PACKET: Final[int] = 263  # <linux/socket.h>
PACKET_ADD_MEMBERSHIP: Final[int] = 1  # <linux/if_packet.h>
PACKET_MR_PROMISC: Final[int] = 1  # <linux/if_packet.h>

# struct packet_mreq { int mr_ifindex; unsigned short mr_type;
#                      unsigned short mr_alen; unsigned char mr_address[8]; }
# "=" means native byte order *with standard sizes and no alignment*: this is
# a struct passed to our own kernel, not sent on the network, so host order
# is correct here. Contrast with "!" for wire formats.
_PACKET_MREQ: Final = struct.Struct("=iHH8s")

# Max size of an IPv4 packet is 65,535 bytes (16-bit Total Length field).
# With GRO/LRO offloading, the kernel can hand us merged "super frames" far
# larger than the 1,500-byte MTU, so a small buffer would silently truncate
# them. 65,535 plus a 14-byte Ethernet header (plus a VLAN tag) fits.
DEFAULT_BUFFER_SIZE: Final[int] = 65_535 + 18

# A timeout makes recvfrom() wake up periodically. In Milestone 4 that lets
# the capture thread notice a shutdown request instead of blocking forever.
DEFAULT_TIMEOUT_S: Final[float] = 1.0


class PacketType(IntEnum):
    """``sll_pkttype`` values from <linux/if_packet.h>.

    The kernel tells us *why* we are seeing each frame. This is free metadata
    that a plain IP-level sniffer (or Windows SIO_RCVALL) never gets.
    """

    HOST = 0  # addressed to us
    BROADCAST = 1  # to everyone
    MULTICAST = 2  # to a group we are in
    OTHERHOST = 3  # to someone else (only seen in promiscuous mode)
    OUTGOING = 4  # sent *by* us
    LOOPBACK = 5
    USER = 6
    KERNEL = 7


@dataclass(frozen=True, slots=True)
class RawFrame:
    """One captured frame plus the metadata the kernel attached to it."""

    data: bytes
    timestamp: float  # seconds since the epoch (see note in frames())
    interface: str
    pkttype: int

    @property
    def direction(self) -> str:
        """Readable name of ``pkttype``, e.g. ``"OUTGOING"``."""
        try:
            return PacketType(self.pkttype).name
        except ValueError:
            return f"UNKNOWN({self.pkttype})"


def _require_linux() -> None:
    """Fail fast, with a clear reason, on any OS without AF_PACKET."""
    if not sys.platform.startswith("linux") or not hasattr(socket, "AF_PACKET"):
        raise UnsupportedPlatformError(
            f"AF_PACKET raw sockets are Linux-only (this is {sys.platform!r}). "
            "Run inside a Linux VM; Windows and macOS backends are future work."
        )


class RawSocketCapture:
    """Context manager around a Linux ``AF_PACKET`` raw socket.

    Usage::

        with RawSocketCapture(interface="eth0", promiscuous=True) as cap:
            for frame in cap.frames():
                ...

    Why a context manager? A raw socket is an OS resource, and with
    promiscuous mode it also changes NIC state. ``with`` guarantees
    ``close()`` runs on normal exit, on Ctrl+C, and on any exception. That
    is the RAII pattern from C++, in Python form.
    """

    def __init__(
        self,
        interface: str | None = None,
        *,
        promiscuous: bool = False,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
        timeout: float | None = DEFAULT_TIMEOUT_S,
    ) -> None:
        if promiscuous and interface is None:
            # Promiscuous mode is a per-NIC setting, so we must know which NIC.
            raise InterfaceError("Promiscuous mode requires an explicit interface")
        self.interface = interface
        self.promiscuous = promiscuous
        self.buffer_size = buffer_size
        self.timeout = timeout
        self._sock: socket.socket | None = None

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        """Create, bind and configure the raw socket."""
        _require_linux()
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
            )
        except PermissionError as exc:
            raise InsufficientPrivilegesError(
                "Raw sockets need the CAP_NET_RAW capability. "
                "Run with: sudo python -m sniffer ..."
            ) from exc

        try:
            if self.interface is not None:
                self._bind(sock, self.interface)
            if self.promiscuous:
                assert self.interface is not None  # guaranteed by __init__
                self._enable_promiscuous(sock, self.interface)
            sock.settimeout(self.timeout)
        except BaseException:
            # Never leak the file descriptor if configuration fails halfway.
            sock.close()
            raise
        self._sock = sock

    def close(self) -> None:
        """Close the socket. Safe to call more than once."""
        if self._sock is not None:
            self._sock.close()  # kernel also drops our promisc reference here
            self._sock = None

    def __enter__(self) -> RawSocketCapture:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- configuration helpers -------------------------------------------

    @staticmethod
    def _bind(sock: socket.socket, interface: str) -> None:
        """Restrict capture to one interface.

        For AF_PACKET the address is a tuple ``(ifname, protocol)``. Binding
        with protocol 0 would mean "no packets"; we repeat ETH_P_ALL.

        BYTE-ORDER TRAP (found by testing this code live): here we pass
        ETH_P_ALL in *host* order, with no htons(). CPython's bind() builds
        the ``sockaddr_ll`` struct itself and calls htons() on the protocol
        for us. ``socket.socket()``, above, does not: it passes the number
        straight to the socket(2) system call. Calling htons() here as well
        would swap twice, ask the kernel for EtherType 0x0300 (which does not
        exist), and the socket would silently receive nothing. Likewise, the
        protocol that recvfrom() returns in ``addr`` is already host order.
        """
        try:
            sock.bind((interface, ETH_P_ALL))
        except OSError as exc:
            if exc.errno in (errno.ENODEV, errno.ENXIO):
                raise InterfaceError(f"No such interface: {interface!r}") from exc
            raise

    @staticmethod
    def _enable_promiscuous(sock: socket.socket, interface: str) -> None:
        """Ask the kernel to put ``interface`` in promiscuous mode."""
        try:
            ifindex = socket.if_nametoindex(interface)
        except OSError as exc:
            raise InterfaceError(f"No such interface: {interface!r}") from exc
        mreq = _PACKET_MREQ.pack(ifindex, PACKET_MR_PROMISC, 0, b"")
        try:
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        except PermissionError as exc:
            raise InsufficientPrivilegesError(
                "Promiscuous mode needs CAP_NET_ADMIN as well as CAP_NET_RAW"
            ) from exc

    # -- reading -----------------------------------------------------------

    def recv(self) -> RawFrame | None:
        """Read one frame. Returns ``None`` if the timeout expired first."""
        if self._sock is None:
            raise SnifferError("Socket is not open; use 'with RawSocketCapture()'")
        try:
            data, addr = self._sock.recvfrom(self.buffer_size)
        except TimeoutError:  # socket.timeout is an alias since Python 3.10
            return None
        # addr = (ifname, proto, pkttype, hatype, hwaddr), see packet(7)
        ifname, _proto, pkttype, _hatype, _hwaddr = addr
        # time.time() is taken in user space, *after* the kernel queued the
        # frame, so it lags by the scheduling delay. Kernel timestamps
        # (SO_TIMESTAMPNS + recvmsg) are more accurate; noted for later.
        return RawFrame(
            data=data, timestamp=time.time(), interface=ifname, pkttype=pkttype
        )

    def frames(self, count: int | None = None) -> Iterator[RawFrame]:
        """Yield frames forever, or until ``count`` frames have been read.

        A generator keeps memory flat: one frame at a time, pulled on demand,
        instead of building a list that grows without limit.
        """
        seen = 0
        while count is None or seen < count:
            frame = self.recv()
            if frame is None:
                continue  # timeout tick: a hook for shutdown checks later
            seen += 1
            yield frame
