"""Tests for the capture layer's error handling, with the OS calls mocked out."""

from __future__ import annotations

import errno
import socket
from unittest import mock

import pytest

from sniffer.capture import ETH_P_ALL, PacketType, RawFrame, RawSocketCapture
from sniffer.exceptions import (
    InsufficientPrivilegesError,
    InterfaceError,
    SnifferError,
    UnsupportedPlatformError,
)
from sniffer.utils.hexdump import hexdump


def test_permission_error_becomes_friendly_error() -> None:
    with (
        mock.patch(
            "sniffer.capture.socket.socket",
            side_effect=PermissionError(errno.EPERM, "nope"),
        ),
        pytest.raises(InsufficientPrivilegesError) as info,
    ):
        RawSocketCapture().open()
    assert isinstance(info.value.__cause__, PermissionError)  # chain kept


def test_non_linux_is_rejected() -> None:
    with (
        mock.patch("sniffer.capture.sys.platform", "darwin"),
        pytest.raises(UnsupportedPlatformError),
    ):
        RawSocketCapture().open()


def test_promiscuous_requires_interface() -> None:
    with pytest.raises(InterfaceError):
        RawSocketCapture(promiscuous=True)


def test_bad_interface_closes_socket() -> None:
    fake = mock.MagicMock()
    fake.bind.side_effect = OSError(errno.ENODEV, "No such device")
    with (
        mock.patch("sniffer.capture.socket.socket", return_value=fake),
        pytest.raises(InterfaceError),
    ):
        RawSocketCapture(interface="nope0").open()
    fake.close.assert_called_once()  # no leaked file descriptor


def test_bind_passes_protocol_in_host_order() -> None:
    # Regression test: CPython's bind() applies htons() itself, so we must
    # NOT. A double swap makes the bound socket silently receive nothing.
    fake = mock.MagicMock()
    with mock.patch("sniffer.capture.socket.socket", return_value=fake):
        RawSocketCapture(interface="eth0").open()
    fake.bind.assert_called_once_with(("eth0", ETH_P_ALL))


def test_recv_before_open_raises() -> None:
    with pytest.raises(SnifferError):
        RawSocketCapture().recv()


def test_recv_timeout_returns_none() -> None:
    cap = RawSocketCapture()
    cap._sock = mock.MagicMock()
    cap._sock.recvfrom.side_effect = socket.timeout
    assert cap.recv() is None


def test_recv_unpacks_kernel_metadata() -> None:
    cap = RawSocketCapture()
    cap._sock = mock.MagicMock()
    cap._sock.recvfrom.return_value = (b"abc", ("eth0", 0x0800, 4, 1, b"\x00" * 6))
    frame = cap.recv()
    assert frame is not None
    assert frame.interface == "eth0"
    assert frame.direction == PacketType.OUTGOING.name


def test_unknown_pkttype_name() -> None:
    assert RawFrame(b"", 0.0, "lo", 42).direction == "UNKNOWN(42)"


def test_hexdump_layout() -> None:
    out = hexdump(bytes(range(0x41, 0x41 + 18)))
    lines = out.splitlines()
    assert lines[0].startswith("0000  41 42 43 44 45 46 47 48  49 4a")
    assert lines[0].endswith("|ABCDEFGHIJKLMNOP|")
    assert lines[1].startswith("0010  51 52")
    assert lines[1].endswith("|QR|")
    # The ASCII column starts at the same position on every line.
    assert lines[0].index("|") == lines[1].index("|")


def test_hexdump_truncates() -> None:
    assert hexdump(b"\x00" * 40, max_bytes=16).endswith("(24 more bytes)")
