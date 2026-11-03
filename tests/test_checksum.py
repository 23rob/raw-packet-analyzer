"""Tests for the RFC 1071 Internet checksum."""

from __future__ import annotations

from sniffer.utils.checksum import internet_checksum, ones_complement_sum

# The header of a real packet captured in Milestone 1 (frame #2).
REAL_HEADER = bytes.fromhex(
    "45000034e3f340004006 8c74 c0000202a04f680a".replace(" ", "")
)


def test_rfc1071_worked_example() -> None:
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert ones_complement_sum(data) == 0xDDF2
    assert internet_checksum(data) == 0x220D


def test_real_header_verifies_to_zero() -> None:
    assert internet_checksum(REAL_HEADER) == 0


def test_recomputing_with_zeroed_field_gives_stored_value() -> None:
    zeroed = REAL_HEADER[:10] + b"\x00\x00" + REAL_HEADER[12:]
    assert internet_checksum(zeroed) == 0x8C74


def test_single_bit_flip_is_detected() -> None:
    corrupted = bytearray(REAL_HEADER)
    corrupted[8] ^= 0x01  # TTL 64 -> 65
    assert internet_checksum(bytes(corrupted)) != 0


def test_odd_length_is_zero_padded() -> None:
    assert internet_checksum(b"\x12\x34\x56") == internet_checksum(b"\x12\x34\x56\x00")


def test_word_swap_is_not_detected() -> None:
    # Documents a known weakness: addition is commutative.
    assert internet_checksum(b"\x00\x01\x00\x02") == internet_checksum(
        b"\x00\x02\x00\x01"
    )


def test_double_fold() -> None:
    # 0xFFFF * 2 = 0x1FFFE -> fold -> 0xFFFF; exercises the carry loop.
    assert ones_complement_sum(b"\xff\xff\xff\xff") == 0xFFFF
