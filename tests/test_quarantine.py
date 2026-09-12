"""Security-focused quarantine vault tests."""

from pathlib import Path

import pytest

from clamguardian.core.quarantine import QuarantineVault


def test_round_trip_and_metadata(tmp_path: Path) -> None:
    source = tmp_path / "suspicious.bin"
    source.write_bytes(b"secret payload")
    vault = QuarantineVault(tmp_path / "vault", QuarantineVault.generate_key())

    entry = vault.quarantine(source)
    assert not source.exists()
    assert entry.original_name == "suspicious.bin"
    assert len(vault.list_entries()) == 1

    restored = tmp_path / "restored.bin"
    assert vault.restore(entry.item_id, restored) == restored
    assert restored.read_bytes() == b"secret payload"
    assert vault.list_entries() == []


def test_wrong_key_cannot_decrypt(tmp_path: Path) -> None:
    source = tmp_path / "secret.txt"
    source.write_text("do not expose")
    key = QuarantineVault.generate_key()
    vault = QuarantineVault(tmp_path / "vault", key)
    entry = vault.quarantine(source)

    attacker_vault = QuarantineVault(tmp_path / "vault", QuarantineVault.generate_key())
    with pytest.raises(Exception):  # noqa: B017 - InvalidTag has no stable alias here
        attacker_vault.restore(entry.item_id, tmp_path / "leaked.txt")
    assert not (tmp_path / "leaked.txt").exists()


def test_rejects_non_aes256_key(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        QuarantineVault(tmp_path / "vault", b"short")


# ---------------------------------------------------------------------------
# Phase 3 Security Gap Closure: Quarantine
# ---------------------------------------------------------------------------


def test_corrupted_ciphertext_raises_error(tmp_path: Path) -> None:
    source = tmp_path / "file.txt"
    source.write_bytes(b"sensitive content")
    key = QuarantineVault.generate_key()
    vault = QuarantineVault(tmp_path / "vault", key)
    entry = vault.quarantine(source)

    vault_file = tmp_path / "vault" / f"{entry.item_id}.qtn"
    raw = bytearray(vault_file.read_bytes())
    raw[-1] ^= 0xFF  # corrupt last byte of ciphertext/tag
    vault_file.write_bytes(raw)

    from cryptography.exceptions import InvalidTag

    with pytest.raises((InvalidTag, ValueError)):
        vault.restore(entry.item_id, tmp_path / "restored.txt")


def test_corrupted_metadata_aad_raises_error(tmp_path: Path) -> None:
    source = tmp_path / "file.txt"
    source.write_bytes(b"sensitive content")
    key = QuarantineVault.generate_key()
    vault = QuarantineVault(tmp_path / "vault", key)
    entry = vault.quarantine(source)

    vault_file = tmp_path / "vault" / f"{entry.item_id}.qtn"
    raw = bytearray(vault_file.read_bytes())
    # Magic header is 16 bytes, aad_len is 4 bytes -> tamper in AAD block
    raw[22] ^= 0xFF
    vault_file.write_bytes(raw)

    with pytest.raises(ValueError, match="Invalid quarantine"):
        vault.restore(entry.item_id, tmp_path / "restored.txt")


def test_invalid_item_id_validation(tmp_path: Path) -> None:
    key = QuarantineVault.generate_key()
    vault = QuarantineVault(tmp_path / "vault", key)

    for bad_id in ("../traversal", "invalid/id", "../../etc/passwd", "not-hex!", ""):
        with pytest.raises(ValueError, match="Invalid quarantine item id"):
            vault.restore(bad_id, tmp_path / "target.txt")
        with pytest.raises(ValueError, match="Invalid quarantine item id"):
            vault.delete(bad_id)


def test_nonexistent_item_id(tmp_path: Path) -> None:
    key = QuarantineVault.generate_key()
    vault = QuarantineVault(tmp_path / "vault", key)
    valid_fake_id = "0123456789abcdef0123456789abcdef"

    with pytest.raises(FileNotFoundError):
        vault.restore(valid_fake_id, tmp_path / "target.txt")

    with pytest.raises(FileNotFoundError):
        vault.delete(valid_fake_id)


def test_large_file_quarantine_behavior(tmp_path: Path) -> None:
    source = tmp_path / "large.bin"
    chunk = b"A" * 1024 * 1024  # 1 MiB chunk
    source.write_bytes(chunk * 3)  # 3 MiB payload

    key = QuarantineVault.generate_key()
    vault = QuarantineVault(tmp_path / "vault", key)

    entry = vault.quarantine(source)
    assert not source.exists()
    assert entry.size == 3 * 1024 * 1024

    restored = tmp_path / "restored_large.bin"
    vault.restore(entry.item_id, restored)
    assert restored.stat().st_size == 3 * 1024 * 1024


def test_toctou_source_disappears_during_quarantine(tmp_path: Path) -> None:
    source = tmp_path / "missing_source.txt"
    key = QuarantineVault.generate_key()
    vault = QuarantineVault(tmp_path / "vault", key)

    with pytest.raises(FileNotFoundError):
        vault.quarantine(source)
