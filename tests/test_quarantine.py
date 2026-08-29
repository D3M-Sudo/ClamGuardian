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
    with pytest.raises(Exception):
        attacker_vault.restore(entry.item_id, tmp_path / "leaked.txt")
    assert not (tmp_path / "leaked.txt").exists()


def test_rejects_non_aes256_key(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        QuarantineVault(tmp_path / "vault", b"short")
