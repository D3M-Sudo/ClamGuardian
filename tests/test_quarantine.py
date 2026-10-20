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


# ---------------------------------------------------------------------------
# M5 (WP-2.3): chunked streaming, size limit, structural integrity, legacy read
# ---------------------------------------------------------------------------


def _pattern(size: int) -> bytes:
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def _data_offset(record: bytes) -> int:
    aad_len = int.from_bytes(record[16:20], "big")
    return 20 + aad_len + 8 + 12


def test_chunked_round_trip_preserves_content(tmp_path: Path) -> None:
    """A payload spanning many chunks round-trips byte for byte."""
    payload = _pattern(2 * 1024 * 1024 + 12345)
    source = tmp_path / "multi.bin"
    source.write_bytes(payload)
    vault = QuarantineVault(
        tmp_path / "vault", QuarantineVault.generate_key(), chunk_size=64 * 1024
    )

    entry = vault.quarantine(source)
    record = (tmp_path / "vault" / f"{entry.item_id}.qtn").read_bytes()
    assert len(record) > len(payload)  # per-chunk authentication tags

    restored = tmp_path / "restored.bin"
    vault.restore(entry.item_id, restored)
    assert restored.read_bytes() == payload


def test_empty_file_round_trip(tmp_path: Path) -> None:
    """An empty file is still an authenticated record, not an empty blob."""
    source = tmp_path / "empty.bin"
    source.write_bytes(b"")
    vault = QuarantineVault(tmp_path / "vault", QuarantineVault.generate_key())

    entry = vault.quarantine(source)
    assert entry.size == 0
    restored = tmp_path / "restored_empty.bin"
    vault.restore(entry.item_id, restored)
    assert restored.read_bytes() == b""


def test_exact_multiple_of_chunk_size_round_trip(tmp_path: Path) -> None:
    """A payload that is an exact multiple of the chunk size keeps its last chunk."""
    payload = _pattern(3 * 1024)
    source = tmp_path / "exact.bin"
    source.write_bytes(payload)
    vault = QuarantineVault(tmp_path / "vault", QuarantineVault.generate_key(), chunk_size=1024)

    entry = vault.quarantine(source)
    restored = tmp_path / "restored_exact.bin"
    vault.restore(entry.item_id, restored)
    assert restored.read_bytes() == payload


def test_truncated_record_is_rejected(tmp_path: Path) -> None:
    """Dropping bytes from the ciphertext must fail authentication, not truncate data."""
    from cryptography.exceptions import InvalidTag

    payload = _pattern(4096)
    source = tmp_path / "trunc.bin"
    source.write_bytes(payload)
    vault = QuarantineVault(tmp_path / "vault", QuarantineVault.generate_key(), chunk_size=1024)
    entry = vault.quarantine(source)

    record_path = tmp_path / "vault" / f"{entry.item_id}.qtn"
    raw = record_path.read_bytes()
    record_path.write_bytes(raw[:-40])

    destination = tmp_path / "should_not_exist.bin"
    with pytest.raises((InvalidTag, ValueError)):
        vault.restore(entry.item_id, destination)
    assert not destination.exists()


def test_reordered_chunks_are_rejected(tmp_path: Path) -> None:
    """Chunk order is authenticated: swapping two records must be detected."""
    from cryptography.exceptions import InvalidTag

    payload = _pattern(3 * 1024)
    source = tmp_path / "reorder.bin"
    source.write_bytes(payload)
    vault = QuarantineVault(tmp_path / "vault", QuarantineVault.generate_key(), chunk_size=1024)
    entry = vault.quarantine(source)

    record_path = tmp_path / "vault" / f"{entry.item_id}.qtn"
    raw = record_path.read_bytes()
    offset = _data_offset(raw)
    width = 1024 + 16
    first = raw[offset : offset + width]
    second = raw[offset + width : offset + 2 * width]
    tampered = raw[:offset] + second + first + raw[offset + 2 * width :]
    record_path.write_bytes(tampered)

    destination = tmp_path / "reordered.bin"
    with pytest.raises((InvalidTag, ValueError)):
        vault.restore(entry.item_id, destination)
    assert not destination.exists()


def test_size_limit_is_enforced_without_losing_the_source(tmp_path: Path) -> None:
    """A file above the vault limit is refused, and the original is left alone."""
    source = tmp_path / "too_big.bin"
    source.write_bytes(b"x" * 4096)
    vault = QuarantineVault(
        tmp_path / "vault", QuarantineVault.generate_key(), max_bytes=1024
    )

    with pytest.raises(ValueError, match="too large to quarantine"):
        vault.quarantine(source)

    assert source.exists(), "a refused file must never be deleted"
    assert vault.list_entries() == []


def test_memory_stays_bounded_for_large_payloads(tmp_path: Path) -> None:
    """Neither quarantining nor restoring may load the whole payload in memory."""
    import tracemalloc

    megabyte = b"B" * (1024 * 1024)
    size = 8 * 1024 * 1024
    source = tmp_path / "big.bin"
    with source.open("wb") as handle:
        for _ in range(size // (1024 * 1024)):
            handle.write(megabyte)

    vault = QuarantineVault(
        tmp_path / "vault", QuarantineVault.generate_key(), chunk_size=256 * 1024
    )

    tracemalloc.start()
    try:
        entry = vault.quarantine(source)
        _, quarantine_peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        restored = tmp_path / "restored_big.bin"
        vault.restore(entry.item_id, restored)
        _, restore_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert entry.size == size
    assert restored.stat().st_size == size
    limit = 2 * 1024 * 1024
    assert quarantine_peak < limit, f"quarantine peak {quarantine_peak} bytes"
    assert restore_peak < limit, f"restore peak {restore_peak} bytes"


def test_legacy_single_blob_record_is_still_restorable(tmp_path: Path) -> None:
    """Records written by the previous format stay readable after the upgrade."""
    import json
    import secrets

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = QuarantineVault.generate_key()
    vault_dir = tmp_path / "vault"
    vault = QuarantineVault(vault_dir, key)
    item_id = "0123456789abcdef0123456789abcdef"
    payload = b"legacy quarantined payload"
    metadata = {
        "item_id": item_id,
        "original_name": "legacy.bin",
        "original_path": "/tmp/legacy.bin",
        "created_at": 0.0,
        "size": len(payload),
    }
    aad = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    nonce = secrets.token_bytes(12)
    legacy = (
        b"CLAMGUARDIAN-Q1\x00"
        + len(aad).to_bytes(4, "big")
        + aad
        + nonce
        + AESGCM(key).encrypt(nonce, payload, aad)
    )
    (vault_dir / f"{item_id}.qtn").write_bytes(legacy)

    assert [entry.item_id for entry in vault.list_entries()] == [item_id]
    restored = tmp_path / "legacy_restored.bin"
    vault.restore(item_id, restored)
    assert restored.read_bytes() == payload


def test_restore_target_rejects_relative_and_traversal_paths(tmp_path: Path) -> None:
    vault = QuarantineVault(tmp_path / "vault", QuarantineVault.generate_key())
    for raw in ("relative.bin", "../escape.bin", "dir/../../escape.bin"):
        with pytest.raises(ValueError, match="unsafe original path"):
            vault._restore_target({"original_path": raw}, None)


def test_quarantine_refuses_symlink_and_keeps_target(tmp_path: Path) -> None:
    real = tmp_path / "real.bin"
    real.write_bytes(b"keep me")
    link = tmp_path / "link.bin"
    link.symlink_to(real)
    vault = QuarantineVault(tmp_path / "vault", QuarantineVault.generate_key())

    with pytest.raises(ValueError, match="symbolic link"):
        vault.quarantine(link)

    assert real.read_bytes() == b"keep me"
    assert link.is_symlink()


def test_vault_directory_symlink_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real-vault"
    real.mkdir()
    link = tmp_path / "vault-link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic link"):
        QuarantineVault(link, QuarantineVault.generate_key())

