from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.models.entities import EncryptionKey, EncryptionKeyPurpose
from app.services import encryption, key_management

pytestmark = pytest.mark.asyncio


async def test_text_round_trips(session):
    ciphertext = await encryption.encrypt_text(session, "Badge 4471, DOB 1990-02-11")

    assert await encryption.decrypt_text(session, ciphertext) == "Badge 4471, DOB 1990-02-11"


async def test_the_ciphertext_does_not_contain_the_plaintext(session):
    ciphertext = await encryption.encrypt_text(session, "sensitive-value")

    assert "sensitive-value" not in ciphertext


async def test_the_ciphertext_carries_its_key_version(session):
    ciphertext = await encryption.encrypt_text(session, "value")

    version, _, token = ciphertext.partition(":")
    assert version.isdigit()
    assert token


async def test_encrypting_twice_gives_different_ciphertext(session):
    first = await encryption.encrypt_text(session, "value")
    second = await encryption.encrypt_text(session, "value")

    assert first != second
    assert await encryption.decrypt_text(session, first) == "value"
    assert await encryption.decrypt_text(session, second) == "value"


@pytest.mark.parametrize("empty", [None, ""])
async def test_empty_values_pass_through_untouched(session, empty):
    assert await encryption.encrypt_text(session, empty) == empty
    assert await encryption.decrypt_text(session, empty) == empty


async def test_an_unversioned_value_is_returned_as_is(session):
    assert await encryption.decrypt_text(session, "plain-legacy-value") == "plain-legacy-value"


async def test_an_undecryptable_value_does_not_raise(session):
    await encryption.encrypt_text(session, "seed")

    assert await encryption.decrypt_text(session, "1:not-a-real-token") == "1:not-a-real-token"


async def test_bytes_round_trip(session):
    blob = await encryption.encrypt_bytes(session, b"\x00\x01evidence\xff")

    assert await encryption.decrypt_bytes(session, blob) == b"\x00\x01evidence\xff"


async def test_encrypted_bytes_do_not_contain_the_original(session):
    blob = await encryption.encrypt_bytes(session, b"secret-evidence")

    assert b"secret-evidence" not in blob


async def test_unversioned_bytes_pass_through(session):
    assert await encryption.decrypt_bytes(session, b"raw-legacy-bytes") == b"raw-legacy-bytes"


async def test_pii_and_object_storage_use_different_keys(session):
    _, pii_key = await key_management.get_active_key(
        session, EncryptionKeyPurpose.PII_DATA
    )
    _, object_key = await key_management.get_active_key(
        session, EncryptionKeyPurpose.OBJECT_STORAGE
    )

    assert pii_key != object_key


async def test_a_key_is_minted_on_first_use(session):
    version, raw = await key_management.get_active_key(
        session, EncryptionKeyPurpose.PII_DATA
    )

    assert version == 1
    assert Fernet(raw)


async def test_the_same_key_is_returned_on_later_calls(session):
    first = await key_management.get_active_key(session, EncryptionKeyPurpose.PII_DATA)
    second = await key_management.get_active_key(session, EncryptionKeyPurpose.PII_DATA)

    assert first == second


async def test_stored_keys_are_wrapped_not_plain(session):
    _, raw = await key_management.get_active_key(session, EncryptionKeyPurpose.PII_DATA)

    row = await session.scalar(
        select(EncryptionKey).where(
            EncryptionKey.purpose == EncryptionKeyPurpose.PII_DATA
        )
    )
    assert row.wrapped_key != raw.decode("utf-8")


async def test_rotation_advances_the_version(session):
    await key_management.get_active_key(session, EncryptionKeyPurpose.PII_DATA)

    assert await key_management.rotate_key(session, EncryptionKeyPurpose.PII_DATA) == 2
    assert await key_management.rotate_key(session, EncryptionKeyPurpose.PII_DATA) == 3


async def test_rotation_produces_a_different_key(session):
    _, before = await key_management.get_active_key(
        session, EncryptionKeyPurpose.PII_DATA
    )
    await key_management.rotate_key(session, EncryptionKeyPurpose.PII_DATA)
    _, after = await key_management.get_active_key(session, EncryptionKeyPurpose.PII_DATA)

    assert before != after


async def test_the_old_key_is_retired_not_deleted(session):
    await key_management.get_active_key(session, EncryptionKeyPurpose.PII_DATA)
    await key_management.rotate_key(session, EncryptionKeyPurpose.PII_DATA)

    rows = (
        await session.execute(
            select(EncryptionKey).where(
                EncryptionKey.purpose == EncryptionKeyPurpose.PII_DATA
            )
        )
    ).scalars().all()

    assert len(rows) == 2
    assert sum(1 for row in rows if row.is_active) == 1


async def test_data_encrypted_before_a_rotation_still_decrypts(session):
    ciphertext = await encryption.encrypt_text(session, "written before rotation")
    await key_management.rotate_key(session, EncryptionKeyPurpose.PII_DATA)

    assert await encryption.decrypt_text(session, ciphertext) == "written before rotation"


async def test_a_specific_version_can_be_fetched(session):
    _, first = await key_management.get_active_key(session, EncryptionKeyPurpose.PII_DATA)
    await key_management.rotate_key(session, EncryptionKeyPurpose.PII_DATA)

    assert await key_management.get_key_version(
        session, EncryptionKeyPurpose.PII_DATA, 1
    ) == first


async def test_fetching_a_missing_version_raises(session):
    with pytest.raises(ValueError, match="No .* key at version"):
        await key_management.get_key_version(
            session, EncryptionKeyPurpose.PII_DATA, 99
        )


async def test_a_pem_key_is_a_private_key(session):
    _, pem = await key_management.get_or_create_pem_key(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING
    )

    assert b"PRIVATE KEY" in pem


async def test_the_same_pem_key_is_returned_on_later_calls(session):
    first = await key_management.get_or_create_pem_key(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING
    )
    second = await key_management.get_or_create_pem_key(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING
    )

    assert first == second


async def test_rotating_a_pem_key_advances_the_version(session):
    await key_management.get_or_create_pem_key(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING
    )

    assert await key_management.rotate_pem_key(
        session, EncryptionKeyPurpose.CHECKPOINT_SIGNING
    ) == 2
