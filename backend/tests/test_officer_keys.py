from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from app.models.entities import SigningKeyStatus
from app.services import officer_keys

pytestmark = pytest.mark.asyncio

_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _keypair(bits: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, pem


def _sign(private_key, message: str) -> str:
    return base64.b64encode(
        private_key.sign(message.encode("utf-8"), _PADDING, hashes.SHA256())
    ).decode("utf-8")


async def test_registering_a_key_makes_it_active(session, officer):
    _, pem = _keypair()
    key = await officer_keys.register_key(session, officer, pem)

    assert key.status == SigningKeyStatus.ACTIVE
    assert key.fingerprint == officer_keys.fingerprint(pem)
    assert officer.public_key_pem == pem.strip()


async def test_active_key_is_retrievable(session, officer):
    _, pem = _keypair()
    registered = await officer_keys.register_key(session, officer, pem)

    active = await officer_keys.get_active_key(session, officer.id)
    assert active is not None
    assert active.id == registered.id


@pytest.mark.parametrize(
    "garbage",
    ["", "not a key", "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"],
)
async def test_malformed_pem_is_rejected(session, officer, garbage):
    with pytest.raises(officer_keys.InvalidPublicKey):
        await officer_keys.register_key(session, officer, garbage)


async def test_a_weak_key_is_rejected(session, officer):
    _, pem = _keypair(bits=1024)
    with pytest.raises(officer_keys.InvalidPublicKey):
        await officer_keys.register_key(session, officer, pem)


async def test_a_non_rsa_key_is_rejected(session, officer):
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    with pytest.raises(officer_keys.InvalidPublicKey):
        await officer_keys.register_key(session, officer, pem)


async def test_the_same_key_cannot_be_registered_twice(session, officer):
    _, pem = _keypair()
    await officer_keys.register_key(session, officer, pem)

    with pytest.raises(officer_keys.InvalidPublicKey):
        await officer_keys.register_key(session, officer, pem)


async def test_another_officer_cannot_claim_a_registered_key(session, officer, admin):
    _, pem = _keypair()
    await officer_keys.register_key(session, officer, pem)

    with pytest.raises(officer_keys.InvalidPublicKey):
        await officer_keys.register_key(session, admin, pem)


async def test_rotation_retires_the_previous_key(session, officer):
    _, first_pem = _keypair()
    _, second_pem = _keypair()

    first = await officer_keys.register_key(session, officer, first_pem)
    second = await officer_keys.register_key(session, officer, second_pem)

    assert first.status == SigningKeyStatus.RETIRED
    assert first.retired_at is not None
    assert second.status == SigningKeyStatus.ACTIVE
    assert officer.public_key_pem == second_pem.strip()


async def test_a_retired_key_is_kept_for_historical_verification(session, officer):
    _, first_pem = _keypair()
    _, second_pem = _keypair()
    await officer_keys.register_key(session, officer, first_pem)
    await officer_keys.register_key(session, officer, second_pem)

    listed = await officer_keys.list_keys(session, officer.id)
    assert len(listed) == 2
    assert {key.status for key in listed} == {
        SigningKeyStatus.ACTIVE,
        SigningKeyStatus.RETIRED,
    }


async def test_revoking_clears_the_key_from_the_user(session, officer, admin):
    _, pem = _keypair()
    key = await officer_keys.register_key(session, officer, pem)

    await officer_keys.revoke_key(session, key, admin)

    assert key.status == SigningKeyStatus.REVOKED
    assert key.revoked_by_id == admin.id
    assert key.revoked_at is not None
    assert officer.public_key_pem is None


async def test_revoking_leaves_no_active_key(session, officer, admin):
    _, pem = _keypair()
    key = await officer_keys.register_key(session, officer, pem)
    await officer_keys.revoke_key(session, key, admin)

    assert await officer_keys.get_active_key(session, officer.id) is None


async def test_a_valid_signature_verifies():
    private_key, pem = _keypair()
    message = "document-digest-abc123"
    assert officer_keys.verify_signature(pem, message, _sign(private_key, message))


async def test_a_signature_over_a_different_message_fails():
    private_key, pem = _keypair()
    signature = _sign(private_key, "document-digest-abc123")
    assert not officer_keys.verify_signature(pem, "document-digest-def456", signature)


async def test_a_signature_from_another_key_fails():
    _, pem = _keypair()
    attacker_key, _ = _keypair()
    message = "document-digest-abc123"
    assert not officer_keys.verify_signature(pem, message, _sign(attacker_key, message))


@pytest.mark.parametrize("signature", ["", "not-base64!!", "AAAA"])
async def test_a_malformed_signature_is_rejected_not_crashed(signature):
    _, pem = _keypair()
    assert officer_keys.verify_signature(pem, "anything", signature) is False


async def test_fingerprint_ignores_surrounding_whitespace():
    _, pem = _keypair()
    assert officer_keys.fingerprint(pem) == officer_keys.fingerprint(f"\n  {pem}  \n")


async def test_distinct_keys_have_distinct_fingerprints():
    _, first = _keypair()
    _, second = _keypair()
    assert officer_keys.fingerprint(first) != officer_keys.fingerprint(second)


async def test_signatures_predating_a_revocation_stay_valid(session, officer, admin):
    _, pem = _keypair()
    key = await officer_keys.register_key(session, officer, pem)
    await officer_keys.revoke_key(session, key, admin)

    signed_at = key.revoked_at - timedelta(hours=1)
    assert officer_keys.signature_status(key, signed_at) == "valid"


async def test_signatures_after_a_revocation_need_review(session, officer, admin):
    _, pem = _keypair()
    key = await officer_keys.register_key(session, officer, pem)
    await officer_keys.revoke_key(session, key, admin)

    signed_at = key.revoked_at + timedelta(hours=1)
    assert officer_keys.signature_status(key, signed_at) == "pending_review"


async def test_signatures_from_a_live_key_are_valid(session, officer):
    _, pem = _keypair()
    key = await officer_keys.register_key(session, officer, pem)
    assert officer_keys.signature_status(key, datetime.now(timezone.utc)) == "valid"


async def test_naive_timestamps_are_treated_as_utc(session, officer, admin):
    _, pem = _keypair()
    key = await officer_keys.register_key(session, officer, pem)
    await officer_keys.revoke_key(session, key, admin)

    naive = (key.revoked_at - timedelta(hours=1)).replace(tzinfo=None)
    assert officer_keys.signature_status(key, naive) == "valid"
