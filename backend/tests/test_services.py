from __future__ import annotations

import uuid

import pyotp
import pytest
from sqlalchemy import select

from app.models.entities import KnownDevice
from app.services import devices, mfa, rate_limit, storage

pytestmark = pytest.mark.asyncio


async def test_the_same_browser_and_network_is_one_device():
    first = devices.fingerprint("Firefox/140", "10.0.0.7")
    second = devices.fingerprint("Firefox/140", "10.0.0.7")

    assert first == second


async def test_a_new_lease_in_the_same_range_is_the_same_device():
    office = devices.fingerprint("Firefox/140", "10.0.0.7")
    same_office = devices.fingerprint("Firefox/140", "10.0.0.204")

    assert office == same_office


async def test_a_different_network_is_a_different_device():
    office = devices.fingerprint("Firefox/140", "10.0.0.7")
    elsewhere = devices.fingerprint("Firefox/140", "203.0.113.9")

    assert office != elsewhere


async def test_a_different_browser_is_a_different_device():
    firefox = devices.fingerprint("Firefox/140", "10.0.0.7")
    chrome = devices.fingerprint("Chrome/141", "10.0.0.7")

    assert firefox != chrome


async def test_an_ipv6_prefix_is_kept():
    first = devices.fingerprint("Firefox/140", "2001:db8:1:2:aaaa:bbbb:cccc:dddd")
    same_prefix = devices.fingerprint("Firefox/140", "2001:db8:1:2:1111:2222:3333:4444")
    other_prefix = devices.fingerprint("Firefox/140", "2001:db8:9:9:aaaa:bbbb:cccc:dddd")

    assert first == same_prefix
    assert first != other_prefix


async def test_a_missing_address_still_fingerprints():
    assert devices.fingerprint("Firefox/140", None)
    assert devices.fingerprint(None, None)


async def test_the_fingerprint_does_not_contain_the_address():
    digest = devices.fingerprint("Firefox/140", "203.0.113.9")

    assert "203.0.113" not in digest
    assert "Firefox" not in digest


async def test_an_unseen_device_is_not_known(session, officer):
    assert await devices.is_known(session, officer, "Firefox/140", "10.0.0.7") is False


async def test_a_remembered_device_is_known(session, officer):
    await devices.remember(session, officer, "Firefox/140", "10.0.0.7")

    assert await devices.is_known(session, officer, "Firefox/140", "10.0.0.7") is True


async def test_remembering_twice_does_not_duplicate(session, officer):
    await devices.remember(session, officer, "Firefox/140", "10.0.0.7")
    await devices.remember(session, officer, "Firefox/140", "10.0.0.7")

    rows = (
        await session.execute(
            select(KnownDevice).where(KnownDevice.user_id == officer.id)
        )
    ).scalars().all()
    assert len(rows) == 1


async def test_revisiting_updates_the_last_seen_time(session, officer):
    await devices.remember(session, officer, "Firefox/140", "10.0.0.7")
    row = await session.scalar(
        select(KnownDevice).where(KnownDevice.user_id == officer.id)
    )
    first_seen = row.first_seen_at
    original = row.last_seen_at

    await devices.remember(session, officer, "Firefox/140", "10.0.0.7")
    await session.refresh(row)

    assert row.first_seen_at == first_seen
    assert row.last_seen_at >= original


async def test_one_officers_device_is_not_anothers(session, officer, admin):
    await devices.remember(session, officer, "Firefox/140", "10.0.0.7")

    assert await devices.is_known(session, admin, "Firefox/140", "10.0.0.7") is False


async def test_a_very_long_user_agent_is_truncated(session, officer):
    await devices.remember(session, officer, "U" * 900, "10.0.0.7")

    row = await session.scalar(
        select(KnownDevice).where(KnownDevice.user_id == officer.id)
    )
    assert len(row.user_agent) <= 512


@pytest.mark.parametrize("attempts", [0, 1, 2, 3])
async def test_the_first_few_failures_are_not_delayed(attempts):
    assert rate_limit.backoff_seconds(attempts) == 0


async def test_the_delay_grows_with_each_further_failure():
    delays = [rate_limit.backoff_seconds(n) for n in range(4, 10)]

    assert delays == sorted(delays)
    assert delays[0] == 2
    assert delays[1] == 4
    assert delays[2] == 8


async def test_the_delay_is_capped():
    assert rate_limit.backoff_seconds(1000) == rate_limit.MAX_BACKOFF_SECONDS


async def test_the_lockout_threshold_is_above_the_free_attempts():
    assert rate_limit.MAX_ATTEMPTS > rate_limit.FREE_ATTEMPTS


async def test_the_backoff_never_exceeds_the_lockout():
    for attempts in range(1, 50):
        assert rate_limit.backoff_seconds(attempts) <= rate_limit.LOCKOUT_SECONDS


async def test_a_generated_secret_is_usable():
    secret = mfa.generate_secret()

    assert mfa.verify_code(secret, pyotp.TOTP(secret).now())


async def test_two_secrets_differ():
    assert mfa.generate_secret() != mfa.generate_secret()


async def test_a_wrong_code_is_refused():
    secret = mfa.generate_secret()

    assert mfa.verify_code(secret, "000000") is False


async def test_another_secrets_code_is_refused():
    mine = mfa.generate_secret()
    theirs = mfa.generate_secret()

    assert mfa.verify_code(mine, pyotp.TOTP(theirs).now()) is False


async def test_the_provisioning_uri_names_the_issuer_and_badge():
    uri = mfa.provisioning_uri("BADGE-9911", mfa.generate_secret())

    assert uri.startswith("otpauth://totp/")
    assert "BADGE-9911" in uri
    assert "NyayVault" in uri


async def test_an_object_key_is_scoped_to_its_case_and_document():
    case_id, document_id = uuid.uuid4(), uuid.uuid4()

    key = storage.build_object_key(case_id, document_id, "evidence.pdf")

    assert key == f"cases/{case_id}/documents/{document_id}/evidence.pdf"


async def test_two_documents_never_share_an_object_key():
    case_id = uuid.uuid4()

    first = storage.build_object_key(case_id, uuid.uuid4(), "same-name.pdf")
    second = storage.build_object_key(case_id, uuid.uuid4(), "same-name.pdf")

    assert first != second


async def test_the_same_filename_in_two_cases_does_not_collide():
    document_id = uuid.uuid4()

    first = storage.build_object_key(uuid.uuid4(), document_id, "report.pdf")
    second = storage.build_object_key(uuid.uuid4(), document_id, "report.pdf")

    assert first != second
