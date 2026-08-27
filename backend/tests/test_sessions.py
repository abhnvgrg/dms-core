from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.entities import Session
from app.services import sessions

pytestmark = pytest.mark.asyncio


async def _issue(session, user, mfa_pending: bool = False):
    return await sessions.issue_session(
        session, user, "10.0.0.1", "pytest-agent", mfa_pending=mfa_pending
    )


async def test_issued_tokens_are_distinct(session, officer):
    access, refresh, _ = await _issue(session, officer)
    assert access != refresh
    assert len(access) >= 32
    assert len(refresh) >= 32


async def test_tokens_are_only_stored_as_hashes(session, officer):
    access, refresh, record = await _issue(session, officer)

    rows = (await session.execute(select(Session))).scalars().all()
    stored = " ".join(
        f"{row.access_token_hash}{row.refresh_token_hash}{row.previous_refresh_token_hash}"
        for row in rows
    )
    assert access not in stored
    assert refresh not in stored
    assert record.access_token_hash == hashlib.sha256(access.encode()).hexdigest()


async def test_a_live_session_resolves(session, officer):
    access, _, record = await _issue(session, officer)
    found = await sessions.get_live_session(session, access)
    assert found is not None
    assert found.id == record.id


async def test_an_unknown_token_resolves_to_nothing(session, officer):
    await _issue(session, officer)
    assert await sessions.get_live_session(session, "not-a-real-token") is None


async def test_an_expired_access_token_is_dead(session, officer):
    access, _, record = await _issue(session, officer)
    record.access_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await session.flush()

    assert await sessions.get_live_session(session, access) is None


async def test_a_revoked_session_is_dead(session, officer):
    access, _, _ = await _issue(session, officer)
    await sessions.revoke_session(session, access)

    assert await sessions.get_live_session(session, access) is None


async def test_revoking_all_sessions_kills_every_one(session, officer):
    first, _, _ = await _issue(session, officer)
    second, _, _ = await _issue(session, officer)

    await sessions.revoke_all_sessions(session, officer.id)

    assert await sessions.get_live_session(session, first) is None
    assert await sessions.get_live_session(session, second) is None


async def test_revoking_all_sessions_spares_other_users(session, officer, admin):
    mine, _, _ = await _issue(session, officer)
    theirs, _, _ = await _issue(session, admin)

    await sessions.revoke_all_sessions(session, officer.id)

    assert await sessions.get_live_session(session, mine) is None
    assert await sessions.get_live_session(session, theirs) is not None


async def test_rotation_issues_new_tokens_and_retires_the_old(session, officer):
    access, refresh, record = await _issue(session, officer)

    new_access, new_refresh, rotated = await sessions.rotate_session(session, refresh)

    assert rotated.id == record.id
    assert new_access != access
    assert new_refresh != refresh
    assert await sessions.get_live_session(session, access) is None
    assert await sessions.get_live_session(session, new_access) is not None


async def test_reusing_a_rotated_refresh_token_revokes_the_session(session, officer):
    _, refresh, record = await _issue(session, officer)
    new_access, _, _ = await sessions.rotate_session(session, refresh)

    with pytest.raises(sessions.RefreshRejected) as raised:
        await sessions.rotate_session(session, refresh)

    assert raised.value.reused is True
    assert raised.value.user_id == str(officer.id)
    assert record.revoked_at is not None
    assert await sessions.get_live_session(session, new_access) is None


async def test_an_unknown_refresh_token_is_rejected_without_a_reuse_flag(session, officer):
    with pytest.raises(sessions.RefreshRejected) as raised:
        await sessions.rotate_session(session, "never-issued")
    assert raised.value.reused is False


async def test_an_expired_refresh_token_cannot_rotate(session, officer):
    _, refresh, record = await _issue(session, officer)
    record.refresh_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await session.flush()

    with pytest.raises(sessions.RefreshRejected) as raised:
        await sessions.rotate_session(session, refresh)
    assert raised.value.reused is False


async def test_a_revoked_session_cannot_rotate(session, officer):
    access, refresh, _ = await _issue(session, officer)
    await sessions.revoke_session(session, access)

    with pytest.raises(sessions.RefreshRejected):
        await sessions.rotate_session(session, refresh)


async def test_rotation_twice_over_keeps_only_the_newest_token_live(session, officer):
    _, refresh, _ = await _issue(session, officer)
    _, second_refresh, _ = await sessions.rotate_session(session, refresh)
    third_access, _, _ = await sessions.rotate_session(session, second_refresh)

    assert await sessions.get_live_session(session, third_access) is not None

    with pytest.raises(sessions.RefreshRejected) as raised:
        await sessions.rotate_session(session, second_refresh)
    assert raised.value.reused is True


async def test_access_and_refresh_lifetimes_differ(session, officer):
    _, _, record = await _issue(session, officer)
    assert record.access_expires_at < record.refresh_expires_at


async def test_an_access_token_cannot_be_used_as_a_refresh_token(session, officer):
    access, _, _ = await _issue(session, officer)
    with pytest.raises(sessions.RefreshRejected):
        await sessions.rotate_session(session, access)


async def test_a_refresh_token_cannot_be_used_as_an_access_token(session, officer):
    _, refresh, _ = await _issue(session, officer)
    assert await sessions.get_live_session(session, refresh) is None


async def test_mfa_pending_is_recorded_on_the_session(session, officer):
    _, _, record = await _issue(session, officer, mfa_pending=True)
    assert record.mfa_pending is True


async def test_resolving_a_user_from_a_token(session, officer):
    access, _, _ = await _issue(session, officer)
    resolved = await sessions.resolve_user_for_access_token(session, access)
    assert resolved is not None
    assert resolved.id == officer.id


async def test_resolving_a_user_from_a_dead_token(session, officer):
    access, _, _ = await _issue(session, officer)
    await sessions.revoke_session(session, access)
    assert await sessions.resolve_user_for_access_token(session, access) is None
