from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pyotp
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from app.api import deps
from app.database import get_db
from app.models.entities import Role
from app.services import encryption, sessions

pytestmark = pytest.mark.asyncio


def _build_app(session):
    app = FastAPI()

    @app.get("/me")
    async def me(user=Depends(deps.get_current_user)):
        return {"user_id": str(user.id), "role": user.role.value}

    @app.get("/enrolling")
    async def enrolling(user=Depends(deps.get_enrolling_user)):
        return {"user_id": str(user.id)}

    @app.get("/admin-only")
    async def admin_only(user=Depends(deps.require_roles(Role.ADMIN))):
        return {"user_id": str(user.id)}

    @app.get("/officers-only")
    async def officers_only(
        user=Depends(deps.require_roles(Role.INVESTIGATING_OFFICER, Role.FORENSICS_OFFICER)),
    ):
        return {"user_id": str(user.id)}

    @app.post("/sign")
    async def sign(user=Depends(deps.require_fresh_mfa)):
        return {"user_id": str(user.id)}

    app.dependency_overrides[get_db] = lambda: session
    return app


@pytest_asyncio.fixture
async def client(session):
    transport = ASGITransport(app=_build_app(session))
    async with AsyncClient(transport=transport, base_url="http://rbac.test") as client:
        yield client


async def _token(session, user, mfa_pending: bool = False) -> str:
    access, _, _ = await sessions.issue_session(
        session, user, "10.0.0.1", "pytest-agent", mfa_pending=mfa_pending
    )
    return access


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _enrol_mfa(session, user) -> str:
    secret = pyotp.random_base32()
    user.totp_secret_encrypted = await encryption.encrypt_text(session, secret)
    user.mfa_enabled = True
    await session.flush()
    return secret


async def test_a_valid_session_is_accepted(client, session, officer):
    response = await client.get("/me", headers=_auth(await _token(session, officer)))
    assert response.status_code == 200
    assert response.json()["user_id"] == str(officer.id)


async def test_a_missing_token_is_rejected(client):
    assert (await client.get("/me")).status_code == 401


@pytest.mark.parametrize("token", ["", "garbage", "a" * 64, "../../etc/passwd"])
async def test_a_bad_token_is_rejected(client, token):
    assert (await client.get("/me", headers=_auth(token))).status_code == 401


async def test_a_malformed_authorization_header_is_rejected(client, session, officer):
    token = await _token(session, officer)
    assert (await client.get("/me", headers={"Authorization": token})).status_code == 401
    assert (
        await client.get("/me", headers={"Authorization": f"Basic {token}"})
    ).status_code == 401


async def test_an_expired_session_is_rejected(client, session, officer):
    access, _, record = await sessions.issue_session(
        session, officer, None, None
    )
    record.access_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await session.flush()

    assert (await client.get("/me", headers=_auth(access))).status_code == 401


async def test_a_revoked_session_is_rejected(client, session, officer):
    token = await _token(session, officer)
    await sessions.revoke_session(session, token)

    assert (await client.get("/me", headers=_auth(token))).status_code == 401


async def test_a_deactivated_user_loses_access_mid_session(client, session, officer):
    token = await _token(session, officer)
    assert (await client.get("/me", headers=_auth(token))).status_code == 200

    officer.is_active = False
    await session.flush()

    assert (await client.get("/me", headers=_auth(token))).status_code == 401


async def test_an_mfa_pending_session_cannot_reach_the_application(
    client, session, officer
):
    token = await _token(session, officer, mfa_pending=True)
    response = await client.get("/me", headers=_auth(token))

    assert response.status_code == 403
    assert "MFA enrollment is required" in response.json()["detail"]


async def test_an_mfa_pending_session_can_still_enrol(client, session, officer):
    token = await _token(session, officer, mfa_pending=True)
    response = await client.get("/enrolling", headers=_auth(token))

    assert response.status_code == 200
    assert response.json()["user_id"] == str(officer.id)


async def test_enrolment_is_still_closed_to_a_deactivated_user(client, session, officer):
    token = await _token(session, officer, mfa_pending=True)
    officer.is_active = False
    await session.flush()

    assert (await client.get("/enrolling", headers=_auth(token))).status_code == 401


async def test_an_admin_reaches_an_admin_endpoint(client, session, admin):
    response = await client.get("/admin-only", headers=_auth(await _token(session, admin)))
    assert response.status_code == 200


async def test_an_officer_cannot_reach_an_admin_endpoint(client, session, officer):
    response = await client.get(
        "/admin-only", headers=_auth(await _token(session, officer))
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "You do not have permission to perform this action"


async def test_an_admin_cannot_reach_an_officer_only_endpoint(client, session, admin):
    response = await client.get(
        "/officers-only", headers=_auth(await _token(session, admin))
    )
    assert response.status_code == 403


async def test_a_guard_accepts_any_of_its_listed_roles(client, session, officer):
    response = await client.get(
        "/officers-only", headers=_auth(await _token(session, officer))
    )
    assert response.status_code == 200


async def test_an_unauthenticated_caller_gets_401_not_403(client):
    assert (await client.get("/admin-only")).status_code == 401


async def test_a_demotion_applies_to_an_open_session(client, session, admin):
    token = await _token(session, admin)
    assert (await client.get("/admin-only", headers=_auth(token))).status_code == 200

    admin.role = Role.COURT_OFFICIAL
    await session.flush()

    assert (await client.get("/admin-only", headers=_auth(token))).status_code == 403


async def test_a_promotion_applies_to_an_open_session(client, session, officer):
    token = await _token(session, officer)
    assert (await client.get("/admin-only", headers=_auth(token))).status_code == 403

    officer.role = Role.ADMIN
    await session.flush()

    assert (await client.get("/admin-only", headers=_auth(token))).status_code == 200


async def test_step_up_is_closed_to_a_user_who_never_enrolled(client, session, officer):
    response = await client.post("/sign", headers=_auth(await _token(session, officer)))

    assert response.status_code == 403
    assert "requires multi-factor authentication" in response.json()["detail"]


async def test_step_up_needs_a_code_even_when_enrolled(client, session, officer):
    await _enrol_mfa(session, officer)
    response = await client.post("/sign", headers=_auth(await _token(session, officer)))

    assert response.status_code == 401
    assert "X-MFA-Code" in response.json()["detail"]


async def test_step_up_accepts_a_current_code(client, session, officer):
    secret = await _enrol_mfa(session, officer)
    headers = _auth(await _token(session, officer))
    headers["X-MFA-Code"] = pyotp.TOTP(secret).now()

    response = await client.post("/sign", headers=headers)
    assert response.status_code == 200, response.text


async def test_step_up_rejects_a_wrong_code(client, session, officer):
    await _enrol_mfa(session, officer)
    headers = _auth(await _token(session, officer))
    headers["X-MFA-Code"] = "000000"

    response = await client.post("/sign", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid MFA code"


async def test_step_up_rejects_another_users_code(client, session, officer, admin):
    await _enrol_mfa(session, officer)
    other_secret = await _enrol_mfa(session, admin)

    headers = _auth(await _token(session, officer))
    headers["X-MFA-Code"] = pyotp.TOTP(other_secret).now()

    assert (await client.post("/sign", headers=headers)).status_code == 401


async def test_a_code_cannot_be_replayed_inside_its_window(client, session, officer):
    secret = await _enrol_mfa(session, officer)
    token = await _token(session, officer)
    code = pyotp.TOTP(secret).now()

    first = await client.post("/sign", headers={**_auth(token), "X-MFA-Code": code})
    assert first.status_code == 200

    second = await client.post("/sign", headers={**_auth(token), "X-MFA-Code": code})
    assert second.status_code == 401
    assert "already been used" in second.json()["detail"]


async def test_step_up_still_requires_a_live_session(client, session, officer):
    secret = await _enrol_mfa(session, officer)
    token = await _token(session, officer)
    await sessions.revoke_session(session, token)

    headers = {**_auth(token), "X-MFA-Code": pyotp.TOTP(secret).now()}
    assert (await client.post("/sign", headers=headers)).status_code == 401
