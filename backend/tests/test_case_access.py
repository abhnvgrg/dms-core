from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.api.v1.cases import _get_case_if_authorized, list_cases
from app.api.v1.documents import _enforce_classification, list_documents
from app.models.entities import (
    CaseAssignment,
    DocumentAccessGrant,
    DocumentClassification,
    Role,
)

pytestmark = pytest.mark.asyncio


async def _denied(coro) -> HTTPException:
    with pytest.raises(HTTPException) as raised:
        await coro
    return raised.value


async def test_an_assigned_officer_reaches_their_case(session, officer, make_case):
    case = await make_case(officer)
    found = await _get_case_if_authorized(case.id, officer, session)
    assert found.id == case.id


async def test_an_unassigned_officer_is_refused(session, officer, other_officer, make_case):
    case = await make_case(officer)
    error = await _denied(_get_case_if_authorized(case.id, other_officer, session))

    assert error.status_code == 403
    assert error.detail == "You are not assigned to this case"


async def test_an_admin_reaches_any_case(session, officer, admin, make_case):
    case = await make_case(officer)
    found = await _get_case_if_authorized(case.id, admin, session)
    assert found.id == case.id


async def test_a_missing_case_is_a_404(session, officer):
    error = await _denied(_get_case_if_authorized(uuid.uuid4(), officer, session))
    assert error.status_code == 404


async def test_a_court_official_needs_an_assignment_too(
    session, officer, court_official, make_case
):
    case = await make_case(officer)
    error = await _denied(_get_case_if_authorized(case.id, court_official, session))
    assert error.status_code == 403


async def test_assignment_grants_access(session, officer, other_officer, make_case):
    case = await make_case(officer)
    error = await _denied(_get_case_if_authorized(case.id, other_officer, session))
    assert error.status_code == 403

    session.add(CaseAssignment(case_id=case.id, user_id=other_officer.id))
    await session.flush()

    found = await _get_case_if_authorized(case.id, other_officer, session)
    assert found.id == case.id


async def test_assignment_to_one_case_does_not_open_another(
    session, officer, other_officer, make_case
):
    mine = await make_case(officer)
    theirs = await make_case(other_officer)

    assert (await _get_case_if_authorized(mine.id, officer, session)).id == mine.id
    error = await _denied(_get_case_if_authorized(theirs.id, officer, session))
    assert error.status_code == 403


async def test_listing_cases_shows_only_assigned_ones(
    session, officer, other_officer, make_case
):
    mine = await make_case(officer)
    await make_case(other_officer)

    listed = await list_cases(officer, session)
    assert [case.id for case in listed] == [mine.id]


async def test_listing_cases_as_admin_shows_everything(
    session, officer, other_officer, admin, make_case
):
    first = await make_case(officer)
    second = await make_case(other_officer)

    listed = await list_cases(admin, session)
    ids = {case.id for case in listed}
    assert {first.id, second.id} <= ids


async def test_listing_cases_with_no_assignments_is_empty(session, other_officer):
    assert await list_cases(other_officer, session) == []


async def test_a_shared_case_is_visible_to_both_officers(
    session, officer, other_officer, make_case
):
    case = await make_case(officer, other_officer)

    assert (await _get_case_if_authorized(case.id, officer, session)).id == case.id
    assert (await _get_case_if_authorized(case.id, other_officer, session)).id == case.id


async def test_admin_only_documents_are_hidden_as_missing(
    session, officer, make_case, make_document
):
    case = await make_case(officer)
    document = await make_document(
        case, officer, DocumentClassification.ADMIN_ONLY
    )

    error = await _denied(_enforce_classification(document, officer, session))
    assert error.status_code == 404
    assert error.detail == "Document not found"


async def test_admins_can_read_admin_only_documents(
    session, officer, admin, make_case, make_document
):
    case = await make_case(officer)
    document = await make_document(case, officer, DocumentClassification.ADMIN_ONLY)

    await _enforce_classification(document, admin, session)


async def test_an_assigned_officer_reads_case_restricted_documents(
    session, officer, make_case, make_document
):
    case = await make_case(officer)
    document = await make_document(
        case, officer, DocumentClassification.CASE_RESTRICTED
    )

    await _enforce_classification(document, officer, session)


async def test_a_court_official_cannot_read_case_restricted_documents(
    session, officer, court_official, make_case, make_document
):
    case = await make_case(officer, court_official)
    document = await make_document(
        case, officer, DocumentClassification.CASE_RESTRICTED
    )

    error = await _denied(_enforce_classification(document, court_official, session))
    assert error.status_code == 403
    assert "requires an access grant" in error.detail


async def test_a_court_official_needs_a_grant_for_elevated_documents(
    session, officer, court_official, make_case, make_document
):
    case = await make_case(officer, court_official)
    document = await make_document(
        case, officer, DocumentClassification.COURT_ELEVATED
    )

    error = await _denied(_enforce_classification(document, court_official, session))
    assert error.status_code == 403
    assert "active access grant" in error.detail


async def test_a_live_grant_opens_an_elevated_document(
    session, officer, court_official, make_case, make_document
):
    case = await make_case(officer, court_official)
    document = await make_document(
        case, officer, DocumentClassification.COURT_ELEVATED
    )
    session.add(
        DocumentAccessGrant(
            document_id=document.id,
            grantee_id=court_official.id,
            granted_by_id=officer.id,
            reason="Hearing on 12th",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )
    await session.flush()

    await _enforce_classification(document, court_official, session)


async def test_an_expired_grant_does_not_open_a_document(
    session, officer, court_official, make_case, make_document
):
    case = await make_case(officer, court_official)
    document = await make_document(
        case, officer, DocumentClassification.COURT_ELEVATED
    )
    session.add(
        DocumentAccessGrant(
            document_id=document.id,
            grantee_id=court_official.id,
            granted_by_id=officer.id,
            reason="Hearing last month",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
    )
    await session.flush()

    error = await _denied(_enforce_classification(document, court_official, session))
    assert error.status_code == 403


async def test_a_revoked_grant_does_not_open_a_document(
    session, officer, court_official, make_case, make_document
):
    case = await make_case(officer, court_official)
    document = await make_document(
        case, officer, DocumentClassification.COURT_ELEVATED
    )
    session.add(
        DocumentAccessGrant(
            document_id=document.id,
            grantee_id=court_official.id,
            granted_by_id=officer.id,
            reason="Withdrawn",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            revoked_at=datetime.now(timezone.utc),
        )
    )
    await session.flush()

    error = await _denied(_enforce_classification(document, court_official, session))
    assert error.status_code == 403


async def test_a_grant_to_someone_else_does_not_open_a_document(
    session, officer, court_official, make_case, make_document
):
    case = await make_case(officer, court_official)
    document = await make_document(
        case, officer, DocumentClassification.COURT_ELEVATED
    )
    session.add(
        DocumentAccessGrant(
            document_id=document.id,
            grantee_id=officer.id,
            granted_by_id=officer.id,
            reason="Wrong grantee",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )
    await session.flush()

    error = await _denied(_enforce_classification(document, court_official, session))
    assert error.status_code == 403


async def test_a_grant_on_another_document_does_not_carry_over(
    session, officer, court_official, make_case, make_document
):
    case = await make_case(officer, court_official)
    granted = await make_document(
        case, officer, DocumentClassification.COURT_ELEVATED
    )
    other = await make_document(case, officer, DocumentClassification.COURT_ELEVATED)
    session.add(
        DocumentAccessGrant(
            document_id=granted.id,
            grantee_id=court_official.id,
            granted_by_id=officer.id,
            reason="Only this one",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )
    await session.flush()

    await _enforce_classification(granted, court_official, session)
    error = await _denied(_enforce_classification(other, court_official, session))
    assert error.status_code == 403


async def test_public_documents_are_open_to_a_court_official(
    session, officer, court_official, make_case, make_document
):
    case = await make_case(officer, court_official)
    document = await make_document(
        case, officer, DocumentClassification.PUBLIC_REDACTED
    )

    await _enforce_classification(document, court_official, session)


async def test_listing_documents_shows_only_assigned_cases(
    session, officer, other_officer, make_case, make_document
):
    mine = await make_case(officer)
    theirs = await make_case(other_officer)
    visible = await make_document(mine, officer)
    await make_document(theirs, other_officer)

    listed = await list_documents(officer, session)
    assert [item.id for item in listed] == [visible.id]


async def test_listing_documents_hides_admin_only_from_officers(
    session, officer, make_case, make_document
):
    case = await make_case(officer)
    visible = await make_document(case, officer, DocumentClassification.CASE_RESTRICTED)
    await make_document(case, officer, DocumentClassification.ADMIN_ONLY)

    listed = await list_documents(officer, session)
    assert [item.id for item in listed] == [visible.id]


async def test_listing_documents_as_admin_shows_admin_only(
    session, officer, admin, make_case, make_document
):
    case = await make_case(officer)
    restricted = await make_document(
        case, officer, DocumentClassification.CASE_RESTRICTED
    )
    hidden = await make_document(case, officer, DocumentClassification.ADMIN_ONLY)

    listed = await list_documents(admin, session)
    ids = {item.id for item in listed}
    assert {restricted.id, hidden.id} <= ids


async def test_listing_documents_with_no_assignments_is_empty(
    session, officer, other_officer, make_case, make_document
):
    case = await make_case(officer)
    await make_document(case, officer)

    assert await list_documents(other_officer, session) == []


async def test_a_demoted_role_changes_what_a_listing_returns(
    session, officer, admin, make_case, make_document
):
    case = await make_case(officer)
    await make_document(case, officer, DocumentClassification.ADMIN_ONLY)

    assert len(await list_documents(admin, session)) >= 1

    admin.role = Role.COURT_OFFICIAL
    await session.flush()

    assert await list_documents(admin, session) == []
