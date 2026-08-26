from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, require_roles
from app.database import get_db
from app.models.entities import (
    AuditAction,
    Case,
    CaseAssignment,
    Role,
    User,
)
from app.schemas.cases import CaseAssignmentCreate, CaseCreate, CaseResponse
from app.services.audit import append_entry

router = APIRouter(prefix="/cases", tags=["cases"])


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    payload: CaseCreate,
    current_user: User = Depends(require_roles(Role.INVESTIGATING_OFFICER, Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> CaseResponse:
    existing = await session.scalar(
        select(Case).where(Case.fir_number == payload.fir_number)
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A case with this FIR number already exists",
        )

    case = Case(
        fir_number=payload.fir_number,
        title=payload.title,
        acts_sections=payload.acts_sections,
        status="open",
        created_by_id=current_user.id,
    )
    session.add(case)
    await session.flush()

    session.add(CaseAssignment(case_id=case.id, user_id=current_user.id))

    await append_entry(
        session,
        action=AuditAction.CASE_CREATED,
        actor_id=current_user.id,
        payload={"case_id": str(case.id), "fir_number": case.fir_number},
    )

    await session.commit()
    await session.refresh(case)
    return CaseResponse.model_validate(case)


@router.get("", response_model=list[CaseResponse])
async def list_cases(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[CaseResponse]:
    if current_user.role == Role.ADMIN:
        result = await session.execute(select(Case))
    else:
        result = await session.execute(
            select(Case)
            .join(CaseAssignment, CaseAssignment.case_id == Case.id)
            .where(CaseAssignment.user_id == current_user.id)
        )
    cases = result.scalars().unique().all()
    return [CaseResponse.model_validate(c) for c in cases]


async def _get_case_if_authorized(
    case_id: UUID, current_user: User, session: AsyncSession
) -> Case:
    case = await session.scalar(select(Case).where(Case.id == case_id))
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    if current_user.role == Role.ADMIN:
        return case

    assignment = await session.scalar(
        select(CaseAssignment).where(
            CaseAssignment.case_id == case_id,
            CaseAssignment.user_id == current_user.id,
        )
    )
    if assignment is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not assigned to this case",
        )
    return case


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CaseResponse:
    case = await _get_case_if_authorized(case_id, current_user, session)
    return CaseResponse.model_validate(case)


@router.post("/{case_id}/assignments", status_code=status.HTTP_201_CREATED)
async def assign_to_case(
    case_id: UUID,
    payload: CaseAssignmentCreate,
    current_user: User = Depends(require_roles(Role.INVESTIGATING_OFFICER, Role.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    case = await _get_case_if_authorized(case_id, current_user, session)

    target_user = await session.scalar(select(User).where(User.id == payload.user_id))
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    existing = await session.scalar(
        select(CaseAssignment).where(
            CaseAssignment.case_id == case.id,
            CaseAssignment.user_id == payload.user_id,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already assigned to this case",
        )

    session.add(CaseAssignment(case_id=case.id, user_id=payload.user_id))

    await append_entry(
        session,
        action=AuditAction.CASE_ASSIGNED,
        actor_id=current_user.id,
        payload={"case_id": str(case.id), "assigned_user_id": str(payload.user_id)},
    )

    await session.commit()
    return {"status": "assigned"}