from __future__ import annotations

import inspect
from typing import Any, Iterator

import pytest
from fastapi.routing import APIRoute

from app.api import deps
from app.api.v1.admin import router as admin_router
from app.api.v1.assets import router as assets_router
from app.api.v1.audit import router as audit_router
from app.api.v1.auth import router as auth_router
from app.api.v1.cases import router as cases_router
from app.api.v1.documents import router as documents_router
from app.api.v1.retention import router as retention_router
from app.models.entities import Role

ROUTERS = {
    "auth": auth_router,
    "cases": cases_router,
    "documents": documents_router,
    "audit": audit_router,
    "retention": retention_router,
    "assets": assets_router,
    "admin": admin_router,
}

PUBLIC_ROUTES = {
    ("POST", "/auth/login"),
    ("POST", "/auth/refresh"),
}

ENROLMENT_ROUTES = {
    ("POST", "/auth/mfa/enroll"),
    ("POST", "/auth/mfa/activate"),
    ("POST", "/auth/logout"),
    ("GET", "/auth/me"),
}


def all_routes() -> Iterator[tuple[str, str, str, APIRoute]]:
    for name, router in ROUTERS.items():
        for route in router.routes:
            if not isinstance(route, APIRoute):
                continue
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                yield name, method, route.path, route


def dependencies_of(route: APIRoute) -> Iterator[Any]:
    stack = list(route.dependant.dependencies)
    while stack:
        dependant = stack.pop()
        if dependant.call is not None:
            yield dependant.call
        stack.extend(dependant.dependencies)


def guards_on(route: APIRoute) -> set[str]:
    return {
        getattr(call, "__name__", "")
        for call in dependencies_of(route)
    }


def allowed_roles(route: APIRoute) -> set[Role] | None:
    for call in dependencies_of(route):
        if getattr(call, "__name__", "") != "role_guard":
            continue
        closure = call.__closure__ or ()
        names = call.__code__.co_freevars
        for name, cell in zip(names, closure):
            if name == "allowed_roles":
                return set(cell.cell_contents)
    return None


def is_authenticated(route: APIRoute) -> bool:
    return bool(
        guards_on(route)
        & {"get_current_user", "get_enrolling_user", "role_guard", "require_fresh_mfa"}
    )


def test_the_audit_sees_every_router():
    assert set(ROUTERS) == {
        "auth",
        "cases",
        "documents",
        "audit",
        "retention",
        "assets",
        "admin",
    }


def test_there_are_routes_to_audit():
    assert len(list(all_routes())) > 30


@pytest.mark.parametrize(
    "router,method,path",
    [(r, m, p) for r, m, p, _ in all_routes()],
)
def test_every_route_is_authenticated_unless_it_is_on_the_public_list(
    router, method, path
):
    route = next(
        r for name, m, p, r in all_routes() if name == router and m == method and p == path
    )

    if (method, path) in PUBLIC_ROUTES:
        pytest.skip(f"{method} {path} is deliberately public")

    assert is_authenticated(route), (
        f"{method} {path} in {router}.py has no authentication dependency. "
        f"Add one, or add it to PUBLIC_ROUTES with a reason."
    )


def test_the_public_list_only_contains_routes_that_exist():
    existing = {(m, p) for _, m, p, _ in all_routes()}
    assert PUBLIC_ROUTES <= existing


def test_public_routes_really_are_unauthenticated():
    for name, method, path, route in all_routes():
        if (method, path) in PUBLIC_ROUTES:
            assert not is_authenticated(route), (
                f"{method} {path} is on the public list but is guarded. "
                f"Remove it from PUBLIC_ROUTES."
            )


def enforces_admin_inline(route: APIRoute) -> bool:
    try:
        source = inspect.getsource(route.endpoint)
    except (OSError, TypeError):
        return False
    return "Role.ADMIN" in source and "HTTP_403_FORBIDDEN" in source


def test_every_admin_route_requires_an_administrator():
    for name, method, path, route in all_routes():
        if name != "admin":
            continue

        roles = allowed_roles(route)
        if roles is not None:
            assert roles == {Role.ADMIN}, f"{method} {path} allows {roles}"
            continue

        assert enforces_admin_inline(route), (
            f"{method} {path} has neither a require_roles(Role.ADMIN) dependency "
            f"nor an inline admin check that raises 403."
        )


def test_admin_routes_without_a_role_dependency_at_least_require_step_up():
    for name, method, path, route in all_routes():
        if name != "admin" or allowed_roles(route) is not None:
            continue
        assert "require_fresh_mfa" in guards_on(route), (
            f"{method} {path} relies on an inline admin check with no step-up"
        )


def test_no_route_outside_auth_uses_the_enrolment_only_dependency():
    for name, method, path, route in all_routes():
        if (method, path) in ENROLMENT_ROUTES:
            continue
        assert "get_enrolling_user" not in guards_on(route), (
            f"{method} {path} accepts an MFA-pending session. Only the "
            f"enrolment routes may do that."
        )


def test_the_enrolment_routes_still_require_a_session():
    for name, method, path, route in all_routes():
        if (method, path) in ENROLMENT_ROUTES:
            assert is_authenticated(route)


def test_role_guards_never_allow_an_unknown_role():
    for name, method, path, route in all_routes():
        roles = allowed_roles(route)
        if roles is None:
            continue
        assert roles <= set(Role), f"{method} {path} allows a role outside the enum"
        assert roles, f"{method} {path} has an empty role guard, which denies everyone"


def test_the_guard_dependencies_are_the_ones_deps_exports():
    for name, method, path, route in all_routes():
        for call in dependencies_of(route):
            call_name = getattr(call, "__name__", "")
            if call_name in {"get_current_user", "get_enrolling_user", "require_fresh_mfa"}:
                assert call is getattr(deps, call_name), (
                    f"{method} {path} uses a shadowed copy of {call_name}"
                )


def test_write_routes_on_the_audit_router_are_admin_only():
    for name, method, path, route in all_routes():
        if name != "audit" or method == "GET":
            continue
        roles = allowed_roles(route)
        assert roles is not None, f"{method} {path} has no role guard"
        assert Role.ADMIN in roles


def test_retention_routes_are_role_guarded():
    for name, method, path, route in all_routes():
        if name != "retention":
            continue
        assert allowed_roles(route) is not None, f"{method} {path} has no role guard"


def test_no_route_is_guarded_by_a_bare_role_check_without_authentication():
    for name, method, path, route in all_routes():
        names = guards_on(route)
        if "role_guard" in names:
            assert "get_current_user" in names, (
                f"{method} {path} checks a role without resolving the caller"
            )


def test_step_up_routes_also_carry_ordinary_authentication():
    for name, method, path, route in all_routes():
        names = guards_on(route)
        if "require_fresh_mfa" in names:
            assert "get_current_user" in names
