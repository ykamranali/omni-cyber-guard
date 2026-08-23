"""
Every route authorizes, not just authenticates.

This is a structural guard over the whole API surface, and it exists because
the failure it catches is invisible in review and invisible at runtime. Five
endpoints — the exposure graph, attack paths, attack surface, cloud and
identity — shipped with `Depends(get_current_user)` and nothing else. They
worked. They returned the right data to the right tenant. They simply let a
helpdesk technician, a read-only account, or any role at all read the
organization's entire asset and finding inventory, and let anyone launch an
active probe against any domain on the internet.

Nothing in a behavioural test suite notices that, because the endpoint behaves
correctly for every user you happen to test with. So this walks the syntax tree
of every endpoint module instead and requires each route to name a permission.

A route that genuinely must not require a permission — the login form, the
health probe — is listed in EXEMPT with the reason. The list is the point: the
decision has to be made and written down, not made by omission.
"""
from __future__ import annotations

import ast
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ENDPOINTS = BACKEND / "app" / "api" / "v1" / "endpoints"

ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete", "websocket", "head", "options"}

# module -> {function name: why it is allowed to skip require_permission}
EXEMPT: dict[str, dict[str, str]] = {
    "auth.py": {
        "login": "Establishes the session; there is no authenticated user yet.",
        "refresh": "Exchanges a refresh token; the token itself is the credential.",
    },
    "ws.py": {
        "websocket_endpoint": (
            "A WebSocket cannot use a FastAPI dependency that raises HTTP 403. "
            "It performs the equivalent check inline against the resolved user "
            "— see _resolve_user — and closes with a policy-violation code."
        ),
    },
    "users.py": {
        "read_current_user": (
            "Returns the caller's own record. Requiring MANAGE_USERS here would "
            "stop a user reading their own profile."
        ),
    },
    "organizations.py": {
        "get_current_organization": (
            "Returns the caller's own organization, including the branding "
            "every signed-in user needs to render their UI."
        ),
    },
}


def _endpoint_modules() -> list[Path]:
    return sorted(
        path for path in ENDPOINTS.glob("*.py") if path.name != "__init__.py"
    )


def _is_route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        func = decorator.func
        if isinstance(func, ast.Attribute) and func.attr in ROUTE_DECORATORS:
            value = func.value
            if isinstance(value, ast.Name) and value.id == "router":
                return True
    return False


def _guards(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """
    Every identifier appearing in this route's parameter defaults.

    Both spellings have to be caught: `Depends(require_permission(...))`, where
    the guard is a call, and `Depends(require_super_admin)`, where it is a bare
    name. Collecting plain names as well as call targets covers both.
    """
    found: set[str] = set()
    for default in list(node.args.defaults) + list(node.args.kw_defaults):
        if default is None:
            continue
        for inner in ast.walk(default):
            if isinstance(inner, ast.Name):
                found.add(inner.id)
            elif isinstance(inner, ast.Attribute):
                found.add(inner.attr)
    return found


def _routes(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_route(node):
            yield node


def test_every_route_requires_a_permission():
    unguarded: list[str] = []

    for module in _endpoint_modules():
        exemptions = EXEMPT.get(module.name, {})
        for route in _routes(module):
            if route.name in exemptions:
                continue
            if "require_permission" in _guards(route):
                continue
            if "require_super_admin" in _guards(route):
                # Stricter than a permission, not weaker.
                continue
            unguarded.append(f"{module.name}::{route.name}")

    assert not unguarded, (
        "These routes authenticate but do not authorize. Add "
        "require_permission(...), or add the route to EXEMPT with the reason "
        "it does not need one:\n  " + "\n  ".join(unguarded)
    )


def test_no_route_relies_on_bare_authentication():
    """
    `get_current_user` and `get_current_active_user` establish *who* is calling.
    On their own they answer nothing about what that caller may do, and a route
    that uses one as its only guard is the exact shape of the bug this file
    exists to prevent.
    """
    offenders: list[str] = []

    for module in _endpoint_modules():
        exemptions = EXEMPT.get(module.name, {})
        for route in _routes(module):
            if route.name in exemptions:
                continue
            guards = _guards(route)
            bare = guards & {"get_current_user", "get_current_active_user"}
            if bare and "require_permission" not in guards:
                offenders.append(f"{module.name}::{route.name} uses {', '.join(sorted(bare))}")

    assert not offenders, (
        "Authentication is not authorization:\n  " + "\n  ".join(offenders)
    )


def test_the_exemption_list_has_no_stale_entries():
    """
    An exemption that no longer matches a real route is a claim about the code
    that has stopped being true, and it would silently excuse a future route
    that happened to take the same name.
    """
    stale: list[str] = []

    for module_name, exemptions in EXEMPT.items():
        path = ENDPOINTS / module_name
        if not path.exists():
            stale.append(f"{module_name} (module no longer exists)")
            continue
        actual = {route.name for route in _routes(path)}
        for name in exemptions:
            if name not in actual:
                stale.append(f"{module_name}::{name}")

    assert not stale, (
        "These exemptions no longer correspond to a route:\n  " + "\n  ".join(stale)
    )


def test_every_exemption_states_a_reason():
    unexplained = [
        f"{module}::{name}"
        for module, exemptions in EXEMPT.items()
        for name, reason in exemptions.items()
        if not reason or len(reason) < 15
    ]
    assert not unexplained, (
        "An exemption without a reason is a decision nobody made:\n  "
        + "\n  ".join(unexplained)
    )
