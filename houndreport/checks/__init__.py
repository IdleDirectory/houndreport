"""Pluggable finding checks.

A check is a callable ``fn(ctx: AnalysisContext) -> Iterable[Finding]`` registered with
:func:`check`. Built-in checks live in this package. Third-party packages can add checks
through the ``houndreport.checks`` entry-point group; the entry point may name a module
(importing it runs its ``@check`` decorators) or a check callable.

Findings with no affected objects are dropped, so a check can always yield its findings.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from importlib.metadata import entry_points
from types import ModuleType
from typing import TYPE_CHECKING, Callable, Iterable

from ..model import Finding

if TYPE_CHECKING:
    from ..context import AnalysisContext

CheckFn = Callable[["AnalysisContext"], Iterable[Finding]]

_BUILTIN_MODULES = ("kerberos", "delegation", "acl", "access", "hygiene", "adcs", "paths")


@dataclass(frozen=True)
class RegisteredCheck:
    name: str
    fn: CheckFn
    ids: tuple[str, ...] = ()


REGISTRY: dict[str, RegisteredCheck] = {}
PLUGIN_ERRORS: list[str] = []


def check(name: str, ids: Iterable[str] = ()) -> Callable[[CheckFn], CheckFn]:
    def register(fn: CheckFn) -> CheckFn:
        REGISTRY[name] = RegisteredCheck(name, fn, tuple(ids))
        return fn
    return register


def load_checks(plugins: bool = True) -> dict[str, RegisteredCheck]:
    for module in _BUILTIN_MODULES:
        importlib.import_module(f"{__name__}.{module}")
    if plugins:
        for ep in entry_points(group="houndreport.checks"):
            try:
                obj = ep.load()
            except Exception as exc:  # a broken plugin must not break the report
                PLUGIN_ERRORS.append(f"plugin {ep.name!r} failed to load: {exc}")
                continue
            if callable(obj) and not isinstance(obj, ModuleType) and ep.name not in REGISTRY:
                REGISTRY[ep.name] = RegisteredCheck(ep.name, obj)
    return dict(REGISTRY)


def _skipped(name: str, skip: set[str]) -> bool:
    return name.lower() in skip


def run_checks(ctx: "AnalysisContext") -> list[Finding]:
    skip = {s.lower() for s in ctx.options.skip_checks}
    findings: list[Finding] = []
    ctx.warnings.extend(PLUGIN_ERRORS)
    for name, registered in load_checks().items():
        if _skipped(name, skip):
            continue
        try:
            produced = list(registered.fn(ctx))
        except Exception as exc:
            ctx.warnings.append(f"check {name!r} failed: {type(exc).__name__}: {exc}")
            continue
        findings.extend(f for f in produced if f.affected and not _skipped(f.id, skip))
    findings.sort(key=lambda f: (-f.severity.rank, f.id))
    return findings
