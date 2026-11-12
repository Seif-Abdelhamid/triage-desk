"""Reaching definitions + a taint bit, over the CFG from :mod:`cfg`.

Question answered: *can a value that came from a request / input() /
sys.argv reach the line Semgrep flagged, inside the same function?*

Algorithm
---------
1. Pick the innermost function (or class/module body) that contains the line
   and build its statement-level CFG.
2. For every node, compute the definitions it generates (``x = ...``,
   ``for x in ...``, ``with ... as x``, ``x += ...``, weak updates such as
   ``x[k] = v`` or ``x.append(v)``) and which variables each definition's
   value depends on.
3. Solve classic reaching definitions with a worklist:
   ``IN[n] = U OUT[p]`` over predecessors, ``OUT[n] = GEN[n] U (IN[n] - KILL[n])``.
   Only *strong* definitions (plain assignment to a name) kill.
4. Propagate a taint bit to a fixed point: a definition is tainted if its
   right-hand side contains a source expression, or reads a variable that has
   a tainted definition reaching that node.
5. The flagged line is "tainted" if it contains a source itself, or reads a
   variable with a tainted reaching definition.

Limits (by design, documented in the README): no interprocedural analysis
(calls are opaque, function parameters are untainted unless they *are* a
source name), no sanitizer modelling, no alias / heap analysis, name-based
sources, and ``match`` statements produce ``unknown``.
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from typing import Literal

from .cfg import CFG, Node, UnsupportedConstructError, build_cfg

Label = Literal["tainted", "not_tainted", "unknown"]


@dataclass(frozen=True)
class Sources:
    """What counts as untrusted input. Name-based on purpose: this is a hint."""

    names: frozenset[str] = frozenset({"request"})
    calls: frozenset[str] = frozenset({"input"})
    attributes: frozenset[tuple[str, str]] = frozenset({("sys", "argv")})


DEFAULT_SOURCES = Sources()


@dataclass(frozen=True)
class Definition:
    id: int
    var: str
    node: int
    line: int
    strong: bool
    deps: frozenset[str]
    direct_source: bool


@dataclass
class Result:
    label: Label
    reason: str
    variable: str | None = None
    def_line: int | None = None

    def as_hint(self) -> str:
        if self.label == "tainted":
            if self.variable:
                return (
                    f"tainted input reaches this line (via `{self.variable}`, "
                    f"defined on line {self.def_line})"
                )
            return "tainted input reaches this line (source expression on the line)"
        if self.label == "not_tainted":
            return "no flow from request/input() to this line found inside the function"
        return f"reachability unknown ({self.reason})"


# ---------------------------------------------------------------- expressions


def _loads(expr: ast.AST | None) -> set[str]:
    if expr is None:
        return set()
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _has_source(expr: ast.AST | None, sources: Sources) -> bool:
    if expr is None:
        return False
    for n in ast.walk(expr):
        if isinstance(n, ast.Name) and n.id in sources.names:
            return True
        if isinstance(n, ast.Attribute):
            if n.attr in sources.names:  # flask.request, self.request
                return True
            if isinstance(n.value, ast.Name) and (n.value.id, n.attr) in sources.attributes:
                return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in sources.calls:
            return True
    return False


def _base_name(target: ast.AST) -> str | None:
    while isinstance(target, (ast.Attribute, ast.Subscript, ast.Starred)):
        target = target.value
    return target.id if isinstance(target, ast.Name) else None


@dataclass
class _Effect:
    """What one CFG node reads and writes."""

    uses: set[str] = field(default_factory=set)
    direct_source: bool = False
    # (var, strong, deps, direct_source)
    defs: list[tuple[str, bool, frozenset[str], bool]] = field(default_factory=list)


def _bind(
    target: ast.AST,
    value: ast.AST | None,
    eff: _Effect,
    sources: Sources,
    extra_deps: set[str] | None = None,
) -> None:
    deps = frozenset(_loads(value) | (extra_deps or set()))
    src = _has_source(value, sources)
    if isinstance(target, ast.Name):
        eff.defs.append((target.id, True, deps, src))
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:  # conservative: every element depends on the whole RHS
            _bind(elt, value, eff, sources, extra_deps)
    elif isinstance(target, ast.Starred):
        _bind(target.value, value, eff, sources, extra_deps)
    else:  # x.attr = v / x[k] = v: weak update of x, keeps x's old definitions alive
        base = _base_name(target)
        eff.uses |= _loads(target)
        if base is not None:
            eff.defs.append((base, False, deps | {base}, src))


def _walrus(expr: ast.AST | None, eff: _Effect, sources: Sources) -> None:
    if expr is None:
        return
    for n in ast.walk(expr):
        if isinstance(n, ast.NamedExpr):
            _bind(n.target, n.value, eff, sources)


def _effect(node: Node, sources: Sources) -> _Effect:
    s = node.stmt
    eff = _Effect()
    if s is None:
        return eff

    def read(expr: ast.AST | None) -> None:
        eff.uses |= _loads(expr)
        eff.direct_source |= _has_source(expr, sources)
        _walrus(expr, eff, sources)

    if isinstance(s, ast.Assign):
        read(s.value)
        for t in s.targets:
            _bind(t, s.value, eff, sources)
    elif isinstance(s, ast.AnnAssign):
        if s.value is not None:
            read(s.value)
            _bind(s.target, s.value, eff, sources)
    elif isinstance(s, ast.AugAssign):
        read(s.value)
        base = _base_name(s.target)
        if base is not None:
            eff.uses.add(base)
            strong = isinstance(s.target, ast.Name)
            eff.defs.append(
                (base, strong, frozenset(_loads(s.value) | {base}), _has_source(s.value, sources))
            )
    elif isinstance(s, ast.Expr):
        read(s.value)
        call = s.value
        # x.append(v) / x.update(v): weak update of x with v's taint.
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
            base = _base_name(call.func.value)
            if base is not None and (call.args or call.keywords):
                args: list[ast.AST] = [*call.args, *(k.value for k in call.keywords)]
                deps: set[str] = set()
                src = False
                for a in args:
                    deps |= _loads(a)
                    src |= _has_source(a, sources)
                eff.defs.append((base, False, frozenset(deps | {base}), src))
    elif isinstance(s, (ast.If, ast.While)):
        read(s.test)
    elif isinstance(s, (ast.For, ast.AsyncFor)):
        read(s.iter)
        _bind(s.target, s.iter, eff, sources)
    elif isinstance(s, (ast.With, ast.AsyncWith)):
        for item in s.items:
            read(item.context_expr)
            if item.optional_vars is not None:
                _bind(item.optional_vars, item.context_expr, eff, sources)
    elif isinstance(s, ast.ExceptHandler):
        read(s.type)
        if s.name:
            eff.defs.append((s.name, True, frozenset(), False))
    elif isinstance(s, (ast.Import, ast.ImportFrom)):
        for alias in s.names:
            name = (alias.asname or alias.name).split(".")[0]
            eff.defs.append((name, True, frozenset(), False))
    elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        eff.defs.append((s.name, True, frozenset(), False))
    elif isinstance(s, ast.Delete):
        for t in s.targets:
            if isinstance(t, ast.Name):
                eff.defs.append((t.id, True, frozenset(), False))
            else:
                eff.uses |= _loads(t)
    elif isinstance(s, (ast.Return, ast.Raise, ast.Assert)):
        for child in ast.iter_child_nodes(s):
            read(child)
    return eff


# ---------------------------------------------------------------- analysis


@dataclass
class Analysis:
    cfg: CFG
    defs: list[Definition]
    effects: dict[int, _Effect]
    reach_in: dict[int, frozenset[int]]
    tainted: set[int]


def _scope_for_line(tree: ast.Module, line: int) -> tuple[list[ast.stmt], list[str]]:
    """Innermost function/class body containing ``line``; module body otherwise."""
    best: ast.AST = tree
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body_start = n.body[0].lineno
            end = n.end_lineno or n.lineno
            if body_start <= line <= end:
                cur_start = getattr(best, "lineno", 0)
                if n.lineno >= cur_start:
                    best = n
    params: list[str] = []
    if isinstance(best, (ast.FunctionDef, ast.AsyncFunctionDef)):
        a = best.args
        params = [p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]]
        if a.vararg:
            params.append(a.vararg.arg)
        if a.kwarg:
            params.append(a.kwarg.arg)
    scopes = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    body = best.body if isinstance(best, scopes) else []
    return body, params


def analyze_scope(
    body: list[ast.stmt], params: list[str] | None = None, sources: Sources = DEFAULT_SOURCES
) -> Analysis:
    cfg = build_cfg(body)
    effects = {n.id: _effect(n, sources) for n in cfg.nodes}
    for param in params or []:  # parameters are defined at entry, untainted
        effects[cfg.entry].defs.append((param, True, frozenset(), False))

    defs: list[Definition] = []
    gen: dict[int, set[int]] = {}
    by_var: dict[str, set[int]] = {}
    for n in cfg.nodes:
        gen[n.id] = set()
        for var, strong, deps, src in effects[n.id].defs:
            d = Definition(len(defs), var, n.id, n.first_line, strong, deps, src)
            defs.append(d)
            gen[n.id].add(d.id)
            by_var.setdefault(var, set()).add(d.id)
    kill: dict[int, set[int]] = {}
    for n in cfg.nodes:
        k: set[int] = set()
        for did in gen[n.id]:
            d = defs[did]
            if d.strong:
                k |= by_var[d.var] - gen[n.id]
        kill[n.id] = k

    # Worklist reaching definitions.
    out: dict[int, set[int]] = {n.id: set(gen[n.id]) for n in cfg.nodes}
    reach_in: dict[int, set[int]] = {n.id: set() for n in cfg.nodes}
    work = deque(n.id for n in cfg.nodes)
    while work:
        nid = work.popleft()
        node = cfg.nodes[nid]
        new_in: set[int] = set()
        for p in node.pred:
            new_in |= out[p]
        reach_in[nid] = new_in
        new_out = gen[nid] | (new_in - kill[nid])
        if new_out != out[nid]:
            out[nid] = new_out
            work.extend(node.succ)

    # Taint fixed point (monotone: bits only flip from False to True).
    tainted: set[int] = set()
    changed = True
    while changed:
        changed = False
        for d in defs:
            if d.id in tainted:
                continue
            if d.direct_source or any(
                e in tainted and defs[e].var in d.deps for e in reach_in[d.node]
            ):
                tainted.add(d.id)
                changed = True

    return Analysis(cfg, defs, effects, {k: frozenset(v) for k, v in reach_in.items()}, tainted)


def reaches(source: str, line: int, sources: Sources = DEFAULT_SOURCES) -> Result:
    """Label ``line`` of ``source`` (1-based) as tainted / not_tainted / unknown."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return Result("unknown", f"could not parse file: {exc.msg}")
    body, params = _scope_for_line(tree, line)
    try:
        an = analyze_scope(body, params, sources)
    except UnsupportedConstructError as exc:
        return Result("unknown", f"unsupported construct: {exc}")
    nodes = an.cfg.nodes_on_line(line)
    if not nodes:
        return Result("unknown", "no statement on that line in this scope")
    for node in nodes:
        eff = an.effects[node.id]
        if eff.direct_source:
            return Result("tainted", "source expression on the flagged line")
        for did in sorted(an.reach_in[node.id]):
            d = an.defs[did]
            if did in an.tainted and d.var in eff.uses:
                return Result("tainted", "tainted definition reaches a use", d.var, d.line)
    return Result("not_tainted", "no tainted definition reaches the uses on this line")
