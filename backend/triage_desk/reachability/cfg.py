"""Statement-level control-flow graph (CFG) for one Python scope.

One CFG node per simple statement, plus one "header" node per ``if`` test,
``while`` test, ``for`` iteration step and ``with`` header. The builder handles
straight-line code, if/elif/else, while/for loops (with else, break and
continue), with-blocks and an over-approximation of try/except/finally.

It is intraprocedural on purpose: calls are opaque, nested functions and
classes are a single "defines a name" node, and ``match`` statements are
rejected with :class:`UnsupportedConstructError` instead of being modelled badly.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


class UnsupportedConstructError(Exception):
    """The scope contains syntax the CFG builder does not model."""


@dataclass
class Node:
    id: int
    kind: str  # "entry" | "exit" | "stmt" | "branch" | "loop" | "with"
    stmt: ast.AST | None = None
    first_line: int = 0
    last_line: int = 0
    succ: set[int] = field(default_factory=set)
    pred: set[int] = field(default_factory=set)


@dataclass
class _Loop:
    header: int
    breaks: list[int] = field(default_factory=list)


class CFG:
    def __init__(self) -> None:
        self.nodes: list[Node] = []
        self.entry = self._new("entry").id
        self.exit = self._new("exit").id

    def _new(self, kind: str, stmt: ast.AST | None = None, first: int = 0, last: int = 0) -> Node:
        node = Node(id=len(self.nodes), kind=kind, stmt=stmt, first_line=first, last_line=last)
        self.nodes.append(node)
        return node

    def edge(self, a: int, b: int) -> None:
        self.nodes[a].succ.add(b)
        self.nodes[b].pred.add(a)

    def nodes_on_line(self, line: int) -> list[Node]:
        """Nodes whose own source span (not their nested bodies) covers ``line``."""
        return [n for n in self.nodes if n.stmt is not None and n.first_line <= line <= n.last_line]


_SIMPLE = (
    ast.Assign,
    ast.AugAssign,
    ast.AnnAssign,
    ast.Expr,
    ast.Pass,
    ast.Assert,
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.Delete,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
)


def _header_span(stmt: ast.stmt, last_expr: ast.AST) -> tuple[int, int]:
    end = getattr(last_expr, "end_lineno", None) or stmt.lineno
    return stmt.lineno, end


class _Builder:
    def __init__(self, cfg: CFG) -> None:
        self.cfg = cfg
        self.loops: list[_Loop] = []

    def _link(self, preds: set[int], node: Node) -> None:
        for p in preds:
            self.cfg.edge(p, node.id)

    def block(self, stmts: list[ast.stmt], preds: set[int]) -> set[int]:
        """Add ``stmts``; return the nodes that fall through to whatever follows."""
        current = set(preds)
        for stmt in stmts:
            current = self.stmt(stmt, current)
        return current

    def stmt(self, s: ast.stmt, preds: set[int]) -> set[int]:
        cfg = self.cfg
        if isinstance(s, _SIMPLE):
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Only the header line belongs to this scope; the body is another scope.
                first = min([s.lineno] + [d.lineno for d in s.decorator_list])
                span = (first, s.lineno)
            else:
                span = (s.lineno, s.end_lineno or s.lineno)
            node = cfg._new("stmt", s, *span)
            self._link(preds, node)
            return {node.id}

        if isinstance(s, (ast.Return, ast.Raise)):
            node = cfg._new("stmt", s, s.lineno, s.end_lineno or s.lineno)
            self._link(preds, node)
            cfg.edge(node.id, cfg.exit)
            return set()

        if isinstance(s, ast.If):
            node = cfg._new("branch", s, *_header_span(s, s.test))
            self._link(preds, node)
            out = self.block(s.body, {node.id})
            out |= self.block(s.orelse, {node.id}) if s.orelse else {node.id}
            return out

        if isinstance(s, (ast.While, ast.For, ast.AsyncFor)):
            last = s.test if isinstance(s, ast.While) else s.iter
            node = cfg._new("loop", s, *_header_span(s, last))
            self._link(preds, node)
            loop = _Loop(header=node.id)
            self.loops.append(loop)
            body_out = self.block(s.body, {node.id})
            for b in body_out:
                cfg.edge(b, node.id)  # back edge
            self.loops.pop()
            # The loop exits through the header (condition false / iterator done);
            # ``else`` runs on that path only, ``break`` skips it.
            out = self.block(s.orelse, {node.id}) if s.orelse else {node.id}
            return out | set(loop.breaks)

        if isinstance(s, ast.Break):
            if not self.loops:
                raise UnsupportedConstructError("break outside loop")
            node = cfg._new("stmt", s, s.lineno, s.lineno)
            self._link(preds, node)
            self.loops[-1].breaks.append(node.id)
            return set()

        if isinstance(s, ast.Continue):
            if not self.loops:
                raise UnsupportedConstructError("continue outside loop")
            node = cfg._new("stmt", s, s.lineno, s.lineno)
            self._link(preds, node)
            cfg.edge(node.id, self.loops[-1].header)
            return set()

        if isinstance(s, (ast.With, ast.AsyncWith)):
            node = cfg._new("with", s, *_header_span(s, s.items[-1].context_expr))
            self._link(preds, node)
            return self.block(s.body, {node.id})

        if isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
            return self._try(s, preds)

        raise UnsupportedConstructError(type(s).__name__)

    def _try(self, s: Any, preds: set[int]) -> set[int]:  # ast.Try or ast.TryStar
        # Over-approximation: an exception may be raised before any statement of
        # the try body, so every handler is reachable from the try's predecessors
        # and from every node created inside the body.
        before = len(self.cfg.nodes)
        body_out = self.block(s.body, preds)
        body_nodes = set(range(before, len(self.cfg.nodes)))
        handler_preds = set(preds) | body_nodes
        out = self.block(s.orelse, body_out) if s.orelse else body_out
        for handler in s.handlers:
            # ``except E as name`` binds name; model it as a with-like header node.
            node = self.cfg._new("with", handler, handler.lineno, handler.lineno)
            self._link(handler_preds, node)
            out |= self.block(handler.body, {node.id})
        if s.finalbody:
            out = self.block(s.finalbody, out | handler_preds)
        return out


def build_cfg(body: list[ast.stmt]) -> CFG:
    cfg = CFG()
    builder = _Builder(cfg)
    out = builder.block(body, {cfg.entry})
    for n in out:
        cfg.edge(n, cfg.exit)
    return cfg
