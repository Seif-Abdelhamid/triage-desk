import textwrap

import pytest

from triage_desk.reachability import reaches
from triage_desk.reachability.cfg import build_cfg


def line_of(src: str, marker: str = "# SINK") -> int:
    for i, text in enumerate(src.splitlines(), start=1):
        if marker in text:
            return i
    raise AssertionError("marker not found")


def check(src: str) -> str:
    src = textwrap.dedent(src)
    return reaches(src, line_of(src)).label


def test_straight_line_flow() -> None:
    src = """
    def view():
        q = request.args.get("q")
        sql = "SELECT * FROM t WHERE x = '" + q + "'"
        cursor.execute(sql)  # SINK
    """
    assert check(src) == "tainted"


def test_reports_witness_variable_and_line() -> None:
    src = textwrap.dedent("""
    def view():
        q = request.args.get("q")
        run(q)  # SINK
    """)
    result = reaches(src, line_of(src))
    assert result.variable == "q"
    assert result.def_line == 3
    assert "tainted input reaches this line" in result.as_hint()


def test_source_on_the_flagged_line_itself() -> None:
    src = """
    def view():
        cursor.execute("SELECT " + request.args["q"])  # SINK
    """
    assert check(src) == "tainted"


def test_input_call_is_a_source() -> None:
    src = """
    name = input("name? ")
    os.system("echo " + name)  # SINK
    """
    assert check(src) == "tainted"


def test_sys_argv_is_a_source() -> None:
    src = """
    import sys
    target = sys.argv[1]
    subprocess.run(target, shell=True)  # SINK
    """
    assert check(src) == "tainted"


def test_overwrite_kills_tainted_definition() -> None:
    src = """
    def view():
        q = request.args.get("q")
        q = "constant"
        cursor.execute(q)  # SINK
    """
    assert check(src) == "not_tainted"


def test_constant_only_flow() -> None:
    src = """
    def job():
        cmd = "ls -la"
        subprocess.run(cmd, shell=True)  # SINK
    """
    assert check(src) == "not_tainted"


def test_one_branch_taints() -> None:
    src = """
    def view(flag):
        x = "safe"
        if flag:
            x = request.form["x"]
        eval(x)  # SINK
    """
    assert check(src) == "tainted"


def test_both_branches_overwrite() -> None:
    src = """
    def view(flag):
        x = request.form["x"]
        if flag:
            x = "a"
        else:
            x = "b"
        eval(x)  # SINK
    """
    assert check(src) == "not_tainted"


def test_elif_chain() -> None:
    src = """
    def view(n):
        if n == 1:
            x = "a"
        elif n == 2:
            x = input()
        else:
            x = "c"
        eval(x)  # SINK
    """
    assert check(src) == "tainted"


def test_reassignment_later_in_loop_reaches_via_back_edge() -> None:
    # First iteration x is safe, but on the second iteration the value assigned
    # at the bottom of the body flows back to the sink through the back edge.
    src = """
    def view():
        x = "safe"
        for i in range(3):
            eval(x)  # SINK
            x = request.args.get("q")
    """
    assert check(src) == "tainted"


def test_loop_that_cleans_before_use_each_iteration() -> None:
    src = """
    def view():
        x = request.args.get("q")
        while more():
            x = "safe"
            eval(x)  # SINK
    """
    assert check(src) == "not_tainted"


def test_zero_iteration_loop_keeps_tainted_value() -> None:
    src = """
    def view():
        x = request.args.get("q")
        while more():
            x = "safe"
        eval(x)  # SINK
    """
    assert check(src) == "tainted"


def test_taint_propagates_through_loop_carried_dependency() -> None:
    # y is only tainted after x is; needs the taint fixed point, not one pass.
    src = """
    def view():
        x = "a"
        y = "b"
        for _ in range(2):
            y = x
            x = request.args["q"]
        eval(y)  # SINK
    """
    assert check(src) == "tainted"


def test_for_target_from_tainted_iterable() -> None:
    src = """
    def view():
        for item in request.json["items"]:
            eval(item)  # SINK
    """
    assert check(src) == "tainted"


def test_break_skips_reassignment() -> None:
    src = """
    def view():
        x = request.args["q"]
        while True:
            if done():
                break
            x = "safe"
        eval(x)  # SINK
    """
    assert check(src) == "tainted"


def test_continue_edges_back_to_header() -> None:
    src = """
    def view(rows):
        x = "safe"
        for r in rows:
            if r:
                x = input()
                continue
            eval(x)  # SINK
    """
    assert check(src) == "tainted"


def test_augmented_assignment_keeps_taint() -> None:
    src = """
    def view():
        cmd = "grep "
        cmd += request.args["pattern"]
        os.system(cmd)  # SINK
    """
    assert check(src) == "tainted"


def test_weak_update_via_append() -> None:
    src = """
    def view():
        parts = []
        parts.append(request.args["a"])
        os.system(" ".join(parts))  # SINK
    """
    assert check(src) == "tainted"


def test_subscript_store_is_weak_update() -> None:
    src = """
    def view():
        d = {}
        d["k"] = request.args["a"]
        d["j"] = "x"
        eval(d["k"])  # SINK
    """
    assert check(src) == "tainted"


def test_tuple_unpacking() -> None:
    src = """
    def view():
        a, b = request.args["a"], "x"
        eval(a)  # SINK
    """
    assert check(src) == "tainted"


def test_with_as_binding() -> None:
    src = """
    def view():
        with open(request.args["path"]) as fh:
            data = fh.read()
        eval(data)  # SINK
    """
    assert check(src) == "tainted"


def test_try_except_over_approximation() -> None:
    src = """
    def view():
        x = request.args["q"]
        try:
            x = "safe"
            risky()
        except ValueError:
            pass
        eval(x)  # SINK
    """
    # The exception may fire before the reassignment, so the tainted value can survive.
    assert check(src) == "tainted"


def test_parameters_are_untainted_no_interprocedural_analysis() -> None:
    # Documented limit: we do not look at callers.
    src = """
    def helper(value):
        os.system(value)  # SINK
    """
    assert check(src) == "not_tainted"


def test_calls_are_opaque() -> None:
    # Documented limit: the return value of an arbitrary call is not a source.
    src = """
    def view():
        v = get_param()
        os.system(v)  # SINK
    """
    assert check(src) == "not_tainted"


def test_innermost_function_is_analyzed_separately() -> None:
    src = """
    def outer():
        q = request.args["q"]
        def inner():
            q = "safe"
            eval(q)  # SINK
        inner()
    """
    assert check(src) == "not_tainted"


def test_match_statement_is_unknown() -> None:
    src = """
    def view(cmd):
        match cmd:
            case "a":
                x = 1
        eval(cmd)  # SINK
    """
    assert check(src) == "unknown"


def test_syntax_error_is_unknown() -> None:
    assert reaches("def broken(:\n", 1).label == "unknown"


@pytest.mark.parametrize("line", [0, 999])
def test_line_without_statement_is_unknown(line: int) -> None:
    assert reaches("x = 1\n", line).label == "unknown"


def test_cfg_has_back_edge_for_loop() -> None:
    import ast

    body = ast.parse("while c:\n    x = 1\ny = 2\n").body
    cfg = build_cfg(body)
    header = next(n for n in cfg.nodes if n.kind == "loop")
    assign = next(n for n in cfg.nodes if n.first_line == 2)
    assert header.id in assign.succ  # back edge
    assert assign.id in header.succ
