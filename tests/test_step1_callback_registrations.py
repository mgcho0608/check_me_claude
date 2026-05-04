"""Pytest fixtures for step1.callback_registrations primitives.

Four registration mechanisms are detected:

- function_table : top-level static array initialized with function
  names.
- function_pointer_assignment : assignment of a function name to a
  function-pointer-typed lvalue inside a function body.
- signal_handler : signal()/bsd_signal()/sysv_signal() with a
  resolved handler function.
- constructor : __attribute__((constructor)) and
  __attribute__((destructor)).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from check_me.step1 import runner as step1_runner


def _project(tmp: Path, files: dict[str, str]) -> Path:
    root = tmp / "proj"
    root.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return root


def _cb(tmp_path: Path, source: str) -> list[dict]:
    root = _project(tmp_path, {"f.c": source})
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    return substrate["categories"]["callback_registrations"]


# ---------------- function_table ----------------


def test_static_array_of_function_names_emits_function_table(tmp_path):
    rows = _cb(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int add1(int x){return x+1;}
        int add2(int x){return x+2;}
        static op_t handlers[] = { add1, add2 };
        """,
    )
    ft = [r for r in rows if r["kind"] == "function_table"]
    assert {r["callback_function"] for r in ft} == {"add1", "add2"}
    for r in ft:
        assert r["registration_site"] == "handlers[]"


def test_table_records_slot_index_in_note(tmp_path):
    rows = _cb(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int a(int x){return x;}
        int b(int x){return x;}
        int c(int x){return x;}
        static op_t T[] = { a, b, c };
        """,
    )
    ft = sorted(
        (r for r in rows if r["kind"] == "function_table"),
        key=lambda r: r["callback_function"],
    )
    assert "slot index 0" in ft[0]["note"]
    assert "slot index 1" in ft[1]["note"]
    assert "slot index 2" in ft[2]["note"]


def test_table_with_null_slots_skips_them(tmp_path):
    """libssh's default_packet_handlers[] has many NULL slots between
    real handlers. Only the function-typed slots should produce rows."""
    rows = _cb(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int handler(int x){return x;}
        static op_t T[] = { 0, 0, handler, 0 };
        """,
    )
    ft = [r for r in rows if r["kind"] == "function_table"]
    assert len(ft) == 1
    assert ft[0]["callback_function"] == "handler"


def test_table_in_function_body_is_not_extracted(tmp_path):
    """Only top-level (file-scope) tables count as function_table.
    A table-typed local var does not — it is not a registration."""
    rows = _cb(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int h(int x){return x;}
        int call(void) {
            op_t local[] = { h };
            return local[0](0);
        }
        """,
    )
    ft = [r for r in rows if r["kind"] == "function_table"]
    assert ft == []


# ---------------- function_pointer_assignment ----------------


def test_struct_field_assigned_function_emits_fn_ptr_assign(tmp_path):
    rows = _cb(
        tmp_path,
        """
        typedef int (*op_t)(int);
        struct slot { op_t cb; };
        int my_cb(int x){return x;}
        void install(struct slot *s){ s->cb = my_cb; }
        """,
    )
    asg = [r for r in rows if r["kind"] == "function_pointer_assignment"]
    assert len(asg) == 1
    assert asg[0]["callback_function"] == "my_cb"
    assert "s->cb" in asg[0]["registration_site"]


def test_global_function_pointer_assignment_inside_body(tmp_path):
    rows = _cb(
        tmp_path,
        """
        typedef int (*op_t)(int);
        op_t g_cb;
        int my_cb(int x){return x;}
        void install(void){ g_cb = my_cb; }
        """,
    )
    asg = [r for r in rows if r["kind"] == "function_pointer_assignment"]
    assert len(asg) == 1
    assert asg[0]["callback_function"] == "my_cb"
    assert asg[0]["registration_site"] == "g_cb"


def test_int_field_assignment_is_not_a_callback_registration(tmp_path):
    """Negative case: an assignment of an int does not count even if
    the RHS happens to be a function name (illegal C, but smoke
    check anyway)."""
    rows = _cb(
        tmp_path,
        """
        struct s { int x; };
        void f(struct s *p, int v){ p->x = v; }
        """,
    )
    assert [r for r in rows if r["kind"] == "function_pointer_assignment"] == []


def test_function_pointer_assigned_to_local_variable(tmp_path):
    rows = _cb(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int my_cb(int x){return x;}
        int run(void) {
            op_t local;
            local = my_cb;
            return local(0);
        }
        """,
    )
    asg = [r for r in rows if r["kind"] == "function_pointer_assignment"]
    assert len(asg) == 1
    assert asg[0]["callback_function"] == "my_cb"


def test_compound_assignment_is_not_a_function_pointer_registration(tmp_path):
    """`+=` etc. are not function-pointer registrations."""
    rows = _cb(
        tmp_path,
        """
        int g(int n){ int c = 0; c += n; return c; }
        """,
    )
    assert [r for r in rows if r["kind"] == "function_pointer_assignment"] == []


def test_assignment_in_initializer_uses_decl_form(tmp_path):
    """`op_t cb = my_cb;` — captured? The current detection rule walks
    BinaryOperator assignments, so initializers (which are
    InitListExprs / AST-different from assignments) are NOT picked up
    here. This documents the boundary explicitly."""
    rows = _cb(
        tmp_path,
        """
        typedef int (*op_t)(int);
        int my_cb(int x){return x;}
        int run(void){
            op_t cb = my_cb;       /* initializer, not assignment */
            return cb(1);
        }
        """,
    )
    # Non-strict: this case is not in scope. Must not crash.
    assert [r for r in rows if r["kind"] == "function_pointer_assignment"] == []


# ---------------- signal_handler ----------------


def test_signal_with_function_handler_emits_signal_handler(tmp_path):
    rows = _cb(
        tmp_path,
        """
        #include <signal.h>
        void on_sig(int s){(void)s;}
        void install(void){ signal(SIGINT, on_sig); }
        """,
    )
    sigs = [r for r in rows if r["kind"] == "signal_handler"]
    assert len(sigs) == 1
    assert sigs[0]["callback_function"] == "on_sig"


def test_signal_with_constant_handler_is_not_extracted(tmp_path):
    """`signal(SIGINT, SIG_IGN)` — handler is not a FunctionDecl
    reference."""
    rows = _cb(
        tmp_path,
        """
        #include <signal.h>
        void install(void){ signal(SIGINT, SIG_IGN); }
        """,
    )
    sigs = [r for r in rows if r["kind"] == "signal_handler"]
    assert sigs == []


def test_other_calls_do_not_register_as_signal_handler(tmp_path):
    rows = _cb(
        tmp_path,
        """
        #include <stdio.h>
        int helper(int x){return x;}
        int call(void){ return helper(1); }
        """,
    )
    assert [r for r in rows if r["kind"] == "signal_handler"] == []


# ---------------- constructor / destructor ----------------


def test_constructor_attribute_emits_constructor_row(tmp_path):
    rows = _cb(
        tmp_path,
        """
        __attribute__((constructor)) void early_init(void){}
        """,
    )
    ctor = [r for r in rows if r["kind"] == "constructor"]
    assert len(ctor) == 1
    assert ctor[0]["callback_function"] == "early_init"
    assert "constructor" in ctor[0]["registration_site"]


def test_destructor_attribute_emits_constructor_row(tmp_path):
    """The schema's enum lumps constructor and destructor under one
    'constructor' kind; the note distinguishes them."""
    rows = _cb(
        tmp_path,
        """
        __attribute__((destructor)) void late_cleanup(void){}
        """,
    )
    rows_c = [r for r in rows if r["kind"] == "constructor"]
    assert len(rows_c) == 1
    assert "destructor" in rows_c[0]["registration_site"]
    assert rows_c[0]["note"] == "destructor"


def test_unrelated_attribute_is_not_a_constructor(tmp_path):
    rows = _cb(
        tmp_path,
        """
        __attribute__((noinline)) int slow(int x){return x;}
        """,
    )
    assert [r for r in rows if r["kind"] == "constructor"] == []


def test_function_with_multiple_attributes_picks_constructor(tmp_path):
    rows = _cb(
        tmp_path,
        """
        __attribute__((constructor, used)) void early(void){}
        """,
    )
    ctor = [r for r in rows if r["kind"] == "constructor"]
    assert len(ctor) == 1
    assert ctor[0]["callback_function"] == "early"


# ---------------- struct_initializer ----------------


def test_global_struct_with_function_pointer_field_emits_struct_initializer(tmp_path):
    """The vtable-registration idiom: a global struct whose fields
    are initialised with named functions. Captures Linux-kernel
    ``struct file_operations``, contiki PROCESS expansion, etc."""
    rows = _cb(
        tmp_path,
        """
        struct ops { int (*open)(void); int (*close)(void); };
        int my_open(void){return 0;}
        int my_close(void){return 0;}
        struct ops vtbl = { my_open, my_close };
        """,
    )
    si = sorted(
        (r for r in rows if r["kind"] == "struct_initializer"),
        key=lambda r: r["callback_function"],
    )
    assert {r["callback_function"] for r in si} == {"my_close", "my_open"}
    for r in si:
        assert r["registration_site"] == "vtbl{}"


def test_designated_struct_initializer_with_fp_field(tmp_path):
    """Designated initialiser ``.field = fn``."""
    rows = _cb(
        tmp_path,
        """
        struct ops { int (*open)(void); int (*close)(void); };
        int my_open(void){return 0;}
        int my_close(void){return 0;}
        struct ops vtbl = { .open = my_open, .close = my_close };
        """,
    )
    si = {r["callback_function"] for r in rows if r["kind"] == "struct_initializer"}
    assert si == {"my_open", "my_close"}


def test_array_of_struct_with_fp_fields_emits_struct_initializer(tmp_path):
    """The nginx ``ngx_command_t cmds[]`` pattern: array whose
    elements are structs with function-pointer fields. Each fn
    reference should be recorded as ``struct_initializer`` (the
    outer is array but elements are records)."""
    rows = _cb(
        tmp_path,
        """
        struct cmd { const char *name; int (*set)(int); };
        int set_a(int x){return x;}
        int set_b(int x){return x;}
        struct cmd cmds[] = {
            { "a", set_a },
            { "b", set_b },
        };
        """,
    )
    si = {r["callback_function"] for r in rows if r["kind"] == "struct_initializer"}
    assert si == {"set_a", "set_b"}


def test_struct_with_no_fp_fields_emits_no_struct_initializer(tmp_path):
    rows = _cb(
        tmp_path,
        """
        struct cfg { int port; const char *name; };
        struct cfg c = { 80, "hi" };
        """,
    )
    assert [r for r in rows if r["kind"] == "struct_initializer"] == []


# ---------------- callback_argument ----------------


def test_pthread_create_emits_callback_argument(tmp_path):
    """Generic POSIX shape: any function passed as a CallExpr
    argument is a registration. Captures pthread_create / atexit /
    qsort / project-internal helpers uniformly."""
    rows = _cb(
        tmp_path,
        """
        typedef unsigned long pthread_t;
        typedef struct { int _; } pthread_attr_t;
        int pthread_create(pthread_t *, const pthread_attr_t *,
                           void *(*)(void *), void *);

        void *worker(void *arg){(void)arg; return 0;}
        void start(pthread_t *t){ pthread_create(t, 0, worker, 0); }
        """,
    )
    ca = [r for r in rows if r["kind"] == "callback_argument"]
    assert any(r["callback_function"] == "worker" for r in ca)
    assert any("pthread_create" in r["registration_site"] for r in ca)


def test_atexit_emits_callback_argument(tmp_path):
    rows = _cb(
        tmp_path,
        """
        int atexit(void (*)(void));
        void cleanup(void){}
        void install(void){ atexit(cleanup); }
        """,
    )
    ca = [r for r in rows if r["kind"] == "callback_argument"]
    assert {r["callback_function"] for r in ca} == {"cleanup"}


def test_signal_does_not_emit_callback_argument(tmp_path):
    """Signal API is more-specifically covered by signal_handler;
    callback_argument must skip signal/bsd_signal/sysv_signal to
    avoid duplicating the same registration under two kinds."""
    rows = _cb(
        tmp_path,
        """
        typedef void (*sighandler_t)(int);
        sighandler_t signal(int, sighandler_t);
        void on_sig(int s){(void)s;}
        void install(void){ signal(2, on_sig); }
        """,
    )
    by_fn = {(r["callback_function"], r["kind"]) for r in rows}
    assert ("on_sig", "signal_handler") in by_fn
    assert ("on_sig", "callback_argument") not in by_fn


def test_call_with_no_function_argument_emits_nothing(tmp_path):
    rows = _cb(
        tmp_path,
        """
        int compute(int x){return x*2;}
        void caller(void){ (void)compute(5); }
        """,
    )
    assert [r for r in rows if r["kind"] == "callback_argument"] == []


def test_project_internal_register_helper_is_caught(tmp_path):
    """An internal ``register_handler(my_fn)`` looks structurally
    identical to POSIX ``atexit(fn)`` and should be captured the
    same way — no allow-list of API names is hardcoded."""
    rows = _cb(
        tmp_path,
        """
        typedef int (*handler_t)(int);
        void register_handler(handler_t);
        int my_handler(int x){return x;}
        void install(void){ register_handler(my_handler); }
        """,
    )
    ca = [r for r in rows if r["kind"] == "callback_argument"]
    assert {r["callback_function"] for r in ca} == {"my_handler"}


# ---------------- structural / cross-mechanism ----------------


def test_a_file_with_all_four_mechanisms(tmp_path):
    rows = _cb(
        tmp_path,
        """
        #include <signal.h>
        typedef int (*op_t)(int);

        int t1(int x){return x;}
        int t2(int x){return x;}
        static op_t T[] = { t1, t2 };

        struct slot { op_t cb; };
        int handler(int x){return x;}
        void install_field(struct slot *s){ s->cb = handler; }

        void on_sig(int s){(void)s;}
        void install_signal(void){ signal(SIGINT, on_sig); }

        __attribute__((constructor)) void early(void){}
        """,
    )
    kinds = sorted({r["kind"] for r in rows})
    assert kinds == [
        "constructor",
        "function_pointer_assignment",
        "function_table",
        "signal_handler",
    ]


def test_only_project_files_emit_rows(tmp_path):
    rows = _cb(
        tmp_path,
        """
        #include <signal.h>
        void on_sig(int s){(void)s;}
        void install(void){ signal(SIGINT, on_sig); }
        """,
    )
    files_seen = {r["file"] for r in rows}
    assert files_seen == {"f.c"}


def test_deterministic_output(tmp_path):
    src = """
    typedef int (*op_t)(int);
    int a(int x){return x;}
    int b(int x){return x;}
    static op_t T[] = { a, b };
    """
    a = _cb(tmp_path / "a", src)
    b = _cb(tmp_path / "b", src)
    assert a == b


def test_substrate_validates_against_schema(tmp_path):
    schema_path = (
        Path(__file__).parents[1] / "schemas" / "substrate.v1.json"
    )
    if not schema_path.is_file():
        pytest.skip("schema file not present")
    schema = json.loads(schema_path.read_text())
    root = _project(
        tmp_path,
        {
            "f.c": (
                "typedef int (*op_t)(int);\n"
                "int h(int x){return x;}\n"
                "static op_t T[] = { h };\n"
            )
        },
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(substrate, schema)
