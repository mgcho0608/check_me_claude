"""Pytest fixtures for step1.trust_boundaries primitives.

Detection rule under test: a function is a trust boundary if its
body directly invokes one of the curated POSIX / common-libc I/O
APIs in ``trust_boundaries.API_TABLE``. One row is emitted per
``(function, kind, direction)``.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from check_me.step1 import runner as step1_runner
from check_me.step1 import trust_boundaries as tb_mod


def _project(tmp: Path, files: dict[str, str]) -> Path:
    root = tmp / "proj"
    root.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return root


def _tb(tmp_path: Path, source: str) -> list[dict]:
    root = _project(tmp_path, {"f.c": source})
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    return substrate["categories"]["trust_boundaries"]


# ---------- network input direction ----------


def test_recv_marks_function_as_network_input(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/types.h>
        #include <sys/socket.h>
        int handle(int fd) {
            char buf[64];
            return recv(fd, buf, sizeof(buf), 0);
        }
        """,
    )
    assert any(
        r["function"] == "handle"
        and r["kind"] == "network_socket"
        and r["direction"] == "untrusted_to_trusted"
        for r in rows
    ), rows


def test_recvmsg_marks_function_as_network_input(tmp_path):
    """Mirrors dnsmasq's receive_query."""
    rows = _tb(
        tmp_path,
        """
        #include <sys/types.h>
        #include <sys/socket.h>
        int handle(int fd, struct msghdr *m) {
            return recvmsg(fd, m, 0);
        }
        """,
    )
    nets = [r for r in rows if r["function"] == "handle" and r["kind"] == "network_socket"]
    assert any(r["direction"] == "untrusted_to_trusted" for r in nets), rows


def test_accept_marks_function_as_network_input(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/types.h>
        #include <sys/socket.h>
        int srv(int sock) {
            return accept(sock, 0, 0);
        }
        """,
    )
    assert any(
        r["function"] == "srv"
        and r["kind"] == "network_socket"
        and r["direction"] == "untrusted_to_trusted"
        for r in rows
    ), rows


# ---------- network output direction ----------


def test_sendto_marks_function_as_network_output(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/types.h>
        #include <sys/socket.h>
        int reply(int fd, void *p, int n) {
            return sendto(fd, p, n, 0, 0, 0);
        }
        """,
    )
    assert any(
        r["function"] == "reply"
        and r["kind"] == "network_socket"
        and r["direction"] == "trusted_to_untrusted"
        for r in rows
    ), rows


def test_function_with_both_recv_and_send_emits_two_rows(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/types.h>
        #include <sys/socket.h>
        int echo(int fd) {
            char buf[64];
            int n = recv(fd, buf, sizeof(buf), 0);
            return send(fd, buf, n, 0);
        }
        """,
    )
    nets = [r for r in rows if r["function"] == "echo" and r["kind"] == "network_socket"]
    dirs = sorted(r["direction"] for r in nets)
    assert dirs == ["trusted_to_untrusted", "untrusted_to_trusted"], rows


# ---------- file I/O ----------


def test_read_marks_function_as_file_input(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <unistd.h>
        int rd(int fd, void *buf, unsigned long n) {
            return read(fd, buf, n);
        }
        """,
    )
    assert any(
        r["function"] == "rd"
        and r["kind"] == "file_read"
        and r["direction"] == "untrusted_to_trusted"
        for r in rows
    ), rows


def test_fopen_marks_function_as_file_unknown_direction(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <stdio.h>
        int op(const char *p) {
            FILE *f = fopen(p, "r");
            return f ? 0 : -1;
        }
        """,
    )
    assert any(
        r["function"] == "op"
        and r["kind"] == "file_read"
        and r["direction"] == "unknown"
        for r in rows
    ), rows


def test_fgets_marks_function_as_file_input(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <stdio.h>
        int rd(FILE *f) {
            char b[80];
            return fgets(b, sizeof(b), f) ? 0 : -1;
        }
        """,
    )
    assert any(
        r["function"] == "rd"
        and r["kind"] == "file_read"
        and r["direction"] == "untrusted_to_trusted"
        for r in rows
    ), rows


def test_write_marks_function_as_file_output(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <unistd.h>
        int wr(int fd, void *buf, unsigned long n) {
            return write(fd, buf, n);
        }
        """,
    )
    assert any(
        r["function"] == "wr"
        and r["kind"] == "file_read"
        and r["direction"] == "trusted_to_untrusted"
        for r in rows
    ), rows


# ---------- IPC ----------


def test_pipe_marks_function_as_ipc_unknown(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <unistd.h>
        int mk(int *fds) {
            return pipe(fds);
        }
        """,
    )
    assert any(
        r["function"] == "mk"
        and r["kind"] == "ipc_endpoint"
        and r["direction"] == "unknown"
        for r in rows
    ), rows


def test_msgrcv_marks_function_as_ipc_input(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/msg.h>
        int recv_msg(int q, void *p, unsigned long n) {
            return msgrcv(q, p, n, 0, 0);
        }
        """,
    )
    assert any(
        r["function"] == "recv_msg"
        and r["kind"] == "ipc_endpoint"
        and r["direction"] == "untrusted_to_trusted"
        for r in rows
    ), rows


# ---------- external_io ----------


def test_getenv_marks_function_as_external_input(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <stdlib.h>
        const char *cfg(void) {
            return getenv("CONFIG_PATH");
        }
        """,
    )
    assert any(
        r["function"] == "cfg"
        and r["kind"] == "external_io"
        and r["direction"] == "untrusted_to_trusted"
        for r in rows
    ), rows


def test_ioctl_marks_function_as_external_unknown(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/ioctl.h>
        int op(int fd, int req) {
            return ioctl(fd, req);
        }
        """,
    )
    assert any(
        r["function"] == "op"
        and r["kind"] == "external_io"
        and r["direction"] == "unknown"
        for r in rows
    ), rows


def test_scanf_marks_function_as_external_input(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <stdio.h>
        int input(int *out) {
            return scanf("%d", out);
        }
        """,
    )
    assert any(
        r["function"] == "input"
        and r["kind"] == "external_io"
        and r["direction"] == "untrusted_to_trusted"
        for r in rows
    ), rows


# ---------- main(argv) — CLI input ----------


def test_main_with_argv_emits_external_io_trust_boundary(tmp_path):
    """``int main(int argc, char *argv[])`` is the C-standard CLI
    entry; argv is attacker-controlled. Captured generically by
    name + parameter count, no project-specific check."""
    rows = _tb(
        tmp_path,
        """
        int main(int argc, char *argv[]) { (void)argc; (void)argv; return 0; }
        """,
    )
    main_rows = [r for r in rows if r["function"] == "main"]
    assert any(
        r["kind"] == "external_io"
        and r["direction"] == "untrusted_to_trusted"
        and "argv of main()" in r.get("note", "")
        for r in main_rows
    ), main_rows


def test_main_without_argv_does_not_emit_argv_row(tmp_path):
    rows = _tb(
        tmp_path,
        """
        int main(void) { return 0; }
        """,
    )
    assert all("argv of main()" not in r.get("note", "") for r in rows)


def test_non_main_function_with_two_args_is_not_argv_row(tmp_path):
    rows = _tb(
        tmp_path,
        """
        int handler(int code, char *msg) { (void)code; (void)msg; return 0; }
        """,
    )
    assert rows == []


# ---------- POSIX additions (B2 audit) ----------


def test_popen_marks_function_as_ipc_input(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <stdio.h>
        int run(void) {
            FILE *f = popen("cat", "r");
            (void)f; return 0;
        }
        """,
    )
    assert any(
        r["function"] == "run"
        and r["kind"] == "ipc_endpoint"
        and r["direction"] == "untrusted_to_trusted"
        for r in rows
    ), rows


def test_mmap_marks_function_as_file_read_unknown_direction(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/mman.h>
        void *map(int fd, unsigned long n) {
            return mmap(0, n, 1, 1, fd, 0);
        }
        """,
    )
    assert any(
        r["function"] == "map"
        and r["kind"] == "file_read"
        and r["direction"] == "unknown"
        for r in rows
    ), rows


def test_socketpair_marks_function_as_ipc_endpoint(tmp_path):
    """``socketpair`` creates a Unix-domain socket pair — POSIX
    classifies it under inter-process communication."""
    rows = _tb(
        tmp_path,
        """
        #include <sys/socket.h>
        int pair(int sv[2]) { return socketpair(1, 1, 0, sv); }
        """,
    )
    assert any(
        r["function"] == "pair" and r["kind"] == "ipc_endpoint"
        for r in rows
    ), rows


# ---------- negative cases ----------


def test_internal_function_is_not_a_trust_boundary(tmp_path):
    rows = _tb(
        tmp_path,
        """
        int helper(int x) { return x + 1; }
        int caller(int x) { return helper(x); }
        """,
    )
    assert rows == []


def test_libc_string_calls_do_not_register_as_boundaries(tmp_path):
    """memcpy / strlen are not trust boundaries even though they are libc."""
    rows = _tb(
        tmp_path,
        """
        #include <string.h>
        int copy(char *d, const char *s, unsigned long n) {
            memcpy(d, s, n);
            return strlen(d);
        }
        """,
    )
    assert rows == []


def test_only_function_decl_line_recorded(tmp_path):
    """Boundary 'line' is the function declaration, not the API call site."""
    rows = _tb(
        tmp_path,
        """
        #include <unistd.h>
        int       /* L2 (return type) */
        rd(int fd, void *buf, unsigned long n)  /* L3 (decl) */
        {                                       /* L4 */
            int r;                              /* L5 */
            r = read(fd, buf, n);               /* L6 */
            return r;                           /* L7 */
        }
        """,
    )
    boundary = next(
        r for r in rows
        if r["function"] == "rd" and r["kind"] == "file_read"
    )
    # libclang reports a function's location at the declarator; in
    # this layout that's around line 3. We just assert it is well
    # before the call site at line 6.
    assert boundary["line"] < 6, boundary


def test_note_includes_api_name_and_call_site_line(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/types.h>
        #include <sys/socket.h>
        int handle(int fd) {
            char b[8];
            return recv(fd, b, 8, 0);
        }
        """,
    )
    boundary = next(r for r in rows if r["function"] == "handle")
    assert "recv@L" in boundary["note"], boundary


def test_external_header_boundary_not_attributed_to_project(tmp_path):
    """When a header file from a parallel project tree contains a
    function that calls recv, only its own boundary should appear, with
    its own file path. (Smoke check of the in-project filter.)"""
    rows = _tb(
        tmp_path,
        """
        #include <sys/socket.h>
        int handle(int fd) {
            char b[8];
            return recv(fd, b, 8, 0);
        }
        """,
    )
    files_seen = {r["file"] for r in rows}
    assert files_seen == {"f.c"}


def test_two_functions_each_emit_their_own_boundary(tmp_path):
    rows = _tb(
        tmp_path,
        """
        #include <sys/socket.h>
        #include <unistd.h>
        int net(int s) { char b[4]; return recv(s, b, 4, 0); }
        int file(int fd) { char b[4]; return read(fd, b, 4); }
        """,
    )
    boundaries = sorted({(r["function"], r["kind"]) for r in rows})
    assert ("net", "network_socket") in boundaries
    assert ("file", "file_read") in boundaries


def test_deterministic_output(tmp_path):
    src = """
    #include <sys/socket.h>
    int h(int s) { char b[4]; return recv(s, b, 4, 0); }
    """
    a = _tb(tmp_path / "a", src)
    b = _tb(tmp_path / "b", src)
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
                "#include <sys/socket.h>\n"
                "int h(int s){char b[4];return recv(s,b,4,0);}"
            )
        },
    )
    substrate, _ = step1_runner.run(root, project_name="t", cve="CVE-test")
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(substrate, schema)


def test_api_table_directions_are_valid_enum(tmp_path):
    """All entries in API_TABLE must use the schema's allowed direction
    enum values."""
    allowed = {"untrusted_to_trusted", "trusted_to_untrusted", "unknown"}
    for api, (kind, direction) in tb_mod.API_TABLE.items():
        assert direction in allowed, (api, direction)
        assert kind in {
            "network_socket", "ipc_endpoint", "file_read",
            "external_io", "unknown",
        }, (api, kind)
