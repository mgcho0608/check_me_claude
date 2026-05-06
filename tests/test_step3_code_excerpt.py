"""Tests for Step 3 source-code excerpt extraction.

The macro-wrapped-function-definition fallback is the focus
here — many real-world C codebases (libssh's SSH_PACKET_CALLBACK,
contiki's PROCESS_THREAD, Linux-kernel macros, OpenSSL
IMPLEMENT_*, nginx ngx_*) define functions inside an UPPERCASE
wrapping macro. libclang sees the macro name as the
FUNCTION_DECL spelling and the real function identifier as a
child cursor. Without the fallback, ``extract_excerpts`` silently
drops these — which broke libssh CVE-2018-10933's
``ssh_packet_userauth_success`` body extraction (sink line=0
in the IR was the visible symptom).

These tests use synthetic project trees, no project-specific
content. The fallback rule (FUNCTION_DECL spelling looks like
a macro AND a child cursor's spelling is in ``wanted``) is a
pure libclang + C-convention shape match, so the tests verify
generality on a tiny made-up macro pattern that mirrors the
shape without referencing any real project's macro name.
"""

from __future__ import annotations

import textwrap

from check_me.step3.code_excerpt import (
    _looks_like_function_identifier,
    _looks_like_macro_name,
    extract_excerpts,
)


# --------------------------------------------------------------------------- #
# Helper-level shape rules
# --------------------------------------------------------------------------- #


def test_looks_like_macro_name_accepts_uppercase_underscore():
    assert _looks_like_macro_name("SSH_PACKET_CALLBACK")
    assert _looks_like_macro_name("PROCESS_THREAD")
    assert _looks_like_macro_name("MODULE_INIT")
    assert _looks_like_macro_name("_MY_MACRO_")
    # Mixed digits + uppercase ok.
    assert _looks_like_macro_name("CRYPTO_ASN1_F2")


def test_looks_like_macro_name_rejects_regular_function_names():
    # Regular function identifiers are not all-uppercase.
    assert not _looks_like_macro_name("ssh_packet_callback")
    assert not _looks_like_macro_name("SshPacketCallback")
    assert not _looks_like_macro_name("foo")
    # Single character and empty rejected.
    assert not _looks_like_macro_name("F")
    assert not _looks_like_macro_name("")
    # Non-alpha-non-digit-non-underscore rejected.
    assert not _looks_like_macro_name("FOO BAR")
    assert not _looks_like_macro_name("FOO-BAR")
    # No alpha character (just underscore/digits) rejected.
    assert not _looks_like_macro_name("__")
    assert not _looks_like_macro_name("_1_2_")


def test_looks_like_function_identifier_basic():
    assert _looks_like_function_identifier("ssh_packet_userauth_success")
    assert _looks_like_function_identifier("foo_bar")
    assert _looks_like_function_identifier("_internal")
    assert not _looks_like_function_identifier("")
    assert not _looks_like_function_identifier("a")
    assert not _looks_like_function_identifier("1foo")


# --------------------------------------------------------------------------- #
# End-to-end extraction with libclang
# --------------------------------------------------------------------------- #


def _write(tmp_path, rel: str, body: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body))


def test_extract_excerpts_finds_normal_functions(tmp_path):
    """Sanity: regular C function definitions still extracted
    (the fallback path must not regress the fast path)."""
    _write(tmp_path, "src/foo.c", """\
        int helper(int x) {
            return x + 1;
        }

        int target_fn(int n) {
            return helper(n) * 2;
        }
        """)
    out = extract_excerpts(tmp_path, [("src/foo.c", "target_fn")])
    assert len(out) == 1
    assert out[0].function == "target_fn"
    assert "return helper(n) * 2;" in out[0].body


def test_extract_excerpts_macro_wrapped_function_definition(tmp_path):
    """The fallback case: a function defined inside an
    UPPERCASE wrapping macro. libclang's FUNCTION_DECL
    spelling becomes the macro name; the real function
    identifier is a child cursor.

    Uses a synthetic ``MY_HANDLER`` macro pattern that mirrors
    the shape of libssh's SSH_PACKET_CALLBACK / contiki's
    PROCESS_THREAD without referencing either project's name.
    The fallback rule is project-agnostic — this one synthetic
    case validates the general mechanism."""
    _write(tmp_path, "src/handlers.c", """\
        #define MY_HANDLER(name) \\
            int name(int session, int type, int packet)

        MY_HANDLER(handle_login_success) {
            return type;
        }

        MY_HANDLER(handle_login_failure) {
            return packet;
        }

        int regular_fn(int x) {
            return x;
        }
        """)
    out = extract_excerpts(
        tmp_path,
        [
            ("src/handlers.c", "handle_login_success"),
            ("src/handlers.c", "handle_login_failure"),
            ("src/handlers.c", "regular_fn"),
        ],
    )
    names = {e.function for e in out}
    assert "handle_login_success" in names, (
        "Macro-wrapped function definition body must be extracted "
        "via the children-scan fallback. See _resolve_macro_wrapped_name."
    )
    assert "handle_login_failure" in names
    assert "regular_fn" in names


def test_extract_excerpts_does_not_false_match_param_name(tmp_path):
    """Negative: a regular (non-macro) function whose parameter
    name happens to match a wanted symbol must NOT be extracted
    as if it were that symbol. Without the macro-name gate, a
    naive children-scan would false-match here."""
    _write(tmp_path, "src/x.c", """\
        int foo(int wanted_symbol) {
            return wanted_symbol + 1;
        }
        """)
    # ``wanted_symbol`` is the parameter name of foo. The fallback
    # must not return foo's body as if it were wanted_symbol's.
    out = extract_excerpts(tmp_path, [("src/x.c", "wanted_symbol")])
    assert out == [], (
        "PARM_DECL spelling matching a wanted symbol must NOT be "
        "treated as a macro-wrapped function definition when the "
        "containing FUNCTION_DECL has a regular (non-macro-shaped) "
        "name. _looks_like_macro_name gate guards against this."
    )
