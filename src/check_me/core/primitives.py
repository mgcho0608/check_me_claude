"""
Structural Reasoning Primitives (PLAN.md §11)

결정론적이고 재사용 가능한 heuristic 분석 단위.
모든 primitive는 compact, machine-readable, confidence-bounded.

Primitives:
  - result_use_links     : guard 함수의 반환값이 실제 조건 분기에 쓰이는가
  - enforcement_links    : guard가 action을 직접 gate하는가
  - state_lifecycle      : 상태 플래그(verified/authenticated 등)의 변화 흔적
  - decision_input_hints : guard 함수에 들어오는 입력의 신뢰도 힌트
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ──────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────

@dataclass
class ResultUseLink:
    """guard 함수의 반환값이 분기 조건에 쓰이는 흔적."""
    function_id: str          # 이 분석이 일어난 함수
    guard_name: str           # if (guard_name(...)) 형태로 쓰인 이름
    pattern: str              # 매칭된 패턴 유형
    line: int
    heuristic: bool = True
    confidence: str = "low"


@dataclass
class EnforcementLink:
    """guard 결과가 action을 gate하는 구조적 흔적."""
    function_id: str
    guard_name: str
    action_name: str
    guard_line: int
    action_line: int
    guard_result_used: bool   # guard 반환값이 조건으로 쓰였는가
    heuristic: bool = True
    confidence: str = "low"


@dataclass
class StateLifecycleEntry:
    """verified / authenticated 등 상태 플래그의 변화 흔적."""
    function_id: str
    flag_name: str             # e.g. "verified", "authenticated"
    assigned_value: str        # "true" | "false" | "unknown"
    line: int
    heuristic: bool = True


@dataclass
class DecisionInputHint:
    """guard 함수 인수의 신뢰도 힌트 (외부 입력인가, 내부 상태인가)."""
    function_id: str
    guard_name: str
    arg_token: str             # 인수 텍스트 (heuristic token)
    source_hint: str           # "external" | "internal_state" | "unknown"
    line: int
    heuristic: bool = True


@dataclass
class FunctionPrimitives:
    """단일 함수에 대한 전체 primitive 집합."""
    function_id: str
    result_use_links: list[ResultUseLink] = field(default_factory=list)
    enforcement_links: list[EnforcementLink] = field(default_factory=list)
    state_lifecycle: list[StateLifecycleEntry] = field(default_factory=list)
    decision_input_hints: list[DecisionInputHint] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────
# Patterns
# ──────────────────────────────────────────────────────────────

# guard 함수 이름 패턴 (check_*, verify_*, validate_*, is_*, has_*)
_GUARD_NAME_RE = re.compile(
    r"\b((?:check|verify|validate|authenticate|authorize|is_|has_)\w*)\s*\(",
    re.IGNORECASE,
)

# if (guard(...)) or if (!guard(...)) — result used in branch
_IF_GUARD_RE = re.compile(
    r"\bif\s*\(\s*!?\s*((?:check|verify|validate|authenticate|authorize|is_|has_)\w*)\s*\(",
    re.IGNORECASE,
)

# ret = guard(...) / result = guard(...)
_ASSIGN_GUARD_RE = re.compile(
    r"\b\w+\s*=\s*((?:check|verify|validate|authenticate|authorize|is_|has_)\w*)\s*\(",
    re.IGNORECASE,
)

# state flag assignments: verified = true/false, authenticated = true/false
_STATE_ASSIGN_RE = re.compile(
    r"\b(verified|authenticated|authorized|trusted|session_valid|is_valid|auth_ok)\s*"
    r"[=!]=?\s*(true|false|1|0|NULL|nullptr)",
    re.IGNORECASE,
)

# action function calls (used for enforcement link detection)
_ACTION_CALL_RE = re.compile(
    r"\b(install|write|flash|activate|apply|execute|run|commit|"
    r"delete|grant|admin|elevate|send|deploy|update|store|persist)\w*\s*\(",
    re.IGNORECASE,
)

# external input hints
_EXTERNAL_TOKENS = frozenset([
    "buf", "buffer", "input", "data", "pkg", "package", "payload",
    "msg", "message", "request", "req", "user", "token", "param",
    "argv", "getenv", "recv", "read",
])


# ──────────────────────────────────────────────────────────────
# Extractor
# ──────────────────────────────────────────────────────────────

class PrimitivesExtractor:
    """
    주어진 함수 본문 텍스트에서 structural reasoning primitives를 추출한다.
    모든 결과는 결정론적(regex-based)이며 heuristic 플래그가 붙는다.
    """

    def extract(self, function_id: str, body: str) -> FunctionPrimitives:
        lines = body.splitlines()
        result = FunctionPrimitives(function_id=function_id)

        result.result_use_links = self._extract_result_use(function_id, lines)
        result.state_lifecycle = self._extract_state_lifecycle(function_id, lines)
        result.decision_input_hints = self._extract_decision_inputs(function_id, lines)
        result.enforcement_links = self._extract_enforcement_links(
            function_id, lines, result.result_use_links
        )

        return result

    # ── result-use links ───────────────────────────────────────

    def _extract_result_use(
        self, function_id: str, lines: list[str]
    ) -> list[ResultUseLink]:
        links: list[ResultUseLink] = []
        seen: set[tuple] = set()

        for i, line in enumerate(lines, start=1):
            # Pattern A: if (guard(...)) or if (!guard(...))
            for m in _IF_GUARD_RE.finditer(line):
                key = (function_id, m.group(1), i, "if_guard")
                if key not in seen:
                    seen.add(key)
                    links.append(ResultUseLink(
                        function_id=function_id,
                        guard_name=m.group(1),
                        pattern="if_guard",
                        line=i,
                    ))

            # Pattern B: ret = guard(...)  followed by if (ret)
            for m in _ASSIGN_GUARD_RE.finditer(line):
                key = (function_id, m.group(1), i, "assign_then_branch")
                if key not in seen:
                    seen.add(key)
                    links.append(ResultUseLink(
                        function_id=function_id,
                        guard_name=m.group(1),
                        pattern="assign_then_branch",
                        line=i,
                    ))

        return sorted(links, key=lambda l: l.line)

    # ── enforcement links ──────────────────────────────────────

    def _extract_enforcement_links(
        self,
        function_id: str,
        lines: list[str],
        result_use_links: list[ResultUseLink],
    ) -> list[EnforcementLink]:
        """
        guard가 result-used 되어 있고, 같은 함수에 action call이 있으면
        enforcement link 후보로 기록한다.
        guard_line < action_line 인 경우만 (선행 검사 패턴).
        """
        links: list[EnforcementLink] = []
        guard_used_lines = {rul.guard_name: rul.line for rul in result_use_links}

        action_calls: list[tuple[str, int]] = []
        for i, line in enumerate(lines, start=1):
            for m in _ACTION_CALL_RE.finditer(line):
                action_calls.append((m.group(0).rstrip("("), i))

        for guard_name, guard_line in guard_used_lines.items():
            for action_name, action_line in action_calls:
                if guard_line < action_line:
                    links.append(EnforcementLink(
                        function_id=function_id,
                        guard_name=guard_name,
                        action_name=action_name,
                        guard_line=guard_line,
                        action_line=action_line,
                        guard_result_used=True,
                    ))

        return sorted(links, key=lambda l: (l.guard_line, l.action_line))

    # ── state lifecycle ────────────────────────────────────────

    def _extract_state_lifecycle(
        self, function_id: str, lines: list[str]
    ) -> list[StateLifecycleEntry]:
        entries: list[StateLifecycleEntry] = []
        seen: set[tuple] = set()

        for i, line in enumerate(lines, start=1):
            for m in _STATE_ASSIGN_RE.finditer(line):
                flag = m.group(1).lower()
                val_raw = m.group(2).lower()
                val = "true" if val_raw in {"true", "1"} else "false"
                key = (function_id, flag, i)
                if key not in seen:
                    seen.add(key)
                    entries.append(StateLifecycleEntry(
                        function_id=function_id,
                        flag_name=flag,
                        assigned_value=val,
                        line=i,
                    ))

        return sorted(entries, key=lambda e: e.line)

    # ── decision input hints ───────────────────────────────────

    def _extract_decision_inputs(
        self, function_id: str, lines: list[str]
    ) -> list[DecisionInputHint]:
        hints: list[DecisionInputHint] = []
        seen: set[tuple] = set()

        for i, line in enumerate(lines, start=1):
            for m in _GUARD_NAME_RE.finditer(line):
                guard_name = m.group(1)
                # heuristically extract first argument token
                rest = line[m.end():]
                arg_token = rest.split(")")[0].split(",")[0].strip()
                arg_token = re.sub(r"[&*]", "", arg_token).strip()

                source_hint = "unknown"
                if any(t in arg_token.lower() for t in _EXTERNAL_TOKENS):
                    source_hint = "external"
                elif any(kw in arg_token.lower() for kw in
                         ["session", "state", "header", "ctx", "context", "self"]):
                    source_hint = "internal_state"

                key = (function_id, guard_name, arg_token, i)
                if key not in seen:
                    seen.add(key)
                    hints.append(DecisionInputHint(
                        function_id=function_id,
                        guard_name=guard_name,
                        arg_token=arg_token,
                        source_hint=source_hint,
                        line=i,
                    ))

        return sorted(hints, key=lambda h: h.line)


# ──────────────────────────────────────────────────────────────
# Serialization helpers
# ──────────────────────────────────────────────────────────────

def primitives_to_dict(p: FunctionPrimitives) -> dict:
    return {
        "function_id": p.function_id,
        "result_use_links": [
            {
                "guard_name": r.guard_name,
                "pattern": r.pattern,
                "line": r.line,
                "heuristic": r.heuristic,
                "confidence": r.confidence,
            }
            for r in p.result_use_links
        ],
        "enforcement_links": [
            {
                "guard_name": e.guard_name,
                "action_name": e.action_name,
                "guard_line": e.guard_line,
                "action_line": e.action_line,
                "guard_result_used": e.guard_result_used,
                "heuristic": e.heuristic,
                "confidence": e.confidence,
            }
            for e in p.enforcement_links
        ],
        "state_lifecycle": [
            {
                "flag_name": s.flag_name,
                "assigned_value": s.assigned_value,
                "line": s.line,
                "heuristic": s.heuristic,
            }
            for s in p.state_lifecycle
        ],
        "decision_input_hints": [
            {
                "guard_name": d.guard_name,
                "arg_token": d.arg_token,
                "source_hint": d.source_hint,
                "line": d.line,
                "heuristic": d.heuristic,
            }
            for d in p.decision_input_hints
        ],
    }
