"""
LLM Interpreter — candidate 구조적 해석 (탐지가 아님).

PLAN.md §14: LLM은 candidate를 interpret하는 역할만 한다.
- exploitability 판단 금지
- 구조적 의미 설명에 집중
- LLM disabled 시 placeholder 반환
"""

from __future__ import annotations

from dataclasses import dataclass

from check_me.llm.client import LLMClient


_SYSTEM_PROMPT = """\
You are a security analysis assistant helping a human reviewer understand \
structural security candidates from a static analysis tool.

Rules:
1. These are CANDIDATES, not confirmed vulnerabilities.
2. Do NOT claim the candidate is exploitable, proven, or a confirmed vulnerability.
3. Describe what the structural pattern suggests and why a human reviewer \
   should investigate it.
4. Be concise (3-5 sentences max).
5. Use hedged language: "structurally suggests", "may indicate", \
   "worth investigating", "not confirmed".
"""

_USER_TEMPLATE = """\
Candidate:
  id: {candidate_id}
  family: {family}
  state: {state}
  confidence: {confidence}
  claim: {claim}

Evidence:
{evidence_text}

Provide a structural interpretation for a security reviewer.
"""


@dataclass
class Interpretation:
    candidate_id: str
    interpretation: str
    llm_used: bool
    model: str


class CandidateInterpreter:
    def __init__(self, client: LLMClient) -> None:
        self.client = client

    def interpret_all(
        self,
        candidates: list[dict],
        only_active: bool = True,
    ) -> list[Interpretation]:
        """
        candidates 리스트를 받아 각 candidate의 structural interpretation을 반환한다.
        only_active=True면 ACTIVE 상태 candidate만 처리한다.
        """
        results: list[Interpretation] = []
        for c in candidates:
            if only_active and c.get("state") != "ACTIVE":
                results.append(Interpretation(
                    candidate_id=c["candidate_id"],
                    interpretation="[skipped — state is not ACTIVE]",
                    llm_used=False,
                    model="",
                ))
                continue
            results.append(self._interpret_one(c))
        return results

    def _interpret_one(self, candidate: dict) -> Interpretation:
        cid = candidate.get("candidate_id", "unknown")

        if not self.client.is_available():
            return Interpretation(
                candidate_id=cid,
                interpretation=(
                    "[LLM disabled — configure .env to enable interpretation. "
                    f"Candidate state={candidate.get('state')}, "
                    f"confidence={candidate.get('confidence')}]"
                ),
                llm_used=False,
                model="",
            )

        prompt = _USER_TEMPLATE.format(
            candidate_id=cid,
            family=candidate.get("family", candidate.get("rule_id", "unknown")),
            state=candidate.get("state", ""),
            confidence=candidate.get("confidence", ""),
            claim=candidate.get("claim", ""),
            evidence_text=self._format_evidence(candidate.get("evidence", {})),
        )

        try:
            text = self.client._call_with_system(_SYSTEM_PROMPT, prompt)
        except Exception as e:
            text = f"[LLM call failed: {e}]"

        return Interpretation(
            candidate_id=cid,
            interpretation=text,
            llm_used=True,
            model=self.client.config.model,
        )

    @staticmethod
    def _format_evidence(evidence: dict) -> str:
        lines: list[str] = []
        for k, v in evidence.items():
            if v is None:
                continue
            lines.append(f"  {k}: {v}")
        return "\n".join(lines) if lines else "  (none)"
