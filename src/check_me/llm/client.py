"""
LLM 클라이언트 — 사내 내부 서버 연동.
현재는 해석기(interpreter) 역할만 담당. 탐지기로 쓰지 않는다.
설정은 .env의 CHECK_ME_LLM_* 환경변수에서 로드한다.
"""

from __future__ import annotations

from check_me.config import LLMConfig


class LLMClient:
    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self._client = None

    def is_available(self) -> bool:
        return (
            self.config.enabled
            and bool(self.config.base_url)
            and bool(self.config.api_key)
        )

    def _get_client(self):
        if self._client is not None:
            return self._client

        try:
            import httpx
        except ImportError as e:
            raise RuntimeError("httpx is required for LLM client") from e

        self._client = httpx.Client(
            base_url=self.config.base_url,
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            timeout=self.config.timeout,
        )
        return self._client

    def interpret_candidate(self, candidate: dict) -> str:
        """
        후보를 LLM에게 해석 요청한다.
        LLM은 탐지기가 아니라 해석기다 — 후보의 구조적 의미를 설명한다.
        """
        if not self.is_available():
            return "[LLM disabled — set CHECK_ME_LLM_ENABLED=true and configure .env]"

        prompt = self._build_interpretation_prompt(candidate)
        return self._call(prompt)

    def _build_interpretation_prompt(self, candidate: dict) -> str:
        return (
            f"You are a security analysis assistant.\n"
            f"The following is a structural security candidate (NOT a confirmed vulnerability).\n"
            f"Interpret its structural significance without overstating certainty.\n\n"
            f"Candidate:\n{candidate}\n\n"
            f"Provide a concise structural interpretation. "
            f"Do not claim it is exploitable or a proven vulnerability."
        )

    def _call(self, prompt: str) -> str:
        client = self._get_client()
        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
        }
        response = client.post("/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
