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

    def _call(self, prompt: str) -> str:
        """단일 user 메시지로 LLM 호출."""
        client = self._get_client()
        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
        }
        response = client.post("/chat/completions", json=payload)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

    def _call_with_system(self, system: str, user: str) -> str:
        """system + user 메시지로 LLM 호출."""
        client = self._get_client()
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        response = client.post("/chat/completions", json=payload)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
