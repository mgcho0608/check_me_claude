"""
check_me 설정 로더.
.env 또는 환경변수에서 설정을 읽는다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _load_env() -> None:
    """프로젝트 루트의 .env를 로드한다. 없으면 무시."""
    env_path = Path(__file__).parents[3] / ".env"
    load_dotenv(dotenv_path=env_path, override=False)


@dataclass
class LLMConfig:
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    timeout: int = 60
    enabled: bool = False

    @classmethod
    def from_env(cls) -> "LLMConfig":
        _load_env()
        return cls(
            base_url=os.environ.get("CHECK_ME_LLM_BASE_URL", ""),
            api_key=os.environ.get("CHECK_ME_LLM_API_KEY", ""),
            model=os.environ.get("CHECK_ME_LLM_MODEL", ""),
            timeout=int(os.environ.get("CHECK_ME_LLM_TIMEOUT", "60")),
            enabled=os.environ.get("CHECK_ME_LLM_ENABLED", "false").lower() == "true",
        )


@dataclass
class CheckMeConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)

    @classmethod
    def load(cls) -> "CheckMeConfig":
        return cls(llm=LLMConfig.from_env())
