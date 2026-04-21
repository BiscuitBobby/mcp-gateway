from abc import ABC, abstractmethod
from typing import Any


class AttackProbe(ABC):
    name: str = "base_probe"
    owasp_category: str = "unknown"

    @abstractmethod
    async def run(self, session, llm, goal: str = "") -> dict[str, Any]:
        pass
