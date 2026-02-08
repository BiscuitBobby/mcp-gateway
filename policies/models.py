from pydantic import BaseModel
from typing import List, Dict


class PolicyRequest(BaseModel):
    key: str
    policy_name: str


class KeyPoliciesResponse(BaseModel):
    key: str
    policies: List[str]


class GlobalPolicyRequest(BaseModel):
    name: str
    description: str | None = None
