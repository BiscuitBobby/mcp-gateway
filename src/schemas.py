from __future__ import annotations
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, model_validator

# ── Enums ──────────────────────────────────────────────────────

AttackType = Literal[
    "prompt_injection",
    "sensitive_information_disclosure",
    "misinformation",
    "improper_output_handling",
    "data_exfiltration",
    "excessive_agency",
    "rag_poisoning",
    "tool_misuse",
]

Surface = Literal["ui", "tool", "rag"]

Severity = Literal["critical", "high", "medium", "low", "info"]

RiskLevel = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

StageStatus = Literal["running", "done", "error"]

EventType = Literal[
    "recon.find_chat",
    "recon.map_interface",
    "recon.profile",
    "recon.vuln_analysis",
    "generate.payloads",
    "attack.start",
    "attack.prompt",
    "attack.response",
    "attack.analysis",
    "attack.result",
    "run.start",
    "run.done",
    "run.error",
]

MutationStrategy = Literal[
    "semantic",
    "obfuscation",
    "unicode",
    "chain",
    "context_poisoning",
]


# ── Input ──────────────────────────────────────────────────────


class AttackInput(BaseModel):
    attack_type: AttackType
    surface: Surface
    payload: str = Field(min_length=1)
    mutation_level: int = Field(default=0, ge=0, le=5)
    mutation_strategy: Optional[MutationStrategy] = None
    context: Optional[str] = None

    @model_validator(mode="after")
    def mutation_strategy_required_if_mutating(self):
        if self.mutation_level > 0 and self.mutation_strategy is None:
            raise ValueError("mutation_strategy is required when mutation_level > 0")
        return self


# ── Plan ───────────────────────────────────────────────────────


class AttackPlan(BaseModel):
    attacks: list[AttackInput]


# ── Output ─────────────────────────────────────────────────────


class AttackResult(BaseModel):
    attack_type: AttackType
    surface: Surface
    payload: str
    response: str
    success: bool
    severity: Optional[Severity] = None
    evidence: Optional[str] = None
    notes: Optional[str] = None


# ── Vulnerability ──────────────────────────────────────────────


class Vulnerability(BaseModel):
    vuln_type: AttackType
    severity: Severity
    payload: str
    evidence: str
    surface: Surface
    fix: Optional[str] = None


# ── Interface Map ──────────────────────────────────────────────


class InterfaceMap(BaseModel):
    chat_inputs: list[str] = []
    file_uploads: list[str] = []
    supported_modalities: list[Literal["text", "image", "audio", "document", "url"]] = [
        "text"
    ]
    buttons: list[str] = []
    api_endpoints: list[str] = []
    notes: Optional[str] = None


# ── Agent Profile ──────────────────────────────────────────────


class AgentProfile(BaseModel):
    agent_type: str
    agent_description: str
    capabilities: list[str] = []

    has_tools: bool
    tools: list[str] = []

    has_restrictions: bool
    restrictions: list[str] = []

    has_internet_access: bool
    external_data_sources: list[str] = []

    system_prompt_revealed: bool
    system_prompt_style: str
    system_prompt_excerpt: Optional[str] = None

    knowledge_cutoff: Optional[str] = None
    training_data_sources: list[str] = []

    use_case: str
    target_users: str
    value_proposition: str

    has_rag: bool
    data_stores: list[str] = []
    rag_description: Optional[str] = None

    can_execute_code: bool
    code_environments: list[str] = []

    processes_files: bool
    file_operations: list[str] = []

    notes: Optional[str] = None


# ── Tool Discovery ────────────────────────────────────────────


class DiscoveredTool(BaseModel):
    name: str
    description: str
    risk_notes: Optional[str] = None


class DiscoveredDatasource(BaseModel):
    name: str
    type: str  # e.g. "database", "api", "file_system", "vector_store", "web"
    description: str
    risk_notes: Optional[str] = None


class ToolDiscoveryProfile(BaseModel):
    tools: list[DiscoveredTool] = []
    datasources: list[DiscoveredDatasource] = []
    can_execute_code: bool = False
    can_access_internet: bool = False
    can_read_files: bool = False
    can_write_files: bool = False
    can_call_apis: bool = False
    raw_transcript: Optional[str] = None
    notes: Optional[str] = None


class FullProfile(BaseModel):
    """Unified profile: AgentProfile + ToolDiscoveryProfile in one pass."""

    # ── AgentProfile fields ──
    agent_type: str = ""
    agent_description: str = ""
    capabilities: list[str] = []

    has_tools: bool = False
    has_restrictions: bool = False
    restrictions: list[str] = []

    has_internet_access: bool = False
    external_data_sources: list[str] = []

    system_prompt_revealed: bool = False
    system_prompt_style: str = ""
    system_prompt_excerpt: Optional[str] = None

    knowledge_cutoff: Optional[str] = None
    training_data_sources: list[str] = []

    use_case: str = ""
    target_users: str = ""
    value_proposition: str = ""

    has_rag: bool = False
    data_stores: list[str] = []
    rag_description: Optional[str] = None

    processes_files: bool = False
    file_operations: list[str] = []

    # ── ToolDiscoveryProfile fields ──
    tools: list[DiscoveredTool] = []
    datasources: list[DiscoveredDatasource] = []
    can_execute_code: bool = False
    can_access_internet: bool = False
    can_read_files: bool = False
    can_write_files: bool = False
    can_call_apis: bool = False
    code_environments: list[str] = []
    notes: Optional[str] = None

    def to_agent_profile(self) -> "AgentProfile":
        return AgentProfile(
            agent_type=self.agent_type,
            agent_description=self.agent_description,
            capabilities=self.capabilities,
            has_tools=self.has_tools or len(self.tools) > 0,
            tools=[t.name for t in self.tools],
            has_restrictions=self.has_restrictions,
            restrictions=self.restrictions,
            has_internet_access=self.has_internet_access or self.can_access_internet,
            external_data_sources=self.external_data_sources,
            system_prompt_revealed=self.system_prompt_revealed,
            system_prompt_style=self.system_prompt_style,
            system_prompt_excerpt=self.system_prompt_excerpt,
            knowledge_cutoff=self.knowledge_cutoff,
            training_data_sources=self.training_data_sources,
            use_case=self.use_case,
            target_users=self.target_users,
            value_proposition=self.value_proposition,
            has_rag=self.has_rag,
            data_stores=self.data_stores,
            rag_description=self.rag_description,
            can_execute_code=self.can_execute_code,
            code_environments=self.code_environments,
            processes_files=self.processes_files,
            file_operations=self.file_operations,
            notes=self.notes,
        )

    def to_tool_discovery(self) -> "ToolDiscoveryProfile":
        return ToolDiscoveryProfile(
            tools=self.tools,
            datasources=self.datasources,
            can_execute_code=self.can_execute_code,
            can_access_internet=self.can_access_internet,
            can_read_files=self.can_read_files,
            can_write_files=self.can_write_files,
            can_call_apis=self.can_call_apis,
            notes=self.notes,
        )


# goal


class GoalRequest(BaseModel):
    goal: str
    policies: list[str] = []
    profile: Optional[AgentProfile] = None
    interface: Optional[InterfaceMap] = None
    vuln_report: Optional[VulnerabilityReport] = None
    max_iterations: int = 20


# ── Reasoning ──────────────────────────────────────────────────


class ReasoningAnalysis(BaseModel):
    user_intent: str
    model_behavior: str
    evidence: str
    violation: bool


class ReasoningResult(BaseModel):
    analysis: ReasoningAnalysis
    detected: bool
    risk_level: RiskLevel
    reasoning: str
    confidence: float  # 0.0 → 1.0


# ── Base Probe Result ──────────────────────────────────────────


class BaseProbeResult(BaseModel):
    type: str
    timestamp: str
    probe: str
    category: str
    index: int
    technique: str
    prompt: str
    response: Optional[str] = None
    analysis: Optional[ReasoningResult] = None


# ── Probe Result Variants ──────────────────────────────────────


class PromptInjectionResult(BaseProbeResult):
    type: Literal["prompt_injection_attack"] = "prompt_injection_attack"
    probe: Literal["prompt_injection"] = "prompt_injection"
    category: Literal["LLM01: Prompt Injection"] = "LLM01: Prompt Injection"


class SensitiveInformationDisclosureResult(BaseProbeResult):
    type: Literal["sensitive_information_disclosure_attack"] = (
        "sensitive_information_disclosure_attack"
    )
    probe: Literal["sensitive_information_disclosure"] = (
        "sensitive_information_disclosure"
    )
    category: Literal["LLM02: Sensitive Information Disclosure"] = (
        "LLM02: Sensitive Information Disclosure"
    )


class MisinformationResult(BaseProbeResult):
    type: Literal["misinformation_attack"] = "misinformation_attack"
    probe: Literal["misinformation"] = "misinformation"
    category: Literal["LLM04: Misinformation"] = "LLM04: Misinformation"
    false_claim: Optional[str] = ""


class OutputIntegrityAnalysis(BaseModel):
    contains_script_tag: bool
    contains_html_injection: bool
    contains_json_object: bool
    contains_tool_like_structure: bool
    malformed_json_detected: bool
    unexpected_fields_detected: bool


class ImproperOutputHandlingResult(BaseProbeResult):
    type: Literal["improper_output_handling_attack"] = "improper_output_handling_attack"
    probe: Literal["improper_output_handling"] = "improper_output_handling"
    category: Literal["LLM02: Insecure Output Handling"] = (
        "LLM02: Insecure Output Handling"
    )
    integrity_analysis: OutputIntegrityAnalysis
    violation_detected: bool


class DataExfiltrationResult(BaseProbeResult):
    type: Literal["data_exfiltration_attack"] = "data_exfiltration_attack"
    probe: Literal["data_exfiltration"] = "data_exfiltration"
    category: Literal["LLM06: Sensitive Information Disclosure"] = (
        "LLM06: Sensitive Information Disclosure"
    )


class ExcessiveAgencyResult(BaseProbeResult):
    type: Literal["excessive_agency_attack"] = "excessive_agency_attack"
    probe: Literal["excessive_agency"] = "excessive_agency"
    category: Literal["LLM08: Excessive Agency"] = "LLM08: Excessive Agency"


class ToolAbuseResult(BaseProbeResult):
    type: Literal["tool_abuse_attack"] = "tool_abuse_attack"
    probe: Literal["tool_abuse"] = "tool_abuse"
    category: Literal["LLM07: Tool Abuse"] = "LLM07: Tool Abuse"


class RagPoisoningResult(BaseProbeResult):
    type: Literal["rag_poisoning_attack"] = "rag_poisoning_attack"
    probe: Literal["rag_poisoning"] = "rag_poisoning"
    category: Literal["LLM09: Over-reliance (Indirect via RAG)"] = (
        "LLM09: Over-reliance (Indirect via RAG)"
    )


class ToolMisuseResult(BaseProbeResult):
    type: Literal["tool_misuse_attack"] = "tool_misuse_attack"
    probe: Literal["tool_misuse"] = "tool_misuse"
    category: Literal["LLM08: Excessive Agency"] = "LLM08: Excessive Agency"
    target_tool: Optional[str] = None
    expected_behavior: Optional[str] = None
    risk_level: Optional[RiskLevel] = None
    error: Optional[str] = None


# ── Attack Record (persisted to results.jsonl) ─────────────────


class AttackRecord(BaseModel):
    timestamp: str
    run_id: str
    attack: str
    technique: str
    prompt: str
    response: Optional[str] = None
    detected: Optional[bool] = None
    risk_level: Optional[str] = None
    reasoning: Optional[str] = None


# ── Structured Log Entry (persisted to run.jsonl) ──────────────


class LogEntry(BaseModel):
    event_type: EventType
    attack_id: str
    step_id: str
    timestamp: str
    input: Optional[Any] = None
    output: Optional[Any] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PotentialVulnerability(BaseModel):
    probe: str
    finding: str
    severity: str
    evidence: str
    attack_surface: str
    trust_boundary_violation: str


class VulnerabilityReport(BaseModel):
    potential_vulnerabilities: list[PotentialVulnerability]
    severity_summary: dict[str, int]
    recommended_probe_order: list[str]


class AnalyseRequest(BaseModel):
    profile: Optional[AgentProfile] = None
    interface: Optional[InterfaceMap] = None
