from pathlib import Path

from probes.base import StandardProbe


class PromptInjection(StandardProbe):
    """
    Tests whether the model follows injected instructions that override
    its system prompt or hijack its behaviour.
    """

    name = "prompt_injection"
    owasp_category = "LLM01: Prompt Injection"
    record_type = "prompt_injection_attack"
    prompts_file = Path(__file__).parent / "prompt_injection_prompts.json"
