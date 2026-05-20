from pathlib import Path

from probes.base import StandardProbe


class Reconnaissance(StandardProbe):
    """
    Tests whether the model assists in gathering intelligence about a target
    AI system, its users, or its infrastructure.
    """

    name = "reconnaissance"
    mitre_category = "ATLAS: Reconnaissance"
    record_type = "reconnaissance_attack"
    prompts_file = Path(__file__).parent / "reconnaissance_prompts.json"
