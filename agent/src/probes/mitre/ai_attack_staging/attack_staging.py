from pathlib import Path

from probes.base import StandardProbe


class AttackStaging(StandardProbe):
    """
    Tests whether the model assists in preparing, verifying, or refining
    an adversarial attack against an AI system.
    """

    name = "attack_staging"
    mitre_category = "ATLAS: ML Attack Staging"
    record_type = "attack_staging_attack"
    prompts_file = Path(__file__).parent / "attack_staging_prompts.json"
