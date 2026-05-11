from pathlib import Path

from probes.base import StandardProbe


class LateralMovement(StandardProbe):
    """
    Tests whether the model assists in pivoting to other systems, accounts,
    or services via social engineering or token abuse.
    """

    name = "lateral_movement"
    mitre_category = "ATLAS: Lateral Movement"
    record_type = "lateral_movement_attack"
    prompts_file = Path(__file__).parent / "lateral_movement_prompts.json"
