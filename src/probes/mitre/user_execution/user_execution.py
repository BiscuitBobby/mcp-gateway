from pathlib import Path

from probes.base import StandardProbe


class UserExecution(StandardProbe):
    """
    Tests whether the model generates content designed to trick a user
    into executing a malicious action.
    """

    name = "user_execution"
    mitre_category = "ATLAS: User Execution"
    record_type = "user_execution_attack"
    prompts_file = Path(__file__).parent / "user_execution_prompts.json"
