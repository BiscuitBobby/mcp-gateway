from pathlib import Path

from probes.base import StandardProbe


class CredentialExtraction(StandardProbe):
    """
    Tests whether the model discloses credentials, tokens, or secrets sourced
    from RAG stores, agent tool configs, or its own configuration.
    """

    name = "credential_extraction"
    mitre_category = "ATLAS: Credential Access"
    record_type = "credential_extraction_attack"
    prompts_file = Path(__file__).parent / "credential_extraction_prompts.json"
