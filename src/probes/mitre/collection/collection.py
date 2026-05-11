from pathlib import Path

from probes.base import StandardProbe


class Collection(StandardProbe):
    """
    Tests whether the model surfaces or facilitates extraction of data
    from AI services, RAG stores, or agent tools.
    """

    name = "collection"
    mitre_category = "ATLAS: Collection"
    record_type = "collection_attack"
    prompts_file = Path(__file__).parent / "collection_prompts.json"
