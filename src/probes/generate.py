import logging

from probes.prompt_generator import generate_prompts
from probes.probe_configs import get_all_configs

# RAG document generation is unique — keep its direct import
from probes.owasp.rag_poisoning.generate_documents import main as gen_rag_docs

logger = logging.getLogger(__name__)


def generate_all(app_profile=None, interface_map=None, goal=None, vulnerabilities=None):
    summary = {}

    # Generate prompts for every probe via the shared generator
    for name in get_all_configs():
        logger.info("[generate_all] Generating payloads for: %s", name)
        try:
            result = generate_prompts(
                name,
                app_profile=app_profile,
                interface_map=interface_map,
                goal=goal,
                vulnerabilities=vulnerabilities,
            )
            summary[name] = {"status": "ok", "count": len(result) if result else 0}
        except Exception as exc:
            logger.exception("[generate_all] %s failed: %s", name, exc)
            summary[name] = {"status": "error", "error": str(exc)}

    # RAG document generation (unique workflow, not prompt-based)
    logger.info("[generate_all] Generating RAG poisoning documents")
    try:
        result = gen_rag_docs(
            app_profile=app_profile,
            interface_map=interface_map,
            goal=goal,
            vulnerabilities=vulnerabilities,
        )
        summary["rag_poisoning_docs"] = {
            "status": "ok",
            "count": len(result) if result else 0,
        }
    except Exception as exc:
        logger.exception("[generate_all] rag_poisoning_docs failed: %s", exc)
        summary["rag_poisoning_docs"] = {"status": "error", "error": str(exc)}

    return summary
