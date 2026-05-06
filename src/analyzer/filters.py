from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from dataclasses import dataclass
from typing import Literal, Union
from src.analyzer.models import (
    store,
    make_report,
    get_scan_id,
)
import os

from src.policies.views import GLOBAL_POLICIES, get_policies, load_json

if "GOOGLE_API_KEY" in os.environ:
    model = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=1.0,  # Gemini 3.0+ defaults to 1.0
        max_tokens=None,
        timeout=None,
        max_retries=2,
    )
elif "OPENAI_API_KEY" in os.environ:
    model = ChatOpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        model="meta/llama-4-maverick-17b-128e-instruct",
        temperature=0,
        max_tokens=None,
        timeout=None,
        max_retries=2,
        # api_key="...",
        # base_url="...",
    )
else:
    raise RuntimeError(
        "neither GOOGLE_API_KEY nor OPENAI_API_KEY environment variables set"
    )


# --------------------
# scanning logic
# --------------------
@dataclass
class ScanSuccess:
    result: dict


@dataclass
class ScanFailure:
    error: str


def dynamic_scan(
    logger, traceparent: str, text_type: Literal["input", "output"], text, server_alias
) -> Union[ScanSuccess, ScanFailure]:
    scan_id = get_scan_id(traceparent)
    text = str(text)

    policies = get_policies(server_alias)["policies"]
    print(f"Policies: {policies}")

    if not policies:
        print("No policies configured, skipping scan")
        return ScanSuccess(result={"threat": False})

    selected_policies = {
        policy: load_json(GLOBAL_POLICIES, {})[policy] for policy in policies
    }

    model_with_structure = model.with_structured_output(make_report(selected_policies))

    messages = [
        (
            "system",
            f"You are an auditing assistant that checks for these threats:\n{selected_policies}.",
        ),
        ("human", text),
    ]

    try:
        ai_msg = model_with_structure.invoke(messages)
        store(scan_id, text_type, text, {text_type: ai_msg.model_dump()})
        logger.info(f"scan:{ai_msg}")

        if ai_msg.threat:
            return ScanFailure(error=f"Disallowed (category: {ai_msg})")

        return ScanSuccess(result=ai_msg)
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return ScanFailure(error=str(e))
