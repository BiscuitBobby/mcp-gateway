import os
from pathlib import Path

import dotenv
from browser_use import ChatOpenAI
from groq import Groq
from openai import AsyncOpenAI

# Load environment variables
dotenv.load_dotenv()

# Validate NVIDIA API key
nvidia_api_key = os.getenv("NVIDIA_API_KEY")
if not nvidia_api_key:
    raise EnvironmentError("NVIDIA_API_KEY is not set")

# ── Model Configuration Constants ───────────────────────────────

BASE_URL = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL = "meta/llama-4-maverick-17b-128e-instruct"
GROQ_MODEL = "qwen/qwen3-32b"

# ── NVIDIA AsyncOpenAI Client (for vulnerability analysis) ──────

vulnerability_client = AsyncOpenAI(
    base_url=BASE_URL,
    api_key=nvidia_api_key,
    max_retries=2,
)

VULNERABILITY_MODEL = NVIDIA_MODEL

# ── Groq Client (for prompt generation and document generation) ──

groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

GROQ_PROMPT_MODEL = GROQ_MODEL
GROQ_DOCUMENT_MODEL = GROQ_MODEL

# ── Browser-use Client (NVIDIA for browser automation) ──────────

# Use src/temp directory for browser storage state
STORAGE_DIR = Path(__file__).parent.parent / "temp"
STORAGE_DIR.mkdir(exist_ok=True)
BROWSER_STORAGE_STATE = str(STORAGE_DIR / "auth.json")

browser_llm = ChatOpenAI(
    base_url=BASE_URL,
    api_key=nvidia_api_key,
    model=NVIDIA_MODEL,
    temperature=0.2,
)
