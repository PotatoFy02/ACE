from fastapi import HTTPException

INJECTION_PATTERNS = [
    "ignore previous", "ignore all previous", "ignore above",
    "system prompt", "you are now", "disregard", "new instructions",
    "act as", "jailbreak", "developer mode",
]

MAX_CHARS = 32000  # Gemini 1.5 flash supports ~1M tokens; 32k chars is safe


def validate_description(text: str) -> str:
    t = (text or "").strip()
    if len(t) < 15:
        raise HTTPException(400, "Description too short to analyze (min 15 chars).")
    lowered = t.lower()
    for pat in INJECTION_PATTERNS:
        if pat in lowered:
            raise HTTPException(400, "Input rejected.")
    # Smart truncation — keep first 24k + last 8k chars
    # First section has resource definitions, last section has outputs/variables
    if len(t) > MAX_CHARS:
        t = t[:24000] + "\n\n[... truncated for analysis ...]\n\n" + t[-8000:]
    return t


def validate_name(name: str) -> str:
    n = (name or "Untitled").strip()[:200]
    n = "".join(c for c in n if ord(c) >= 32)
    return n or "Untitled"