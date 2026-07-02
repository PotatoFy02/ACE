from fastapi import HTTPException

INJECTION_PATTERNS = [
    "ignore previous", "ignore all previous", "ignore above",
    "system prompt", "you are now", "disregard", "new instructions",
    "act as", "jailbreak", "developer mode",
]


def validate_description(text: str) -> str:
    t = (text or "").strip()
    if len(t) < 15:
        raise HTTPException(400, "Description too short to analyze (min 15 chars).")
    if len(t) > 8000:
        raise HTTPException(400, "Description too long (max 8000 chars).")
    lowered = t.lower()
    for pat in INJECTION_PATTERNS:
        if pat in lowered:
            raise HTTPException(400, "Input rejected.")
    return t


def validate_name(name: str) -> str:
    n = (name or "Untitled").strip()[:200]
    n = "".join(c for c in n if ord(c) >= 32)
    return n or "Untitled"