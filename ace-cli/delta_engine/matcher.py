"""
RPM -> GPM fuzzy name matcher.
Checks ace-manifest.yaml first, fuzzy match as fallback.
Returns MatchMethod.MANIFEST, FUZZY_NAME, or AMBIGUOUS.
Never forces a wrong pairing.
"""

from schemas.models import RPM, GPM, MatchMethod

MIN_SCORE = 1


def _score(rpm_name: str, role_name: str) -> int:
    rpm_tokens = set(rpm_name.lower().replace("_", "-").split("-"))
    role_tokens = set(role_name.lower().replace("_", "-").split("-"))
    noise = {"role", "iam", "lambda", "function", "prod", "dev", "staging"}
    rpm_tokens -= noise
    role_tokens -= noise
    if not rpm_tokens:
        return 0
    return len(rpm_tokens & role_tokens)


def match_rpm_to_gpm(
    rpm: RPM,
    gpms: list[GPM],
    manifest: dict[str, str] | None = None,
) -> tuple[GPM | None, MatchMethod]:
    """
    Matches one RPM to the best GPM.
    Checks manifest first, fuzzy match as fallback.
    Returns (matched_gpm, match_method).
    Returns (None, AMBIGUOUS) if no confident match found.
    """
    if not gpms:
        return (None, MatchMethod.AMBIGUOUS)

    # Step 1: manifest lookup — explicit always wins
    if manifest:
        role_arn = manifest.get(rpm.service_name)
        if role_arn:
            for gpm in gpms:
                if gpm.role_arn == role_arn:
                    return (gpm, MatchMethod.MANIFEST)
            # Manifest entry exists but role_arn not found in GPMs
            # Don't fall through to fuzzy — manifest is authoritative
            return (None, MatchMethod.AMBIGUOUS)

    # Step 2: fuzzy match fallback
    scores = [(gpm, _score(rpm.service_name, gpm.role_name)) for gpm in gpms]
    scores.sort(key=lambda x: x[1], reverse=True)

    best_score = scores[0][1]
    best_gpm = scores[0][0]

    if best_score < MIN_SCORE:
        return (None, MatchMethod.AMBIGUOUS)

    if len(scores) > 1 and scores[1][1] == best_score:
        return (None, MatchMethod.AMBIGUOUS)

    return (best_gpm, MatchMethod.FUZZY_NAME)