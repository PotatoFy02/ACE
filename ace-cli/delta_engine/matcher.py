"""
RPM -> GPM fuzzy name matcher.
Returns MatchMethod.FUZZY_NAME if confident, AMBIGUOUS if not.
Never forces a wrong pairing.
"""

from schemas.models import RPM, GPM, MatchMethod

# Minimum token overlap score to trust a match.
# Score of 0 = no shared tokens after noise removal = AMBIGUOUS.
# Score of 1 = at least one meaningful token shared = FUZZY_NAME.
MIN_SCORE = 1


def _score(rpm_name: str, role_name: str) -> int:
    """
    Simple token overlap score.
    "sample-lambda" vs "sample-lambda-role" -> 2 tokens match -> score 2
    """
    rpm_tokens = set(rpm_name.lower().replace("_", "-").split("-"))
    role_tokens = set(role_name.lower().replace("_", "-").split("-"))
    noise = {"role", "iam", "lambda", "function", "prod", "dev", "staging"}
    rpm_tokens -= noise
    role_tokens -= noise
    if not rpm_tokens:
        return 0
    return len(rpm_tokens & role_tokens)


def match_rpm_to_gpm(rpm: RPM, gpms: list[GPM]) -> tuple[GPM | None, MatchMethod]:
    """
    Matches one RPM to the best GPM from a list.
    Returns (matched_gpm, match_method).
    Returns (None, AMBIGUOUS) if no confident match found.
    Single GPM is NOT auto-trusted — must still score above MIN_SCORE.
    """
    if not gpms:
        return (None, MatchMethod.AMBIGUOUS)

    scores = [(gpm, _score(rpm.service_name, gpm.role_name)) for gpm in gpms]
    scores.sort(key=lambda x: x[1], reverse=True)

    best_score = scores[0][1]
    best_gpm = scores[0][0]

    # No meaningful token overlap — cannot trust any pairing
    if best_score < MIN_SCORE:
        return (None, MatchMethod.AMBIGUOUS)

    # Two roles tie — cannot pick safely
    if len(scores) > 1 and scores[1][1] == best_score:
        return (None, MatchMethod.AMBIGUOUS)

    return (best_gpm, MatchMethod.FUZZY_NAME)