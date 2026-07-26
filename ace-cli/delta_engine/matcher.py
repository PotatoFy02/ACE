"""
RPM -> GPM fuzzy name matcher.
Returns MatchMethod.FUZZY_NAME if confident, AMBIGUOUS if not.
Never forces a wrong pairing.
"""

from schemas.models import RPM, GPM, MatchMethod


def _score(rpm_name: str, role_name: str) -> int:
    """
    Simple token overlap score.
    "sample-lambda" vs "sample-lambda-role" -> 2 tokens match -> score 2
    """
    rpm_tokens = set(rpm_name.lower().replace("_", "-").split("-"))
    role_tokens = set(role_name.lower().replace("_", "-").split("-"))
    # Remove noise tokens that appear in every role name
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
    """
    if not gpms:
        return (None, MatchMethod.AMBIGUOUS)

    if len(gpms) == 1:
        return (gpms[0], MatchMethod.FUZZY_NAME)

    scores = [(gpm, _score(rpm.service_name, gpm.role_name)) for gpm in gpms]
    scores.sort(key=lambda x: x[1], reverse=True)

    best_score = scores[0][1]
    best_gpm = scores[0][0]

    # Ambiguous if top score is 0 or two roles tie
    if best_score == 0:
        return (None, MatchMethod.AMBIGUOUS)
    if len(scores) > 1 and scores[1][1] == best_score:
        return (None, MatchMethod.AMBIGUOUS)

    return (best_gpm, MatchMethod.FUZZY_NAME)