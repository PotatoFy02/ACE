"""
Delta Engine — computes P_excess = P_granted - P_required.
One DeltaResult per role. Severity assigned here, never in parsers.
"""

from schemas.models import (
    RPM, GPM, DeltaResult, DeltaEntry,
    OverPrivilegeType, MatchMethod, Confidence
)
from delta_engine.severity_map import get_severity
from delta_engine.matcher import match_rpm_to_gpm


def _has_low_confidence(rpm: RPM) -> bool:
    return any(c.confidence == Confidence.LOW for c in rpm.sdk_calls)


def _get_required_actions(rpm: RPM) -> set[str]:
    return {
        call.action_iam
        for call in rpm.sdk_calls
        if call.action_iam != "unknown:unknown"
    }


def _get_granted_actions(gpm: GPM) -> set[str]:
    actions = set()
    for policy in gpm.attached_policies:
        for stmt in policy.statements:
            if stmt.effect == "Allow":
                actions.update(stmt.actions_expanded)
    return actions


def _get_resource_scope_violations(rpm: RPM, gpm: GPM) -> list[DeltaEntry]:
    entries = []
    rpm_non_wildcard = {
        call.action_iam
        for call in rpm.sdk_calls
        if not call.resources_wildcard and call.action_iam != "unknown:unknown"
    }

    for policy in gpm.attached_policies:
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if not stmt.resources_wildcard:
                continue
            for action in stmt.actions_expanded:
                if action in rpm_non_wildcard:
                    entries.append(DeltaEntry(
                        action_iam=action,
                        over_privilege_type=OverPrivilegeType.RESOURCE,
                        severity=get_severity(action),
                        confidence=Confidence.MEDIUM,
                        reason=(
                            f"{action} granted on wildcard resource '*' but "
                            f"code only uses it on a specific resource"
                        )
                    ))

    return entries


def compute_delta(
    rpm: RPM,
    gpms: list[GPM],
    manifest: dict[str, str] | None = None,
) -> DeltaResult:
    """
    Main entry point. Pairs one RPM with one GPM, computes P_excess.
    Checks manifest first, fuzzy match as fallback.
    """
    gpm, match_method = match_rpm_to_gpm(rpm, gpms, manifest)

    if gpm is None or match_method == MatchMethod.AMBIGUOUS:
        return DeltaResult(
            role_arn="unknown",
            role_name="unknown",
            commit_sha=rpm.commit_sha,
            matched_by=MatchMethod.AMBIGUOUS,
            rpm_service_name=rpm.service_name,
            excess=[],
            requires_human_review=True,
            patch_risk="yellow"
        )

    required = _get_required_actions(rpm)
    granted = _get_granted_actions(gpm)
    excess_actions = granted - required

    entries: list[DeltaEntry] = []

    for action in excess_actions:
        entries.append(DeltaEntry(
            action_iam=action,
            over_privilege_type=OverPrivilegeType.ACTION,
            severity=get_severity(action),
            confidence=Confidence.HIGH,
            reason=f"{action} is granted but never called by {rpm.service_name}"
        ))

    entries.extend(_get_resource_scope_violations(rpm, gpm))

    requires_review = _has_low_confidence(rpm) or match_method == MatchMethod.AMBIGUOUS

    if not entries:
        patch_risk = "green"
    elif requires_review:
        patch_risk = "yellow"
    else:
        patch_risk = "red"

    return DeltaResult(
        role_arn=gpm.role_arn,
        role_name=gpm.role_name,
        commit_sha=rpm.commit_sha,
        matched_by=match_method,
        rpm_service_name=rpm.service_name,
        excess=entries,
        requires_human_review=requires_review,
        patch_risk=patch_risk
    )


def compute_all_deltas(
    rpm: RPM,
    gpms: list[GPM],
    manifest: dict[str, str] | None = None,
) -> list[DeltaResult]:
    """
    Computes one DeltaResult per GPM role.
    Each role is evaluated independently against the same RPM.
    """
    return [compute_delta(rpm, [gpm], manifest) for gpm in gpms]