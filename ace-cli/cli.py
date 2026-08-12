# -*- coding: utf-8 -*-
# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE - Automated Cybersecurity Engine
# Unauthorized commercial use prohibited. See LICENSE.
"""
ace-cli - main entry point.
Usage:
  python cli.py analyze --file lambda.py --tf roles.tf
  python cli.py analyze --file lambda.py --tf roles.tf --manifest ace-manifest.yaml
  python cli.py sweep --repo PotatoFy02/ACE
"""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import boto3
# Add ACE root to path so sweeper/ and models_db resolve
sys.path.insert(0, str(Path(__file__).parent.parent))
from parsers.rpm_engine import parse_python_file
from parsers.gpm_engine import parse_terraform_file
from delta_engine.engine import compute_all_deltas
from delta_engine.manifest_loader import load_manifest
from patch_generator.generator import generate_patch
from sweeper.engine import process_role, advance_cooling_off
from sweeper.db import get_roles_by_state


# -- Audit helpers (no-op if ACE_DATABASE_URL not set) ------------------------

def _audit_available() -> bool:
    return bool(os.environ.get("ACE_DATABASE_URL"))


async def _write_audit(rpm, deltas, patch_results):
    from audit.store import insert_scan, insert_patch, log_event
    from audit.models import ScanRecord, PatchRecord, AuditEvent

    total_calls = len(rpm.sdk_calls) if rpm else 0
    unknown_count = sum(
        1 for c in rpm.sdk_calls if c.action_iam == "unknown:unknown"
    ) if rpm else 0
    unknown_rate = round(unknown_count / total_calls * 100, 2) if total_calls else 0.0
    any_blocked = any(getattr(d, "patch_blocked", False) for d in deltas)

    scan = ScanRecord(
        repo=os.environ.get("GITHUB_REPOSITORY", "local"),
        commit_sha=os.environ.get("GITHUB_SHA", "local"),
        branch=os.environ.get("GITHUB_REF_NAME"),
        actor=os.environ.get("GITHUB_ACTOR"),
        unknown_rate=unknown_rate,
        patch_blocked=any_blocked,
        file_count=1,
        sdk_call_count=total_calls,
    )
    scan_id = await insert_scan(scan)

    await log_event(AuditEvent(
        event_type="scan_completed",
        actor=scan.actor,
        scan_id=scan_id,
        metadata={
            "unknown_rate": unknown_rate,
            "sdk_call_count": total_calls,
        },
    ))

    for delta, patch in zip(deltas, patch_results):
        patch_record = PatchRecord(
            scan_id=scan_id,
            role_arn=delta.role_name,
            risk_level=delta.patch_risk,
            actions_removed=[e.action_iam for e in delta.excess] if patch else [],
            actions_added=[],
            patch_blocked=getattr(delta, "patch_blocked", False),
            block_reason=getattr(delta, "review_reason", None),
        )
        patch_id = await insert_patch(patch_record)

        event_type = "patch_blocked" if patch_record.patch_blocked else "patch_generated"
        await log_event(AuditEvent(
            event_type=event_type,
            actor=scan.actor,
            scan_id=scan_id,
            patch_id=patch_id,
            metadata={"role_arn": delta.role_name},
        ))


def _fire_audit(rpm, deltas, patch_results):
    """Fire audit writes without blocking CLI output."""
    if not _audit_available():
        return
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_write_audit(rpm, deltas, patch_results))
    except RuntimeError:
        try:
            asyncio.run(_write_audit(rpm, deltas, patch_results))
        except Exception as e:
            print(f"[audit] WARNING: {e}", file=sys.stderr)


# -- Commands -----------------------------------------------------------------

def cmd_analyze(args):
    py_file = Path(args.file)
    tf_file = Path(args.tf)

    if not py_file.exists():
        print(f"ERROR: Python file not found: {py_file}", file=sys.stderr)
        sys.exit(1)
    if not tf_file.exists():
        print(f"ERROR: Terraform file not found: {tf_file}", file=sys.stderr)
        sys.exit(1)

    manifest = {}
    if args.manifest:
        manifest_path = Path(args.manifest)
        if not manifest_path.exists():
            print(f"WARNING: Manifest file not found: {manifest_path}", file=sys.stderr)
        else:
            manifest = load_manifest(str(manifest_path))
            print(f"Manifest loaded: {len(manifest)} explicit mapping(s)")

    print(f"Analyzing {py_file.name} + {tf_file.name}...\n")

    rpm = parse_python_file(str(py_file))
    gpms = parse_terraform_file(str(tf_file))

    print(f"RPM: {len(rpm.sdk_calls)} SDK calls found")
    print(f"GPM: {len(gpms)} IAM roles found\n")

    if not gpms:
        print("No IAM roles found in Terraform file. Nothing to analyze.")
        sys.exit(0)

    deltas = compute_all_deltas(rpm, gpms, manifest)

    total_excess = sum(len(d.excess) for d in deltas)
    print(f"Found {total_excess} excess permissions across {len(deltas)} role(s)\n")

    patch_results = []

    for delta in deltas:
        print(f"{'='*60}")
        print(f"Role:          {delta.role_name}")
        print(f"Match method:  {delta.matched_by}")
        print(f"Patch risk:    {delta.patch_risk.upper()}")
        print(f"Human review:  {delta.requires_human_review}")
        print(f"Excess ({len(delta.excess)}):")
        if not delta.excess:
            print("  None - role is correctly scoped")
        else:
            for e in sorted(delta.excess, key=lambda x: x.severity, reverse=True):
                print(f"  [{e.severity.upper():6}] {e.action_iam}")
                print(f"           {e.reason}")

        patch = None
        if delta.excess and args.patch:
            patch = generate_patch(delta, str(tf_file))
            print(f"\nPatch diff:")
            print(patch.diff())
            if args.output:
                Path(args.output).write_text(patch.patched_tf, encoding="utf-8")
                print(f"\nPatched file written to: {args.output}")

        patch_results.append(patch)
        print()

    if _audit_available():
        _fire_audit(rpm, deltas, patch_results)
    else:
        print("[audit] ACE_DATABASE_URL not set - skipping audit log", file=sys.stderr)

    if args.json:
        output = [d.model_dump() for d in deltas]
        print(json.dumps(output, indent=2, default=str))

    if any(d.patch_risk == "red" for d in deltas):
        sys.exit(1)


def cmd_sweep(args):
    print(f"[sweep] Starting sweep (repo={args.repo})")

    session = boto3.Session(profile_name=args.aws_profile) if args.aws_profile else boto3.Session()

    # Verify AWS credentials
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"[sweep] AWS account: {identity['Account']} ({identity['Arn']})")
    except Exception as e:
        print(f"[sweep] AWS credentials error: {e}", file=sys.stderr)
        sys.exit(1)

    # Get all tracked roles from DB
    states = ["ACTIVE", "PENDING_REDUCTION", "PR_OPEN"]
    roles = []
    for state in states:
        roles.extend(get_roles_by_state(state))

    if not roles:
        print("[sweep] No roles tracked yet.")
        print("[sweep] Add roles to the sweeper_roles table in Supabase first.")
        return

    print(f"[sweep] Processing {len(roles)} roles...")
    for role in roles:
        print(f"  -> {role['role_name']} ({role['role_arn']})")
        try:
            new_state = process_role(
                role_arn=role["role_arn"],
                role_name=role["role_name"],
                repo=role["repo"],
                tf_file_path=role["tf_file_path"],
                owner_slack_id=role.get("owner_slack_id"),
                excess_actions=[],
                ignore_dormancy=role.get("ignore_dormancy", False),
                boto3_session=session,
            )
            print(f"     state: {role['state']} -> {new_state}")
        except Exception as e:
            print(f"     ERROR: {e}", file=sys.stderr)

    # Advance roles past cooling-off period
    ready = advance_cooling_off()
    if ready:
        print(f"[sweep] {len(ready)} roles ready for PR:")
        for r in ready:
            print(f"  -> {r['role_name']} ({r['role_arn']})")
    else:
        print("[sweep] No roles past cooling-off period.")

    print("[sweep] Done.")


# -- Entry point --------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(prog="ace-cli")
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="Analyze privilege gap")
    analyze.add_argument("--file", required=True, help="Python source file")
    analyze.add_argument("--tf", required=True, help="Terraform .tf file")
    analyze.add_argument("--manifest", help="Path to ace-manifest.yaml (optional)")
    analyze.add_argument("--patch", action="store_true", help="Generate HCL patch")
    analyze.add_argument("--output", help="Write patched .tf to this path")
    analyze.add_argument("--json", action="store_true", help="Output delta as JSON")

    sweep = subparsers.add_parser("sweep", help="Run IAM sweeper against AWS")
    sweep.add_argument("--repo", required=True, help="GitHub repo e.g. PotatoFy02/ACE")
    sweep.add_argument("--aws-profile", default=None, help="AWS profile name (optional)")

    args = parser.parse_args()
    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "sweep":
        cmd_sweep(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()