"""
ace-cli — main entry point.

Usage:
  python cli.py analyze --file lambda.py --tf roles.tf
  python cli.py analyze --repo /path/to/repo
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
import sys
from pathlib import Path

from parsers.rpm_engine import parse_python_file
from parsers.gpm_engine import parse_terraform_file
from delta_engine.engine import compute_all_deltas
from patch_generator.generator import generate_patch


def cmd_analyze(args):
    """
    Analyze a Python file + Terraform file and print the delta.
    """
    py_file = Path(args.file)
    tf_file = Path(args.tf)

    if not py_file.exists():
        print(f"ERROR: Python file not found: {py_file}", file=sys.stderr)
        sys.exit(1)

    if not tf_file.exists():
        print(f"ERROR: Terraform file not found: {tf_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing {py_file.name} + {tf_file.name}...\n")

    # Step 1: parse
    rpm = parse_python_file(str(py_file))
    gpms = parse_terraform_file(str(tf_file))

    print(f"RPM: {len(rpm.sdk_calls)} SDK calls found")
    print(f"GPM: {len(gpms)} IAM roles found\n")

    if not gpms:
        print("No IAM roles found in Terraform file. Nothing to analyze.")
        sys.exit(0)

    # Step 2: compute deltas
    deltas = compute_all_deltas(rpm, gpms)

    # Step 3: report
    total_excess = sum(len(d.excess) for d in deltas)
    print(f"Found {total_excess} excess permissions across {len(deltas)} role(s)\n")

    for delta in deltas:
        print(f"{'='*60}")
        print(f"Role:          {delta.role_name}")
        print(f"Match method:  {delta.matched_by}")
        print(f"Patch risk:    {delta.patch_risk.upper()}")
        print(f"Human review:  {delta.requires_human_review}")
        print(f"Excess ({len(delta.excess)}):")

        if not delta.excess:
            print("  None — role is correctly scoped")
        else:
            for e in sorted(delta.excess, key=lambda x: x.severity, reverse=True):
                print(f"  [{e.severity.upper():6}] {e.action_iam}")
                print(f"           {e.reason}")

        # Step 4: generate patch
        if delta.excess and args.patch:
            patch = generate_patch(delta, str(tf_file))
            print(f"\nPatch diff:")
            print(patch.diff())
            if args.output:
                Path(args.output).write_text(patch.patched_tf, encoding="utf-8")
                print(f"\nPatched file written to: {args.output}")

        print()

    # Step 5: output JSON if requested
    if args.json:
        output = [d.model_dump() for d in deltas]
        print(json.dumps(output, indent=2, default=str))

    # Exit code: 1 if any red-risk patches found (for CI gates)
    if any(d.patch_risk == "red" for d in deltas):
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(prog="ace-cli")
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="Analyze privilege gap")
    analyze.add_argument("--file", required=True, help="Python source file")
    analyze.add_argument("--tf", required=True, help="Terraform .tf file")
    analyze.add_argument("--patch", action="store_true", help="Generate HCL patch")
    analyze.add_argument("--output", help="Write patched .tf to this path")
    analyze.add_argument("--json", action="store_true", help="Output delta as JSON")

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()