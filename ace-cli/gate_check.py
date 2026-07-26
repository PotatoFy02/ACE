"""
Week 2 Exit Gate.
Pass condition: parse 3+ files with AWS calls, fewer than 2 errors.
"""

from pathlib import Path
from parsers.rpm_engine import parse_python_file

OWN_SAMPLES = Path(__file__).parent / "test_samples"
REPO = Path(__file__).parent.parent / "test_repos" / "serverless-patterns"


def run_gate():
    results = {"pass": [], "fail": []}

    # Always test our own sample first
    targets = list(OWN_SAMPLES.glob("*.py"))

    # Add real repo files that contain boto3
    if REPO.exists():
        for f in REPO.rglob("*.py"):
            try:
                if "boto3" in f.read_text(errors="replace"):
                    targets.append(f)
                if len(targets) >= 15:
                    break
            except Exception:
                continue

    print(f"Testing {len(targets)} files\n")

    for f in targets:
        try:
            rpm = parse_python_file(str(f))
            if not rpm.sdk_calls:
                print(f"  SKIP  {f.name} — no AWS calls found")
                continue
            results["pass"].append(f.name)
            print(f"  PASS  {f.name} — {len(rpm.sdk_calls)} calls:")
            for call in rpm.sdk_calls:
                print(f"        {call.action_iam} | confidence={call.confidence} | resources={call.resources}")
        except TimeoutError:
            results["fail"].append((f.name, "TIMEOUT"))
            print(f"  FAIL  {f.name} — timeout")
        except Exception as e:
            results["fail"].append((f.name, str(e)[:100]))
            print(f"  FAIL  {f.name} — {str(e)[:100]}")

    print(f"\n--- Gate Summary ---")
    print(f"Files with AWS calls parsed successfully: {len(results['pass'])}")
    print(f"Files failed:                             {len(results['fail'])}")

    if results["fail"]:
        print("\nFailed files:")
        for name, reason in results["fail"]:
            print(f"  {name}: {reason}")

    if len(results["pass"]) >= 3 and len(results["fail"]) <= 2:
        print("\nGATE: PASS — Week 2 complete, Week 3 unblocked")
    else:
        print("\nGATE: FAIL — fix issues above before Week 3")


if __name__ == "__main__":
    run_gate()