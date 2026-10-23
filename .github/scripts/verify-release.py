"""Fail closed unless a release tag is merged and its main-push E2E passed."""
import json
import os
import subprocess
import sys


def tag_commit(ref):
    if not ref.startswith("refs/tags/v"):
        raise RuntimeError("A v-prefixed release tag is required")
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", ref + "^{commit}"], text=True
    ).strip()
    checkout = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True
    ).strip()
    if checkout != commit:
        raise RuntimeError("The checkout does not match the release tag")
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"],
            check=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            "The tagged commit must be merged into main; full main history is required"
        ) from error
    return commit


def verify_main_ci(repository, commit):
    payload = subprocess.check_output(
        ["gh", "api", "--method", "GET",
         f"repos/{repository}/actions/workflows/e2e.yml/runs",
         "-f", "branch=main", "-f", "event=push",
         "-f", f"head_sha={commit}", "-f", "per_page=1"],
        text=True,
    )
    runs = json.loads(payload).get("workflow_runs", [])
    if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
        raise RuntimeError("No main-push E2E run found for the tagged commit")
    run = runs[0]
    expected = {"head_sha": commit, "head_branch": "main", "event": "push",
                "status": "completed", "conclusion": "success"}
    if any(run.get(key) != value for key, value in expected.items()):
        raise RuntimeError(
            "The latest main-push E2E run for the tagged commit must succeed; "
            "wait for main CI, then re-run this release workflow"
        )
    print(f"Verified main E2E run {run.get('id')} for {commit}")


def main():
    try:
        commit = tag_commit(os.environ["GITHUB_REF"])
        verify_main_ci(os.environ["GITHUB_REPOSITORY"], commit)
    except (RuntimeError, subprocess.CalledProcessError, OSError,
            ValueError, KeyError, AttributeError) as error:
        print(f"Release verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
