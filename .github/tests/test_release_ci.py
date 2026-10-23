"""Exercise the exact-commit main CI policy with harmless API responses."""
import json
import subprocess
import unittest
from unittest.mock import patch

from release_test_support import gate

COMMIT = "1" * 40


def run(**changes):
    result = {"id": 123, "head_sha": COMMIT, "head_branch": "main",
              "event": "push", "status": "completed", "conclusion": "success"}
    return {**result, **changes}


class MainCITest(unittest.TestCase):
    def verify(self, runs):
        with patch.object(gate.subprocess, "check_output",
                          return_value=json.dumps({"workflow_runs": runs})) as api:
            gate.verify_main_ci("example/extension", COMMIT)
        return api.call_args.args[0]

    def test_accepts_exact_commit_main_push_and_queries_only_e2e(self):
        command = self.verify([run()])
        self.assertEqual(command[:5], ["gh", "api", "--method", "GET",
                         "repos/example/extension/actions/workflows/e2e.yml/runs"])
        for field in ["branch=main", "event=push", "head_sha=" + COMMIT, "per_page=1"]:
            self.assertIn(field, command)

    def test_rejects_missing_pending_failed_or_unrelated_ci(self):
        cases = [[], [run(status="in_progress", conclusion=None)],
                 [run(status="queued", conclusion=None)],
                 [run(event="pull_request")], [run(head_branch="release/test")],
                 [run(head_sha="2" * 40)], [{}], None]
        cases += [[run(conclusion=value)] for value in
                  ["failure", "cancelled", "skipped", "neutral", "timed_out"]]
        for runs in cases:
            with self.subTest(runs=runs), self.assertRaises(RuntimeError):
                self.verify(runs)

    def test_does_not_fall_back_to_an_older_success(self):
        with self.assertRaises(RuntimeError):
            self.verify([run(conclusion="failure"), run()])

    def test_api_errors_and_malformed_responses_fail_closed(self):
        cases = [subprocess.CalledProcessError(1, "gh"), OSError("API unavailable")]
        for error in cases:
            with self.subTest(error=error), \
                    patch.object(gate, "tag_commit", return_value=COMMIT), \
                    patch.dict(gate.os.environ, {"GITHUB_REF": "refs/tags/v1.0.0",
                                                "GITHUB_REPOSITORY": "example/extension"}), \
                    patch.object(gate.subprocess, "check_output", side_effect=error):
                self.assertEqual(gate.main(), 1)
        for payload in ["not JSON", "[]", "null"]:
            with self.subTest(payload=payload), \
                    patch.object(gate, "tag_commit", return_value=COMMIT), \
                    patch.dict(gate.os.environ, {"GITHUB_REF": "refs/tags/v1.0.0",
                                                "GITHUB_REPOSITORY": "example/extension"}), \
                    patch.object(gate.subprocess, "check_output", return_value=payload):
                self.assertEqual(gate.main(), 1)
