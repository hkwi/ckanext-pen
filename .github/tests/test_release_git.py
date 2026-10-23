"""Check real Git ancestry and tag peeling in an isolated local repository."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from release_test_support import gate


class ReleaseGitTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        config = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull,
                                         "GIT_CONFIG_NOSYSTEM": "1"})
        config.start()
        self.addCleanup(config.stop)
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.temp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Release Gate Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("commit", "-q", "--allow-empty", "-m", "Synthetic base")
        self.base = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.base)

    def git(self, *args):
        return subprocess.check_output(["git", *args], text=True).strip()

    def test_accepts_lightweight_and_annotated_tags(self):
        self.git("tag", "v1.0.0")
        self.git("tag", "-a", "v1.0.1", "-m", "Synthetic annotated release")
        for tag in ["v1.0.0", "v1.0.1"]:
            with self.subTest(tag=tag):
                self.assertEqual(gate.tag_commit("refs/tags/" + tag), self.base)

    def test_main_checks_ci_for_the_peeled_tag_commit(self):
        self.git("tag", "-a", "v1.0.0", "-m", "Synthetic release")
        with patch.dict(os.environ, {"GITHUB_REF": "refs/tags/v1.0.0",
                                     "GITHUB_REPOSITORY": "example/extension"}), \
                patch.object(gate, "verify_main_ci") as ci:
            self.assertEqual(gate.main(), 0)
            ci.assert_called_once_with("example/extension", self.base)

    def test_accepts_a_commit_that_remains_an_ancestor_of_main(self):
        self.git("tag", "v1.0.0")
        self.git("commit", "-q", "--allow-empty", "-m", "Synthetic next main")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.git("checkout", "-q", "v1.0.0")
        self.assertEqual(gate.tag_commit("refs/tags/v1.0.0"), self.base)

    def test_rejects_unmerged_tag_before_any_api_call(self):
        self.git("switch", "-q", "-c", "release/test")
        self.git("commit", "-q", "--allow-empty", "-m", "Synthetic unmerged release")
        self.git("tag", "v1.0.0")
        with patch.dict(os.environ, {"GITHUB_REF": "refs/tags/v1.0.0"}), \
                patch.object(gate, "verify_main_ci") as ci:
            self.assertEqual(gate.main(), 1)
            ci.assert_not_called()

    def test_rejects_non_release_refs(self):
        for ref in ["refs/heads/main", "refs/tags/test", ""]:
            with self.subTest(ref=ref), self.assertRaises(RuntimeError):
                gate.tag_commit(ref)

    def test_rejects_checkout_mismatch(self):
        self.git("tag", "v1.0.0")
        self.git("commit", "-q", "--allow-empty", "-m", "Synthetic other checkout")
        with self.assertRaises(RuntimeError):
            gate.tag_commit("refs/tags/v1.0.0")

    def test_rejects_missing_main_history(self):
        self.git("tag", "v1.0.0")
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        with self.assertRaises(RuntimeError):
            gate.tag_commit("refs/tags/v1.0.0")
