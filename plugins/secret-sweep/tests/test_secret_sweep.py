#!/usr/bin/env python3
"""
Regression tests for the secret sweeper.

Stdlib `unittest` only, matching the repository's zero-dependency rule.

    python3 -m unittest discover -s tests -v

Three invariants carry this tool:

  * Placeholders, examples and test keys stay silent. A scanner that flags
    `.env.example` gets muted within a day.
  * No finding ever prints a whole credential. The report must not become
    one more place the key exists.
  * A file that once held secrets is reported even after it is deleted from
    the working tree, because git remembers.

None of the credentials below are real. They are shaped like the real thing
so the patterns are exercised, and nothing more.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "secret-sweep" / "scripts" / "secret_sweep.py"
sys.path.insert(0, str(SCRIPT.parent))

import secret_sweep as ss  # noqa: E402

# Synthetic values, assembled at runtime so the literals never sit in one piece.
STRIPE_LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_TEST = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
OPENAI = "sk-proj-" + "T3BlbkFJabcdefghijklmnopqrstuvwx1234"
AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"[:16]
GITHUB = "ghp_" + "016C7ADEabcdefghijklmnopqrstuvwxyz12"


def service_role_jwt() -> str:
    payload = ss.base64.urlsafe_b64encode(b'{"role":"service_role"}').decode().rstrip("=")
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.%s.c2lnbmF0dXJl" % payload


def anon_jwt() -> str:
    payload = ss.base64.urlsafe_b64encode(b'{"role":"anon"}').decode().rstrip("=")
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.%s.c2lnbmF0dXJl" % payload


class Project:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.root)] + list(args),
            capture_output=True, text=True, check=False,
        )

    def init_repo(self) -> None:
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.git("config", "commit.gpgsign", "false")

    def sweep(self) -> ss.Report:
        return ss.sweep(str(self.root))

    def codes(self):
        return sorted(f.code for f in self.sweep().findings)

    def close(self) -> None:
        self._tmp.cleanup()


class ProjectCase(unittest.TestCase):
    def setUp(self) -> None:
        self.project = Project()
        self.addCleanup(self.project.close)


# --------------------------------------------------------------------------
# Silence on things that are not leaks
# --------------------------------------------------------------------------

class TestNoFalsePositives(ProjectCase):
    def test_env_example_is_never_scanned_for_values(self):
        self.project.write(".env.example", "STRIPE_SECRET_KEY=%s\n" % STRIPE_LIVE)
        self.assertEqual(self.project.codes(), [])

    def test_placeholders_are_ignored(self):
        self.project.write(".env", "\n".join([
            "API_KEY=your_api_key_here",
            "DB_PASSWORD=changeme",
            "CLIENT_SECRET=xxxxxxxxxxxx",
            "AUTH_TOKEN=<your-token>",
            "OTHER_SECRET=${SOME_VAR}",
            "TODO_SECRET=TODO",
        ]))
        self.assertEqual([c for c in self.project.codes() if c.startswith("SEC02")], [])

    def test_env_reference_is_not_a_literal(self):
        self.project.write("lib/x.ts", "const API_KEY = process.env.API_KEY;\n")
        self.assertEqual(self.project.codes(), [])

    def test_anon_jwt_is_not_a_secret(self):
        self.project.write("lib/supabase.ts", 'const k = "%s";\n' % anon_jwt())
        self.assertEqual(self.project.codes(), [])

    def test_low_entropy_english_is_not_a_credential(self):
        self.project.write("config.ts", 'const API_KEY = "the quick brown fox jumped";\n')
        self.assertEqual(self.project.codes(), [])

    def test_public_url_var_is_fine(self):
        self.project.write(".env", "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\n")
        self.assertEqual([c for c in self.project.codes() if c == "SEC021"], [])

    def test_node_modules_and_build_output_skipped(self):
        self.project.write("node_modules/p/i.js", 'k="%s"\n' % STRIPE_LIVE)
        self.project.write(".next/static/c.js", 'k="%s"\n' % STRIPE_LIVE)
        self.project.write("dist/b.js", 'k="%s"\n' % STRIPE_LIVE)
        self.assertEqual(self.project.codes(), [])

    def test_ci_reference_to_encrypted_secret_is_fine(self):
        self.project.write(
            ".github/workflows/ci.yml",
            "env:\n  STRIPE_SECRET_KEY: ${{ secrets.STRIPE_SECRET_KEY }}\n",
        )
        self.assertEqual(self.project.codes(), [])

    def test_dockerfile_arg_without_value_is_fine(self):
        self.project.write("Dockerfile", "ARG API_KEY\nENV API_KEY=$API_KEY\n")
        self.assertEqual(self.project.codes(), [])


# --------------------------------------------------------------------------
# Provider patterns
# --------------------------------------------------------------------------

class TestProviderPatterns(ProjectCase):
    def test_stripe_live_key_is_critical(self):
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        findings = self.project.sweep().findings
        self.assertEqual([f.code for f in findings], ["SEC001"])
        self.assertEqual(findings[0].severity, ss.CRITICAL)
        self.assertEqual(findings[0].confidence, ss.FACT)
        self.assertIn("Stripe", findings[0].fix)

    def test_stripe_test_key_is_only_medium(self):
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_TEST)
        findings = self.project.sweep().findings
        self.assertEqual([f.code for f in findings], ["SEC002"])
        self.assertEqual(findings[0].severity, ss.MEDIUM)

    def test_openai_key(self):
        self.project.write("lib/ai.ts", 'const k = "%s";\n' % OPENAI)
        self.assertIn("SEC004", self.project.codes())

    def test_anthropic_key_is_not_double_reported(self):
        self.project.write("lib/ai.ts", 'const k = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345";\n')
        self.assertEqual(self.project.codes(), ["SEC005"])

    def test_aws_access_key(self):
        self.project.write("deploy.sh", "export AWS_ACCESS_KEY_ID=%s\n" % AWS_ID)
        self.assertIn("SEC006", self.project.codes())

    def test_github_token(self):
        self.project.write("script.sh", "TOKEN=%s\n" % GITHUB)
        self.assertIn("SEC008", self.project.codes())

    def test_private_key_block(self):
        self.project.write("key.pem", "-----BEGIN RSA PRIVATE KEY-----\nabc\n")
        self.assertEqual(self.project.codes(), ["SEC014"])

    def test_database_url_with_password(self):
        self.project.write(".env", "DATABASE_URL=postgresql://admin:hunter2pass@db.host:5432/app\n")
        self.assertIn("SEC015", self.project.codes())

    def test_database_url_without_password_is_ignored(self):
        self.project.write(".env", "DATABASE_URL=postgresql://localhost:5432/app\n")
        self.assertEqual([c for c in self.project.codes() if c == "SEC015"], [])

    def test_service_role_jwt(self):
        self.project.write("lib/admin.ts", 'const k = "%s";\n' % service_role_jwt())
        self.assertEqual(self.project.codes(), ["SEC016"])

    def test_same_key_twice_in_a_file_reported_once(self):
        self.project.write("a.ts", 'const a = "%s";\nconst b = "%s";\n' % (STRIPE_LIVE, STRIPE_LIVE))
        self.assertEqual(self.project.codes(), ["SEC001"])


# --------------------------------------------------------------------------
# Never print the secret
# --------------------------------------------------------------------------

class TestRedaction(ProjectCase):
    def test_finding_does_not_contain_the_key(self):
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        finding = self.project.sweep().findings[0]
        blob = json.dumps(finding.as_dict())
        self.assertNotIn(STRIPE_LIVE, blob)
        self.assertIn("****", blob)

    def test_rendered_report_does_not_contain_the_key(self):
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        text = ss.render(self.project.sweep(), str(self.project.root))
        self.assertNotIn(STRIPE_LIVE, text)

    def test_mask_keeps_a_recognisable_prefix(self):
        masked = ss.mask(STRIPE_LIVE)
        self.assertTrue(masked.startswith("sk_l"))
        self.assertNotIn("4eC39Hq", masked)

    def test_short_values_are_fully_masked(self):
        self.assertEqual(ss.mask("abc123"), "******")


# --------------------------------------------------------------------------
# Browser exposure
# --------------------------------------------------------------------------

class TestPublicExposure(ProjectCase):
    def test_public_prefixed_secret_name(self):
        self.project.write(".env", "NEXT_PUBLIC_STRIPE_SECRET_KEY=abc123def456\n")
        self.assertIn("SEC021", self.project.codes())

    def test_public_prefixed_env_access_in_code(self):
        self.project.write("lib/x.ts", "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n")
        self.assertIn("SEC021", self.project.codes())

    def test_vite_import_meta_access(self):
        self.project.write("lib/x.ts", "const k = import.meta.env.VITE_API_SECRET;\n")
        self.assertIn("SEC021", self.project.codes())

    def test_lookalike_identifier_is_not_a_leak(self):
        # A constant, a regex or a comment that merely matches the shape is not
        # an environment variable, and reporting one costs more than it is worth.
        self.project.write("lib/x.ts", "const PUBLIC_SECRET_NAME_RE = /whatever/;\n")
        self.project.write("notes.md", "We removed PUBLIC_SECRET_TOKEN last year.\n")
        self.assertEqual([c for c in self.project.codes() if c == "SEC021"], [])

    def test_env_file_mention_without_assignment_is_ignored(self):
        self.project.write(".env", "# NEXT_PUBLIC_STRIPE_SECRET_KEY was removed\n")
        self.assertEqual([c for c in self.project.codes() if c == "SEC021"], [])

    def test_public_prefixed_but_empty_in_env_is_ignored(self):
        self.project.write(".env", "NEXT_PUBLIC_STRIPE_SECRET_KEY=\n")
        self.assertNotIn("SEC021", self.project.codes())

    def test_server_secret_in_client_component(self):
        self.project.write(
            "components/P.tsx",
            "'use client'\nconst k = process.env.STRIPE_SECRET_KEY;\n",
        )
        self.assertIn("SEC022", self.project.codes())

    def test_server_component_reading_secret_is_fine(self):
        self.project.write("app/page.tsx", "const k = process.env.STRIPE_SECRET_KEY;\n")
        self.assertEqual(self.project.codes(), [])


# --------------------------------------------------------------------------
# Build configuration
# --------------------------------------------------------------------------

class TestBuildConfig(ProjectCase):
    def test_dockerfile_env_secret(self):
        self.project.write("Dockerfile", "FROM node\nENV API_KEY=Xk8sLmQ2pR9vT4wZ\n")
        findings = self.project.sweep().findings
        self.assertIn("SEC030", [f.code for f in findings])
        self.assertIn("image layer", findings[0].detail)

    def test_ci_literal_secret(self):
        self.project.write(
            ".github/workflows/deploy.yml",
            "env:\n  DEPLOY_TOKEN: Xk8sLmQ2pR9vT4wZbN3j\n",
        )
        self.assertIn("SEC031", self.project.codes())


# --------------------------------------------------------------------------
# git hygiene - the part that catches what is already gone
# --------------------------------------------------------------------------

class TestGitHygiene(ProjectCase):
    def test_env_not_ignored_is_high(self):
        self.project.init_repo()
        self.project.write(".env", "SOME_VALUE=1\n")
        self.assertIn("SEC042", self.project.codes())

    def test_env_ignored_and_never_committed_is_clean(self):
        self.project.init_repo()
        self.project.write(".gitignore", ".env\n")
        self.project.write(".env", "SOME_VALUE=1\n")
        self.assertEqual([c for c in self.project.codes() if c.startswith("SEC04")], [])

    def test_tracked_env_is_critical(self):
        self.project.init_repo()
        self.project.write(".env", "SOME_VALUE=1\n")
        self.project.git("add", ".env")
        self.project.git("commit", "-m", "oops")
        codes = self.project.codes()
        self.assertIn("SEC040", codes)
        self.assertNotIn("SEC042", codes)

    def test_env_removed_from_tracking_is_still_reported(self):
        # The whole point: deleting the file does not delete the history.
        self.project.init_repo()
        self.project.write(".env", "SOME_VALUE=1\n")
        self.project.git("add", ".env")
        self.project.git("commit", "-m", "oops")
        self.project.git("rm", "--cached", ".env")
        self.project.git("commit", "-m", "remove")
        self.project.write(".gitignore", ".env\n")
        findings = [f for f in self.project.sweep().findings if f.code == "SEC041"]
        self.assertEqual(len(findings), 1)
        self.assertIn("history", findings[0].detail)

    def test_env_example_is_not_a_git_finding(self):
        self.project.init_repo()
        self.project.write(".env.example", "API_KEY=\n")
        self.project.git("add", ".env.example")
        self.project.git("commit", "-m", "template")
        self.assertEqual([c for c in self.project.codes() if c.startswith("SEC04")], [])

    def test_no_git_repo_means_no_git_findings(self):
        self.project.write(".env", "SOME_VALUE=1\n")
        self.assertEqual([c for c in self.project.codes() if c.startswith("SEC04")], [])


class TestSafeEnvFiles(ProjectCase):
    """
    A key in an ignored, never-committed .env is in the correct place.
    Reporting it as critical is the fastest way to get the tool uninstalled.
    """

    def test_keys_in_a_properly_ignored_env_are_not_findings(self):
        self.project.init_repo()
        self.project.write(".gitignore", ".env\n")
        self.project.write(".env", "STRIPE_SECRET_KEY=%s\n" % STRIPE_LIVE)
        report = self.project.sweep()
        self.assertEqual(report.findings, [])
        self.assertEqual(report.safe_env_secrets, 1)

    def test_the_report_says_so_rather_than_staying_silent(self):
        self.project.init_repo()
        self.project.write(".gitignore", ".env\n")
        self.project.write(".env", "STRIPE_SECRET_KEY=%s\n" % STRIPE_LIVE)
        text = ss.render(self.project.sweep(), str(self.project.root))
        self.assertIn("where they belong", text)

    def test_keys_in_a_committed_env_are_still_critical(self):
        self.project.init_repo()
        self.project.write(".env", "STRIPE_SECRET_KEY=%s\n" % STRIPE_LIVE)
        self.project.git("add", ".env")
        self.project.git("commit", "-m", "oops")
        codes = self.project.codes()
        self.assertIn("SEC040", codes)
        self.assertIn("SEC001", codes)

    def test_keys_in_an_unignored_env_are_still_reported(self):
        self.project.init_repo()
        self.project.write(".env", "STRIPE_SECRET_KEY=%s\n" % STRIPE_LIVE)
        codes = self.project.codes()
        self.assertIn("SEC042", codes)
        self.assertIn("SEC001", codes)

    def test_source_code_keys_are_never_excused_by_a_safe_env(self):
        self.project.init_repo()
        self.project.write(".gitignore", ".env\n")
        self.project.write(".env", "STRIPE_SECRET_KEY=%s\n" % STRIPE_LIVE)
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        self.assertIn("SEC001", self.project.codes())

    def test_worktree_copies_are_not_scanned_twice(self):
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        self.project.write(".claude/worktrees/agent-1/lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        self.assertEqual(self.project.codes(), ["SEC001"])


# --------------------------------------------------------------------------
# Test fixtures - the false-positive class that gets scanners uninstalled
# --------------------------------------------------------------------------

class TestTestPaths(ProjectCase):
    TEST_PATHS = [
        "tests/test_billing.py",
        "src/__tests__/pay.ts",
        "app/checkout.test.ts",
        "e2e/flow.spec.ts",
        "fixtures/stripe.json",
        "cypress/e2e/pay.cy.ts",
    ]

    def test_fixture_keys_are_downgraded_not_hidden(self):
        for relative in self.TEST_PATHS:
            with self.subTest(relative):
                project = Project()
                self.addCleanup(project.close)
                project.write(relative, 'const k = "%s";\n' % STRIPE_LIVE)
                findings = project.sweep().findings
                self.assertEqual(len(findings), 1, relative)
                self.assertEqual(findings[0].severity, ss.REVIEW, relative)
                self.assertEqual(findings[0].confidence, ss.HEURISTIC)
                self.assertIn("test or fixture path", findings[0].detail)

    def test_fixture_keys_never_fail_strict(self):
        self.project.write("tests/test_pay.py", 'K = "%s"\n' % STRIPE_LIVE)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--path", str(self.project.root), "--strict"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)

    def test_include_tests_restores_full_severity(self):
        self.project.write("tests/test_pay.py", 'K = "%s"\n' % STRIPE_LIVE)
        report = ss.sweep(str(self.project.root), include_tests=True)
        self.assertEqual(report.findings[0].severity, ss.CRITICAL)
        self.assertEqual(report.test_findings, 0)

    def test_production_code_is_not_downgraded(self):
        self.project.write("app/checkout.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        self.assertEqual(self.project.sweep().findings[0].severity, ss.CRITICAL)

    def test_a_path_merely_containing_test_is_not_a_test_path(self):
        # "latest/" and "contest.ts" must not be mistaken for test paths.
        self.project.write("latest/checkout.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        self.assertEqual(self.project.sweep().findings[0].severity, ss.CRITICAL)

    def test_report_explains_the_downgrade(self):
        self.project.write("tests/test_pay.py", 'K = "%s"\n' % STRIPE_LIVE)
        text = ss.render(self.project.sweep(), str(self.project.root))
        self.assertIn("--include-tests", text)


class TestHelpers(unittest.TestCase):
    def test_entropy_separates_prose_from_keys(self):
        self.assertLess(ss.shannon_entropy("password password"), 3.0)
        self.assertGreater(ss.shannon_entropy("Xk8sLmQ2pR9vT4wZbN3j"), 3.0)

    def test_placeholder_detection(self):
        for value in ("your_key_here", "changeme", "xxxxxxxxxx", "<token>", "abc", "TODO_replace"):
            self.assertTrue(ss.looks_like_placeholder(value), value)
        self.assertFalse(ss.looks_like_placeholder("Xk8sLmQ2pR9vT4wZbN3j"))


# --------------------------------------------------------------------------
# CLI contract
# --------------------------------------------------------------------------

class TestCli(ProjectCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT)] + list(args),
            capture_output=True, text=True,
        )

    def test_missing_directory_exits_zero(self):
        result = self._run("--path", "/nonexistent-path-for-tests")
        self.assertEqual(result.returncode, 0)
        self.assertIn("no such directory", result.stdout)

    def test_empty_project_exits_zero(self):
        result = self._run("--path", str(self.project.root))
        self.assertEqual(result.returncode, 0)

    def test_json_is_valid_and_shaped_like_the_suite(self):
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        payload = json.loads(self._run("--path", str(self.project.root), "--json").stdout)
        self.assertEqual(payload["counts"]["critical"], 1)
        finding = payload["findings"][0]
        for key in ("code", "severity", "confidence", "title", "file", "line", "detail", "fix"):
            self.assertIn(key, finding)

    def test_strict_fails_on_critical(self):
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        self.assertEqual(self._run("--path", str(self.project.root), "--strict").returncode, 1)

    def test_strict_passes_on_clean_project(self):
        self.project.write("app/page.tsx", "export default () => null;\n")
        self.assertEqual(self._run("--path", str(self.project.root), "--strict").returncode, 0)

    def test_report_tells_you_to_rotate(self):
        self.project.write("lib/pay.ts", 'const k = "%s";\n' % STRIPE_LIVE)
        self.assertIn("Rotate", self._run("--path", str(self.project.root)).stdout)

    def test_report_states_its_limits(self):
        self.assertIn("What this cannot tell you", self._run("--path", str(self.project.root)).stdout)


if __name__ == "__main__":
    unittest.main()
