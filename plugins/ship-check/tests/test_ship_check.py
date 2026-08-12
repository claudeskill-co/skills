#!/usr/bin/env python3
"""
Regression tests for the umbrella.

Stdlib `unittest` only, matching the repository's zero-dependency rule.

    python3 -m unittest discover -s tests -v

This one produces a *verdict*, which is the most dangerous output in the
repository: a wrong CLEAR is worse than no tool at all, because the user
stopped looking. Two properties matter more than any individual rule here -
a missing scanner can never be graded clear, and a heuristic can never block.
Both have their own suites.
"""

import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "ship-check" / "scripts" / "ship_check.py"
PLUGINS = ROOT.parent
sys.path.insert(0, str(SCRIPT.parent))

import ship_check as sc  # noqa: E402


def finding(code="X001", severity=sc.CRITICAL, confidence=sc.FACT, path="a.ts", line=1,
            source="rls-audit", title="t"):
    return sc.Finding(code=code, severity=severity, confidence=confidence, title=title,
                      path=path, line=line, detail="d", fix="f", source=source)


def result(plugin="rls-audit", covers="access control", ran=True, findings=None, error=None):
    return sc.ScanResult(plugin=plugin, covers=covers, ran=ran,
                         findings=list(findings or []), error=error)


ALL_RAN = [result(s.plugin, s.covers, True) for s in sc.SCANNERS]


class TestScannerConformance(unittest.TestCase):
    """The scanners must agree with each other, and nothing else checks that.

    The CI matrix runs each plugin in isolation, so it is structurally
    incapable of catching a disagreement between them. Four independently
    maintained copies of the path classifier had drifted into four different
    answers, and ship-check merged that disagreement into a self-contradicting
    verdict: one file, one line, one key, reported `critical` by secret-sweep
    and `review` by stripe-check.

    This is the tripwire that makes the copies safe to keep.
    """

    CORPUS = [
        # path, is it a test/fixture path
        ("src/index.ts", False),
        ("app/api/route.ts", False),
        ("lib/billing.ts", False),
        # These two are the reason the bug existed. A directory called demo/ in
        # someone else's repository is far more likely to be real code than a
        # throwaway sample, so it is deliberately NOT downgraded.
        ("demo/only.ts", False),
        ("examples/basic/app.ts", False),
        ("samples/app.ts", False),
        ("tests/unit.ts", True),
        ("test/unit.ts", True),
        ("__tests__/a.ts", True),
        ("__mocks__/db.ts", True),
        ("mocks/db.ts", True),
        ("spec/a.ts", True),
        ("fixtures/schema.sql", True),
        ("demo/fixture/broken.ts", True),
        ("testdata/sample.json", True),
        ("e2e/login.ts", True),
        ("cypress/e2e/a.cy.ts", True),
        ("stories/Button.tsx", True),
        ("a.test.ts", True),
        ("a.spec.tsx", True),
        ("tests/test_thing.py", True),
        ("thing_test.py", True),
        ("conftest.py", True),
    ]

    _cache = {}

    @classmethod
    def load(cls, plugin, module):
        if module in cls._cache:
            return cls._cache[module]
        import importlib.util
        path = PLUGINS / plugin / "skills" / plugin / "scripts" / (module + ".py")
        spec = importlib.util.spec_from_file_location("conf_" + module, path)
        loaded = importlib.util.module_from_spec(spec)
        # Register before executing: @dataclass resolves annotations through
        # sys.modules, and fails on a module that is not there yet.
        sys.modules[spec.name] = loaded
        spec.loader.exec_module(loaded)
        cls._cache[module] = loaded
        return loaded

    SCANNER_MODULES = [
        ("rls-audit", "rls_audit"),
        ("secret-sweep", "secret_sweep"),
        ("stripe-check", "stripe_check"),
        ("deploy-check", "deploy_check"),
    ]

    def test_every_scanner_classifies_paths_identically(self):
        modules = [(name, self.load(name, mod)) for name, mod in self.SCANNER_MODULES]
        for path, expected in self.CORPUS:
            answers = {name: bool(mod.is_test_path(path)) for name, mod in modules}
            self.assertEqual(
                set(answers.values()), {expected},
                "scanners disagree on %r: %s (expected %s from all)" % (path, answers, expected))

    def test_the_umbrella_agrees_with_the_scanners(self):
        for path, expected in self.CORPUS:
            self.assertEqual(bool(sc.is_test_path(path)), expected, path)

    def test_the_regex_source_is_byte_identical_everywhere(self):
        """Behavioural equality is the requirement; identical source is how it
        stays true for inputs this corpus does not happen to cover."""
        patterns = {name: self.load(name, mod).TEST_PATH_RE.pattern
                    for name, mod in self.SCANNER_MODULES}
        patterns["ship-check"] = sc.TEST_PATH_RE.pattern
        self.assertEqual(len(set(patterns.values())), 1,
                         "TEST_PATH_RE has drifted apart again: %s"
                         % {k: v[:40] for k, v in patterns.items()})

    def test_every_scanner_emits_the_same_finding_shape(self):
        """ship-check merges these dicts, so the keys are a contract."""
        required = {"code", "severity", "confidence", "title", "file", "line", "detail", "fix"}
        for name, mod in [(n, self.load(n, m)) for n, m in self.SCANNER_MODULES]:
            fields = set(mod.Finding.__dataclass_fields__)
            self.assertTrue({"code", "severity", "confidence", "title", "line"} <= fields,
                            "%s Finding is missing contract fields: %s" % (name, fields))
            self.assertTrue(required <= set(mod.Finding(
                code="X", severity="review", confidence="fact", title="t",
                path="p", line=1, detail="d", fix="f").as_dict()),
                "%s as_dict() does not emit the merge contract" % name)


class TestGrading(unittest.TestCase):

    def test_proven_critical_blocks(self):
        verdict, reason = sc.grade([finding(severity=sc.CRITICAL)], ALL_RAN)
        self.assertEqual(verdict, sc.BLOCKED)
        self.assertIn("1 proven critical", reason)

    def test_proven_high_is_risky(self):
        verdict, _ = sc.grade([finding(severity=sc.HIGH)], ALL_RAN)
        self.assertEqual(verdict, sc.RISKY)

    def test_heuristic_critical_never_blocks(self):
        """Being loudly wrong is how a pre-flight check stops being run."""
        verdict, reason = sc.grade(
            [finding(severity=sc.CRITICAL, confidence=sc.HEURISTIC)], ALL_RAN)
        self.assertEqual(verdict, sc.RISKY)
        self.assertIn("unproven", reason)

    def test_heuristic_critical_does_not_vanish_either(self):
        verdict, _ = sc.grade(
            [finding(severity=sc.CRITICAL, confidence=sc.HEURISTIC)], ALL_RAN)
        self.assertNotEqual(verdict, sc.CLEAR)

    def test_medium_and_review_are_clear(self):
        verdict, _ = sc.grade(
            [finding(severity=sc.MEDIUM), finding(severity=sc.REVIEW, path="b.ts")], ALL_RAN)
        self.assertEqual(verdict, sc.CLEAR)

    def test_nothing_at_all_is_clear(self):
        self.assertEqual(sc.grade([], ALL_RAN)[0], sc.CLEAR)

    def test_a_missing_scanner_can_never_be_clear(self):
        """The property that matters most: not installed is not the same as passed."""
        partial = ALL_RAN[:-1] + [result("deploy-check", "deploy readiness", False,
                                         error="not installed")]
        verdict, reason = sc.grade([], partial)
        self.assertEqual(verdict, sc.PARTIAL)
        self.assertIn("deploy readiness", reason)

    def test_no_scanners_at_all_is_partial(self):
        none_ran = [result(s.plugin, s.covers, False, error="not installed") for s in sc.SCANNERS]
        verdict, reason = sc.grade([], none_ran)
        self.assertEqual(verdict, sc.PARTIAL)
        self.assertIn("nothing was checked", reason)

    def test_a_critical_still_blocks_even_with_scanners_missing(self):
        """Incomplete coverage must not downgrade a real finding."""
        partial = [result("rls-audit", "access control", True),
                   result("secret-sweep", "secrets", False, error="not installed")]
        self.assertEqual(sc.grade([finding()], partial)[0], sc.BLOCKED)

    def test_no_verdict_wording_claims_safety(self):
        for text in sc.VERDICT_LINE.values():
            self.assertNotIn("safe", text.lower())


class TestMerging(unittest.TestCase):

    def test_same_credential_from_two_scanners_becomes_one_finding(self):
        """The one legitimate overlap: a key is both a secret and a payments defect."""
        merged = sc.merge([
            result("secret-sweep", "secrets", True,
                   [finding(code="SEC010", severity=sc.CRITICAL, source="secret-sweep")]),
            result("stripe-check", "payments", True,
                   [finding(code="PAY005", severity=sc.HIGH, source="stripe-check")]),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].code, "SEC010")
        self.assertEqual(len(merged[0].also), 1)
        self.assertIn("stripe-check (PAY005)", merged[0].also[0])

    def test_two_different_defects_at_one_line_are_never_collapsed(self):
        """The defect this fixes: the loser's fix text used to be destroyed,
        leaving a bare code the user could do nothing with."""
        merged = sc.merge([result("deploy-check", "deploy", True, [
            finding(code="DEP005", severity=sc.MEDIUM, source="deploy-check",
                    title="No security headers"),
            finding(code="DEP004", severity=sc.MEDIUM, source="deploy-check",
                    title="Type errors ignored at build time"),
        ])])
        self.assertEqual(len(merged), 2)
        self.assertEqual({f.code for f in merged}, {"DEP004", "DEP005"})

    def test_a_merged_sibling_keeps_its_own_words(self):
        merged = sc.merge([
            result("secret-sweep", "secrets", True,
                   [finding(code="SEC010", severity=sc.CRITICAL, source="secret-sweep")]),
            result("stripe-check", "payments", True,
                   [sc.Finding(code="PAY005", severity=sc.HIGH, confidence=sc.FACT,
                               title="Live Stripe secret key in a file", path="a.ts", line=1,
                               detail="d", fix="Roll the key in the Stripe dashboard",
                               source="stripe-check")]),
        ])
        self.assertIn("Live Stripe secret key in a file", merged[0].also[0])
        self.assertIn("Roll the key", merged[0].also[0])

    def test_the_more_severe_version_survives(self):
        merged = sc.merge([
            result("stripe-check", "payments", True,
                   [finding(code="PAY005", severity=sc.HIGH, source="stripe-check")]),
            result("secret-sweep", "secrets", True,
                   [finding(code="SEC010", severity=sc.CRITICAL, source="secret-sweep")]),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, sc.CRITICAL)
        self.assertEqual(merged[0].code, "SEC010")
        self.assertIn("stripe-check (PAY005)", merged[0].also[0])

    def test_different_lines_stay_separate(self):
        merged = sc.merge([
            result(findings=[finding(line=1), finding(line=9)]),
        ])
        self.assertEqual(len(merged), 2)

    def test_different_files_stay_separate(self):
        merged = sc.merge([result(findings=[finding(path="a.ts"), finding(path="b.ts")])])
        self.assertEqual(len(merged), 2)

    def test_findings_are_sorted_most_severe_first(self):
        merged = sc.merge([result(findings=[
            finding(severity=sc.REVIEW, path="a.ts"),
            finding(severity=sc.CRITICAL, path="b.ts"),
            finding(severity=sc.MEDIUM, path="c.ts"),
        ])])
        self.assertEqual([f.severity for f in merged], [sc.CRITICAL, sc.MEDIUM, sc.REVIEW])

    def test_three_scanners_on_one_credential_collapse_together(self):
        merged = sc.merge([
            result("rls-audit", "a", True, [finding(code="KEY001", severity=sc.CRITICAL, source="rls-audit")]),
            result("secret-sweep", "b", True, [finding(code="SEC010", severity=sc.HIGH, source="secret-sweep")]),
            result("stripe-check", "c", True, [finding(code="PAY005", severity=sc.HIGH, source="stripe-check")]),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].also), 2)

    def test_an_rls_finding_never_merges_into_a_credential_one(self):
        """Different problems, same line - RLS001 is not a credential."""
        merged = sc.merge([
            result("rls-audit", "a", True, [finding(code="RLS001", severity=sc.CRITICAL, source="rls-audit")]),
            result("secret-sweep", "b", True, [finding(code="SEC010", severity=sc.HIGH, source="secret-sweep")]),
        ])
        self.assertEqual(len(merged), 2)

    def test_the_credential_family_is_explicit(self):
        self.assertEqual(sc.family("SEC001"), "credential")
        self.assertEqual(sc.family("KEY001"), "credential")
        self.assertEqual(sc.family("PAY005"), "credential")
        self.assertEqual(sc.family("PAY001"), "PAY001")
        self.assertEqual(sc.family("RLS001"), "RLS001")
        self.assertEqual(sc.family("DEP004"), "DEP004")


class TestLocatingScanners(unittest.TestCase):

    def test_finds_its_siblings_in_this_repository(self):
        roots = sc.candidate_roots(None)
        found = [s.plugin for s in sc.SCANNERS if sc.locate(s, roots)]
        self.assertEqual(found, [s.plugin for s in sc.SCANNERS])

    def test_explicit_scanners_directory_is_exclusive(self):
        """If you say where they are, looking elsewhere would contradict you."""
        with tempfile.TemporaryDirectory() as empty:
            roots = sc.candidate_roots(empty)
            self.assertEqual(roots, [empty])
            self.assertIsNone(sc.locate(sc.SCANNERS[0], roots))

    def test_explicit_directory_that_does_not_exist_yields_nothing(self):
        self.assertEqual(sc.candidate_roots("/nonexistent-scanners-dir"), [])

    def test_db_guard_is_not_run_as_a_scanner(self):
        """It is a hook. Pretending to have run it would be the overclaim."""
        self.assertNotIn(sc.HOOK_PLUGIN, [s.plugin for s in sc.SCANNERS])

    def test_hook_is_detected_in_this_repository(self):
        self.assertTrue(sc.hook_installed(sc.candidate_roots(None)))


class TestRunningScanners(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def fake(self, body):
        path = os.path.join(self.dir, "fake.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        return path

    def test_non_json_output_is_an_error_not_a_pass(self):
        script = self.fake("print('not json at all')\n")
        outcome = sc.run_scanner(sc.SCANNERS[0], script, self.dir)
        self.assertFalse(outcome.ran)
        self.assertIn("not valid JSON", outcome.error or "")

    def test_no_output_is_an_error_not_a_pass(self):
        script = self.fake("import sys\nsys.exit(3)\n")
        outcome = sc.run_scanner(sc.SCANNERS[0], script, self.dir)
        self.assertFalse(outcome.ran)
        self.assertIn("no output", outcome.error or "")

    def test_error_payload_is_surfaced(self):
        script = self.fake("print('{\"error\": \"no such directory\", \"findings\": []}')\n")
        outcome = sc.run_scanner(sc.SCANNERS[0], script, self.dir)
        self.assertFalse(outcome.ran)
        self.assertEqual(outcome.error, "no such directory")

    def test_findings_are_parsed_and_tagged_with_their_source(self):
        payload = json.dumps({"findings": [
            {"code": "RLS001", "severity": "critical", "confidence": "fact",
             "title": "t", "file": "a.sql", "line": 4, "detail": "d", "fix": "f"}]})
        script = self.fake("print(%r)\n" % payload)
        outcome = sc.run_scanner(sc.SCANNERS[0], script, self.dir)
        self.assertTrue(outcome.ran)
        self.assertEqual(outcome.findings[0].source, "rls-audit")
        self.assertEqual(outcome.findings[0].line, 4)

    def test_a_scanner_with_no_findings_counts_as_having_run(self):
        script = self.fake("print('{\"findings\": []}')\n")
        outcome = sc.run_scanner(sc.SCANNERS[0], script, self.dir)
        self.assertTrue(outcome.ran)
        self.assertEqual(outcome.findings, [])


class TestEndToEnd(unittest.TestCase):
    """Against the real sibling scanners in this repository."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def run_cli(self, *args):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = sc.main(["--path", self.root] + list(args))
        return code, buffer.getvalue()

    def test_a_table_without_rls_blocks_the_launch(self):
        self.write("supabase/migrations/001.sql",
                   "create table public.profiles (id uuid primary key, email text);\n")
        code, out = self.run_cli("--strict")
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED", out)
        self.assertIn("RLS001", out)

    def test_an_empty_project_is_not_graded_blocked(self):
        code, out = self.run_cli()
        self.assertEqual(code, 0)
        self.assertNotIn("BLOCKED", out)

    def test_coverage_is_always_printed(self):
        _, out = self.run_cli()
        self.assertIn("Coverage", out)
        for scanner in sc.SCANNERS:
            self.assertIn(scanner.plugin, out)
        self.assertIn(sc.HOOK_PLUGIN, out)

    def test_missing_scanners_are_named_and_downgrade_the_verdict(self):
        with tempfile.TemporaryDirectory() as empty:
            _, out = self.run_cli("--scanners", empty)
        self.assertIn("INCOMPLETE", out)
        self.assertIn("MISSING", out)
        self.assertIn("not installed", out)

    def test_require_full_coverage_fails_when_a_scanner_is_missing(self):
        """Nothing found is not a pass when nothing ran."""
        with tempfile.TemporaryDirectory() as empty:
            code, _ = self.run_cli("--scanners", empty, "--require-full-coverage")
        self.assertEqual(code, 1)

    def test_strict_alone_does_not_fail_on_missing_coverage(self):
        """Two different failures, two different flags. Conflating them made
        the primary CI use case fail closed for a coverage reason rather than
        a security one, every time a scanner was not installed."""
        with tempfile.TemporaryDirectory() as empty:
            code, _ = self.run_cli("--scanners", empty, "--strict")
        self.assertEqual(code, 0)

    def test_strict_still_fails_on_a_real_finding(self):
        self.write("supabase/migrations/001.sql",
                   "create table public.profiles (id uuid primary key);\n")
        code, _ = self.run_cli("--strict")
        self.assertEqual(code, 1)

    def test_downgraded_findings_are_disclosed_in_coverage(self):
        """A CLEAR verdict must never be silent about what it demoted."""
        self.write("fixtures/schema.sql",
                   "create table public.profiles (id uuid primary key);\n")
        _, out = self.run_cli()
        self.assertIn("downgraded as test or fixture paths", out)
        self.assertIn("--include-tests", out)

    def test_review_findings_are_hidden_until_asked_for(self):
        self.write("supabase/migrations/001.sql",
                   "create table public.profiles (id uuid primary key);\n")
        _, quiet = self.run_cli()
        _, loud = self.run_cli("--all")
        self.assertGreaterEqual(len(loud), len(quiet))

    def test_json_output_is_parseable_and_shaped(self):
        self.write("supabase/migrations/001.sql",
                   "create table public.profiles (id uuid primary key);\n")
        _, out = self.run_cli("--json")
        payload = json.loads(out)
        for key in ("verdict", "reason", "coverage", "counts", "findings"):
            self.assertIn(key, payload)
        self.assertEqual(payload["verdict"], sc.BLOCKED)
        self.assertEqual(len(payload["coverage"]), len(sc.SCANNERS) + 1)

    def test_missing_directory_does_not_crash(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = sc.main(["--path", os.path.join(self.root, "nope"), "--strict"])
        self.assertEqual(code, 0)
        self.assertIn("no such directory", buffer.getvalue())

    def test_the_report_says_what_a_clear_result_does_not_mean(self):
        _, out = self.run_cli()
        self.assertIn("What a clear result does not mean", out)
        self.assertIn("snapshot", out)


if __name__ == "__main__":
    unittest.main()
