#!/usr/bin/env python3
"""
Regression tests for the deploy checker.

Stdlib `unittest` only, matching the repository's zero-dependency rule.

    python3 -m unittest discover -s tests -v

Most findings here are absences - no headers, no limiter, no health endpoint -
and an absence is the easiest thing in the world to report wrongly. The
false-positive suites exist to keep this tool from telling a well-configured
project that it is broken, and from reporting the same absence forty times.
"""

import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "deploy-check" / "scripts" / "deploy_check.py"
sys.path.insert(0, str(SCRIPT.parent))

import deploy_check as dc  # noqa: E402


HEADERS_CONFIG = """
const nextConfig = {
  async headers() {
    return [{
      source: "/(.*)",
      headers: [
        { key: "X-Frame-Options", value: "DENY" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      ],
    }];
  },
};
export default nextConfig;
"""


class ProjectCase(unittest.TestCase):

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
        return path

    def scaffold(self):
        """A well-configured project. Nothing in here may be reported."""
        self.write("package.json", '{"name": "app", "version": "1.0.0"}')
        self.write("next.config.mjs", HEADERS_CONFIG)
        self.write(".env.example", "DATABASE_URL=\nSUPABASE_URL=\nRESEND_API_KEY=\n")
        self.write(".env.local", "DATABASE_URL=postgres://dev@localhost:5432/app\n"
                                 "SUPABASE_URL=https://dev.supabase.co\n"
                                 "RESEND_API_KEY=re_local\n")
        self.write("app/api/health/route.ts",
                   "export async function GET() { return Response.json({ ok: true }); }")
        self.write("lib/db.ts", "export const url = process.env.DATABASE_URL;\n")

    def audit(self):
        return dc.audit(self.root)

    def codes(self):
        return [f.code for f in self.audit().sorted_findings()]

    def finding(self, code):
        matches = [f for f in self.audit().findings if f.code == code]
        self.assertTrue(matches, "expected a %s finding, got %s" % (code, self.codes()))
        return matches[0]


class TestWellConfiguredProjectIsSilent(ProjectCase):

    def test_scaffold_produces_nothing(self):
        self.scaffold()
        self.assertEqual(self.codes(), [])

    def test_empty_directory_produces_nothing(self):
        report = self.audit()
        self.assertEqual(report.findings, [])
        self.assertFalse(report.is_project)

    def test_headers_in_vercel_json_count(self):
        self.scaffold()
        self.write("next.config.mjs", "export default {};\n")
        self.write("vercel.json", '{"headers": [{"source": "/(.*)", "headers": []}]}')
        self.assertNotIn("DEP005", self.codes())

    def test_headers_in_middleware_count(self):
        self.scaffold()
        self.write("next.config.mjs", "export default {};\n")
        self.write("middleware.ts", """
export function middleware(request) {
  const res = NextResponse.next();
  res.headers.set("X-Frame-Options", "DENY");
  return res;
}
""")
        self.assertNotIn("DEP005", self.codes())


class TestEnvDrift(ProjectCase):

    def test_variable_used_but_undocumented(self):
        self.scaffold()
        self.write("lib/mail.ts", "export const key = process.env.POSTMARK_TOKEN;\n")
        finding = self.finding("DEP001")
        self.assertIn("POSTMARK_TOKEN", finding.title)
        self.assertEqual(finding.severity, dc.MEDIUM)
        self.assertEqual(finding.path, "lib/mail.ts")

    def test_platform_variables_are_never_reported(self):
        """Asking someone to document NODE_ENV is noise, and noise gets tools muted."""
        self.scaffold()
        self.write("lib/env.ts", """
export const isProd = process.env.NODE_ENV === "production";
export const url = process.env.VERCEL_URL;
export const port = process.env.PORT;
""")
        self.assertEqual(self.codes(), [])

    def test_bracket_and_vite_and_deno_access_are_all_seen(self):
        self.scaffold()
        self.write("lib/a.ts", 'export const a = process.env["ALPHA_KEY"];\n')
        self.write("lib/b.ts", "export const b = import.meta.env.BETA_KEY;\n")
        self.write("lib/c.ts", 'export const c = Deno.env.get("GAMMA_KEY");\n')
        titles = " ".join(f.title for f in self.audit().findings)
        for name in ("ALPHA_KEY", "BETA_KEY", "GAMMA_KEY"):
            self.assertIn(name, titles)

    def test_python_environ_access_is_seen(self):
        self.scaffold()
        self.write("worker/main.py", 'import os\nKEY = os.environ["WORKER_TOKEN"]\n')
        self.assertIn("WORKER_TOKEN", " ".join(f.title for f in self.audit().findings))

    def test_many_missing_variables_collapse_into_one_extra_finding(self):
        self.scaffold()
        body = "\n".join("export const v%d = process.env.VAR_%d;" % (i, i) for i in range(12))
        self.write("lib/many.ts", body)
        findings = [f for f in self.audit().findings if f.code == "DEP001"]
        self.assertEqual(len(findings), dc.MAX_ENV_FINDINGS + 1)
        self.assertIn("4 more variables", findings[-1].title)

    def test_local_only_variable_is_review_not_medium(self):
        self.scaffold()
        self.write(".env.local", "DATABASE_URL=postgres://dev@localhost:5432/app\n"
                                 "SUPABASE_URL=https://dev.supabase.co\n"
                                 "RESEND_API_KEY=re_local\n"
                                 "OLD_FEATURE_FLAG=true\n")
        finding = self.finding("DEP002")
        self.assertEqual(finding.severity, dc.REVIEW)
        self.assertIn("OLD_FEATURE_FLAG", finding.detail)

    def test_local_only_variables_collapse_into_one_finding(self):
        """Found on a real project: eight review lines for the weakest signal
        this tool produces is how a whole report gets skimmed past."""
        self.scaffold()
        extra = "".join("DEAD_FLAG_%d=1\n" % i for i in range(11))
        self.write(".env.local", "DATABASE_URL=postgres://dev@localhost:5432/app\n"
                                 "SUPABASE_URL=x\nRESEND_API_KEY=x\n" + extra)
        findings = [f for f in self.audit().findings if f.code == "DEP002"]
        self.assertEqual(len(findings), 1)
        self.assertIn("11 variable(s)", findings[0].title)
        self.assertIn("and 3 more", findings[0].detail)

    def test_claude_code_variables_are_not_app_config(self):
        """CLAUDE_PROJECT_DIR is handed to hook scripts, not set by a deploy."""
        self.scaffold()
        self.write("scripts/hook.py", 'import os\nroot = os.environ["CLAUDE_PROJECT_DIR"]\n')
        self.assertEqual(self.codes(), [])

    def test_documented_variable_is_silent(self):
        self.scaffold()
        self.write(".env.example", "DATABASE_URL=\nSUPABASE_URL=\nRESEND_API_KEY=\nPOSTMARK_TOKEN=\n")
        self.write("lib/mail.ts", "export const key = process.env.POSTMARK_TOKEN;\n")
        self.assertEqual(self.codes(), [])

    def test_no_example_file_is_one_review_finding(self):
        self.write("package.json", '{"name": "app"}')
        self.write("next.config.mjs", HEADERS_CONFIG)
        self.write("lib/db.ts", "export const url = process.env.DATABASE_URL;\n"
                                "export const key = process.env.SECRET_TOKEN;\n")
        findings = [f for f in self.audit().findings if f.code == "DEP001"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, dc.REVIEW)
        self.assertIn("No env template", findings[0].title)

    def test_variables_in_test_files_are_not_counted(self):
        self.scaffold()
        self.write("tests/setup.ts", "process.env.FAKE_TEST_KEY = 'x';\n")
        self.assertEqual(self.codes(), [])


class TestDatabaseSeparation(ProjectCase):

    def test_same_remote_database_in_dev_and_prod(self):
        self.scaffold()
        shared = "postgres://user:pw@db.abcdefgh.supabase.co:5432/postgres"
        self.write(".env.local", "DATABASE_URL=%s\nSUPABASE_URL=https://dev.supabase.co\n"
                                 "RESEND_API_KEY=x\n" % shared)
        self.write(".env.production", "DATABASE_URL=%s\n" % shared)
        finding = self.finding("DEP003")
        self.assertEqual(finding.severity, dc.HIGH)
        self.assertEqual(finding.confidence, dc.FACT)
        self.assertIn("db.abcdefgh.supabase.co", finding.detail)

    def test_the_value_is_never_printed_in_full(self):
        """A report that quotes a connection string leaks the password it contains."""
        self.scaffold()
        shared = "postgres://user:sup3rs3cret@db.abcdefgh.supabase.co:5432/postgres"
        self.write(".env.local", "DATABASE_URL=%s\nSUPABASE_URL=x\nRESEND_API_KEY=x\n" % shared)
        self.write(".env.production", "DATABASE_URL=%s\n" % shared)
        finding = self.finding("DEP003")
        blob = " ".join([finding.title, finding.detail, finding.fix])
        self.assertNotIn("sup3rs3cret", blob)
        self.assertNotIn(shared, blob)

    def test_different_databases_are_silent(self):
        self.scaffold()
        self.write(".env.local", "DATABASE_URL=postgres://u@db.dev.supabase.co:5432/postgres\n"
                                 "SUPABASE_URL=x\nRESEND_API_KEY=x\n")
        self.write(".env.production", "DATABASE_URL=postgres://u@db.prod.supabase.co:5432/postgres\n")
        self.assertNotIn("DEP003", self.codes())

    def test_shared_localhost_is_not_a_finding(self):
        """Both pointing at localhost means neither is production."""
        self.scaffold()
        self.write(".env.local", "DATABASE_URL=postgres://u@localhost:5432/app\n"
                                 "SUPABASE_URL=x\nRESEND_API_KEY=x\n")
        self.write(".env.production", "DATABASE_URL=postgres://u@localhost:5432/app\n")
        self.assertNotIn("DEP003", self.codes())

    def test_empty_values_are_not_matched_against_each_other(self):
        self.scaffold()
        self.write(".env.local", "DATABASE_URL=\nSUPABASE_URL=x\nRESEND_API_KEY=x\n")
        self.write(".env.production", "DATABASE_URL=\n")
        self.assertNotIn("DEP003", self.codes())


class TestBuildConfig(ProjectCase):

    def test_ignore_build_errors(self):
        self.scaffold()
        self.write("next.config.mjs", HEADERS_CONFIG +
                   "\nexport const extra = { typescript: { ignoreBuildErrors: true } };\n")
        self.assertEqual(self.finding("DEP004").severity, dc.MEDIUM)

    def test_ignore_lint_during_builds(self):
        self.scaffold()
        self.write("next.config.mjs", HEADERS_CONFIG +
                   "\nexport const extra = { eslint: { ignoreDuringBuilds: true } };\n")
        self.assertIn("DEP004", self.codes())

    def test_production_source_maps(self):
        self.scaffold()
        self.write("next.config.mjs", HEADERS_CONFIG +
                   "\nexport const extra = { productionBrowserSourceMaps: true };\n")
        self.assertEqual(self.finding("DEP006").severity, dc.MEDIUM)

    def test_commented_out_config_is_not_a_finding(self):
        self.scaffold()
        self.write("next.config.mjs", HEADERS_CONFIG +
                   "\n// export const extra = { typescript: { ignoreBuildErrors: true } };\n")
        self.assertNotIn("DEP004", self.codes())

    def test_static_export_with_server_routes(self):
        self.scaffold()
        self.write("next.config.mjs", HEADERS_CONFIG + '\nexport const extra = { output: "export" };\n')
        self.write("app/api/subscribe/route.ts",
                   "export async function POST() { return Response.json({}); }")
        finding = self.finding("DEP008")
        self.assertEqual(finding.severity, dc.HIGH)

    def test_static_export_without_server_routes_is_fine(self):
        """A genuinely static site is a correct use of it."""
        self.write("package.json", '{"name": "site"}')
        self.write("next.config.mjs", HEADERS_CONFIG + '\nexport const extra = { output: "export" };\n')
        self.write("app/page.tsx", "export default function Page() { return null; }")
        self.assertNotIn("DEP008", self.codes())


class TestCors(ProjectCase):

    def test_wildcard_origin_is_medium(self):
        self.scaffold()
        self.write("app/api/data/route.ts", """
export async function GET() {
  return new Response("[]", { headers: { "Access-Control-Allow-Origin": "*" } });
}
""")
        finding = self.finding("DEP007")
        self.assertEqual(finding.severity, dc.MEDIUM)

    def test_wildcard_with_credentials_is_high(self):
        self.scaffold()
        self.write("app/api/data/route.ts", """
export async function GET() {
  return new Response("[]", { headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",
  }});
}
""")
        finding = self.finding("DEP007")
        self.assertEqual(finding.severity, dc.HIGH)
        self.assertIn("cookies", finding.title)

    def test_explicit_origin_is_silent(self):
        self.scaffold()
        self.write("app/api/data/route.ts", """
export async function GET() {
  return new Response("[]", { headers: { "Access-Control-Allow-Origin": "https://app.example.com" } });
}
""")
        self.assertNotIn("DEP007", self.codes())


class TestRateLimitingAndHealth(ProjectCase):

    def test_sensitive_route_without_a_limiter(self):
        self.scaffold()
        self.write("app/api/auth/login/route.ts",
                   "export async function POST() { return Response.json({}); }")
        finding = self.finding("DEP009")
        self.assertEqual(finding.severity, dc.MEDIUM)

    def test_a_limiter_anywhere_clears_it(self):
        self.scaffold()
        self.write("app/api/auth/login/route.ts",
                   "export async function POST() { return Response.json({}); }")
        self.write("lib/ratelimit.ts", """
import { Ratelimit } from "@upstash/ratelimit";
export const ratelimit = new Ratelimit({ limiter: Ratelimit.slidingWindow(10, "60 s") });
""")
        self.assertNotIn("DEP009", self.codes())

    def test_one_finding_for_many_sensitive_routes(self):
        """An absence repeated across ten routes is one problem, not ten."""
        self.scaffold()
        for name in ("login", "signup", "reset", "otp", "invite"):
            self.write("app/api/auth/%s/route.ts" % name,
                       "export async function POST() { return Response.json({}); }")
        findings = [f for f in self.audit().findings if f.code == "DEP009"]
        self.assertEqual(len(findings), 1)
        self.assertIn("5 sensitive route(s)", findings[0].title)

    def test_non_sensitive_routes_do_not_demand_a_limiter(self):
        self.scaffold()
        self.write("app/api/posts/route.ts",
                   "export async function GET() { return Response.json([]); }")
        self.assertNotIn("DEP009", self.codes())

    def test_missing_health_endpoint_is_review(self):
        self.scaffold()
        os.remove(os.path.join(self.root, "app/api/health/route.ts"))
        self.write("app/api/posts/route.ts",
                   "export async function GET() { return Response.json([]); }")
        self.assertEqual(self.finding("DEP011").severity, dc.REVIEW)

    def test_health_endpoint_present_is_silent(self):
        self.scaffold()
        self.assertNotIn("DEP011", self.codes())


class TestProductionEnvValues(ProjectCase):

    def test_node_env_not_production_is_high(self):
        self.scaffold()
        self.write(".env.production", "NODE_ENV=development\n")
        finding = self.finding("DEP010")
        self.assertEqual(finding.severity, dc.HIGH)

    def test_node_env_production_is_silent(self):
        self.scaffold()
        self.write(".env.production", "NODE_ENV=production\n")
        self.assertNotIn("DEP010", self.codes())

    def test_debug_flag_on_in_production(self):
        self.scaffold()
        self.write(".env.production", "NEXT_PUBLIC_DEBUG=true\n")
        self.assertEqual(self.finding("DEP010").severity, dc.MEDIUM)

    def test_debug_flag_in_local_env_is_silent(self):
        self.scaffold()
        self.write(".env.development", "NEXT_PUBLIC_DEBUG=true\n")
        self.assertNotIn("DEP010", self.codes())


class TestLoggedEnvironment(ProjectCase):

    def test_logging_an_env_value(self):
        self.scaffold()
        self.write("app/api/debug/route.ts",
                   "export async function GET() { console.log(process.env.DATABASE_URL); }")
        self.assertEqual(self.finding("DEP012").severity, dc.MEDIUM)

    def test_logging_node_env_is_silent(self):
        """Printing which mode you are in leaks nothing."""
        self.scaffold()
        self.write("lib/boot.ts", "console.log(process.env.NODE_ENV);\n")
        self.assertNotIn("DEP012", self.codes())

    def test_commented_log_is_silent(self):
        self.scaffold()
        self.write("lib/boot.ts", "// console.log(process.env.DATABASE_URL);\n")
        self.assertNotIn("DEP012", self.codes())


class TestWalkAndHygiene(ProjectCase):

    def test_node_modules_is_skipped(self):
        self.scaffold()
        self.write("node_modules/pkg/index.js", "console.log(process.env.SOME_PACKAGE_VAR);\n")
        self.assertEqual(self.codes(), [])

    def test_agent_worktrees_are_skipped(self):
        self.scaffold()
        self.write(".claude/worktrees/a/lib/x.ts", "export const x = process.env.WORKTREE_ONLY;\n")
        self.assertEqual(self.codes(), [])

    def test_line_numbers_point_at_the_use(self):
        self.scaffold()
        self.write("lib/mail.ts", "\n\n\nexport const key = process.env.POSTMARK_TOKEN;\n")
        self.assertEqual(self.finding("DEP001").line, 4)

    def test_env_parsing_handles_export_quotes_and_comments(self):
        parsed = dc.parse_env('# comment\nexport FOO="bar"\nBAZ=\'qux\'\n\nEMPTY=\n')
        self.assertEqual(parsed["FOO"][0], "bar")
        self.assertEqual(parsed["BAZ"][0], "qux")
        self.assertEqual(parsed["EMPTY"][0], "")
        self.assertNotIn("# comment", parsed)

    def test_host_of_strips_credentials(self):
        self.assertEqual(dc.host_of("postgres://user:pw@db.example.co:5432/x"), "db.example.co")
        self.assertEqual(dc.host_of("https://abc.supabase.co"), "abc.supabase.co")
        self.assertIsNone(dc.host_of("not-a-url"))


class TestCli(ProjectCase):

    def run_cli(self, *args):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = dc.main(["--path", self.root] + list(args))
        return code, buffer.getvalue()

    def test_clean_project_exits_zero_under_strict(self):
        self.scaffold()
        code, out = self.run_cli("--strict")
        self.assertEqual(code, 0)
        self.assertIn("No deploy defects found", out)

    def test_high_finding_fails_strict(self):
        self.scaffold()
        self.write(".env.production", "NODE_ENV=development\n")
        code, _ = self.run_cli("--strict")
        self.assertEqual(code, 1)

    def test_medium_and_review_pass_strict(self):
        """A heuristic must never break someone's build."""
        self.scaffold()
        self.write("lib/mail.ts", "export const key = process.env.POSTMARK_TOKEN;\n")
        code, _ = self.run_cli("--strict")
        self.assertEqual(code, 0)

    def test_json_output_is_parseable_and_shaped(self):
        self.scaffold()
        self.write(".env.production", "NODE_ENV=development\n")
        _, out = self.run_cli("--json")
        payload = json.loads(out)
        self.assertIn("findings", payload)
        self.assertIn("counts", payload)
        self.assertEqual(payload["findings"][0]["code"], "DEP010")
        self.assertIn("file", payload["findings"][0])

    def test_missing_directory_does_not_crash(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = dc.main(["--path", os.path.join(self.root, "nope"), "--strict"])
        self.assertEqual(code, 0)
        self.assertIn("no such directory", buffer.getvalue())

    def test_report_always_states_its_limits(self):
        self.scaffold()
        _, out = self.run_cli()
        self.assertIn("What this cannot tell you", out)
        self.assertIn("hosting dashboard", out)

    def test_heuristics_are_labelled(self):
        self.scaffold()
        self.write("lib/mail.ts", "export const key = process.env.POSTMARK_TOKEN;\n")
        _, out = self.run_cli()
        self.assertIn("pattern-matched, not proven", out)


if __name__ == "__main__":
    unittest.main()
