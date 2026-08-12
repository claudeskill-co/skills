#!/usr/bin/env python3
"""
Regression tests for the RLS auditor.

Stdlib `unittest` only, matching the repository's zero-dependency rule.

    python3 -m unittest discover -s tests -v

Two invariants carry this tool, and both are locked here:

  * A correct project produces zero findings. A scanner that cries wolf on
    well-written code gets muted, and a muted scanner protects nobody.
  * Every finding points at a real line. A finding that cannot be verified
    in ten seconds will be dismissed, however true it is.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "rls-audit" / "scripts" / "rls_audit.py"
sys.path.insert(0, str(SCRIPT.parent))

import rls_audit as ra  # noqa: E402


class Project:
    """A throwaway project tree on disk."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def audit(self) -> ra.Report:
        return ra.audit(str(self.root))

    def codes(self):
        return sorted(f.code for f in self.audit().findings)

    def close(self) -> None:
        self._tmp.cleanup()


class ProjectCase(unittest.TestCase):
    def setUp(self) -> None:
        self.project = Project()
        self.addCleanup(self.project.close)


# --------------------------------------------------------------------------
# The quiet case: correct code must stay silent
# --------------------------------------------------------------------------

SECURE_MIGRATION = """
-- Profiles, locked to their owner.
create table public.profiles (
  id uuid primary key references auth.users,
  email text
);
alter table public.profiles enable row level security;

create policy "own profile readable" on public.profiles
  for select to authenticated
  using (auth.uid() = id);

create policy "own profile writable" on public.profiles
  for update to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);
"""


class TestNoFalsePositives(ProjectCase):
    def test_correct_project_is_silent(self):
        self.project.write("supabase/migrations/001_init.sql", SECURE_MIGRATION)
        self.project.write("app/page.tsx", "export default function Page() { return <div>hi</div>; }\n")
        self.assertEqual(self.project.codes(), [])

    def test_anon_key_is_not_a_finding(self):
        # The anon key is public by design. Flagging it would train people to ignore us.
        anon = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            + ra.base64.urlsafe_b64encode(b'{"role":"anon"}').decode().rstrip("=")
            + ".c2lnbmF0dXJl"
        )
        self.project.write("lib/supabase.ts", 'export const key = "%s";\n' % anon)
        self.assertEqual(self.project.codes(), [])

    def test_public_env_var_without_secret_in_name_is_ignored(self):
        self.project.write(".env.local", "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\n")
        self.assertEqual(self.project.codes(), [])

    def test_commented_out_sql_is_not_parsed(self):
        self.project.write("db/x.sql", "-- create table public.ghost (id int);\n/* drop table public.other; */\n")
        report = self.project.audit()
        self.assertEqual(report.tables, [])
        self.assertEqual(report.findings, [])

    def test_non_public_schema_is_not_flagged(self):
        # Only the public schema is exposed through the API, so RLS absence
        # elsewhere is not the same defect.
        self.project.write("db/x.sql", "create table internal.audit_log (id int);\n")
        self.assertEqual(self.project.codes(), [])

    def test_dropped_table_is_not_reported(self):
        self.project.write("db/1.sql", "create table public.temp_thing (id int);\n")
        self.project.write("db/2.sql", "drop table public.temp_thing;\n")
        self.assertEqual(self.project.codes(), [])

    def test_route_with_auth_check_is_not_flagged(self):
        self.project.write(
            "app/api/admin/route.ts",
            "const { data } = await supabase.auth.getUser();\n"
            "if (!data.user) return new Response('no', { status: 401 });\n"
            "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n",
        )
        self.assertEqual(self.project.codes(), [])

    def test_server_component_may_read_the_service_key(self):
        self.project.write("lib/admin.ts", "const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n")
        self.assertEqual(self.project.codes(), [])

    def test_build_output_is_skipped(self):
        self.project.write(".next/static/chunk.js", "const k = 'sb_secret_abcdefghijklmno';\n")
        self.project.write("node_modules/pkg/index.js", "const k = 'sb_secret_abcdefghijklmno';\n")
        self.assertEqual(self.project.codes(), [])


# --------------------------------------------------------------------------
# RLS coverage
# --------------------------------------------------------------------------

class TestRlsCoverage(ProjectCase):
    def test_table_without_rls_is_critical(self):
        self.project.write("supabase/migrations/1.sql", "create table public.orders (id int, total numeric);\n")
        findings = self.project.audit().findings
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, "RLS001")
        self.assertEqual(findings[0].severity, ra.CRITICAL)
        self.assertEqual(findings[0].confidence, ra.FACT)
        self.assertIn("public.orders", findings[0].detail)

    def test_if_not_exists_and_quoting_are_handled(self):
        self.project.write("db/1.sql", 'create table if not exists "public"."Orders" (id int);\n')
        report = self.project.audit()
        self.assertEqual(report.tables, ["public.Orders"])
        self.assertEqual([f.code for f in report.findings], ["RLS001"])

    def test_unqualified_table_defaults_to_public(self):
        self.project.write("db/1.sql", "create table notes (id int);\n")
        self.assertEqual(self.project.audit().tables, ["public.notes"])

    def test_explicitly_disabled_rls_is_critical(self):
        self.project.write(
            "db/1.sql",
            "create table public.notes (id int);\n"
            "alter table public.notes disable row level security;\n",
        )
        findings = self.project.audit().findings
        self.assertEqual([f.code for f in findings], ["RLS001"])
        self.assertIn("switched off", findings[0].detail)

    def test_rls_enabled_without_policy_is_medium(self):
        self.project.write(
            "db/1.sql",
            "create table public.notes (id int);\n"
            "alter table public.notes enable row level security;\n",
        )
        findings = self.project.audit().findings
        self.assertEqual([f.code for f in findings], ["RLS002"])
        self.assertEqual(findings[0].severity, ra.MEDIUM)

    def test_enable_and_policy_across_separate_files(self):
        self.project.write("db/1_table.sql", "create table public.notes (id int);\n")
        self.project.write("db/2_rls.sql", "alter table public.notes enable row level security;\n")
        self.project.write(
            "db/3_policy.sql",
            'create policy "own" on public.notes for select using (auth.uid() = owner);\n',
        )
        self.assertEqual(self.project.codes(), [])

    def test_line_number_points_at_the_statement(self):
        self.project.write("db/1.sql", "-- header\n\ncreate table public.notes (id int);\n")
        finding = self.project.audit().findings[0]
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.path, os.path.join("db", "1.sql"))


# --------------------------------------------------------------------------
# Permissive policies
# --------------------------------------------------------------------------

class TestPermissivePolicies(ProjectCase):
    def _with_policy(self, policy_sql: str):
        self.project.write(
            "db/1.sql",
            "create table public.notes (id int);\n"
            "alter table public.notes enable row level security;\n"
            + policy_sql,
        )
        return self.project.audit().findings

    def test_public_select_true_is_high(self):
        findings = self._with_policy('create policy "open" on public.notes for select using (true);\n')
        self.assertEqual([f.code for f in findings], ["RLS003"])
        self.assertEqual(findings[0].severity, ra.HIGH)

    def test_authenticated_select_true_is_medium(self):
        findings = self._with_policy(
            'create policy "open" on public.notes for select to authenticated using (true);\n'
        )
        self.assertEqual([f.code for f in findings], ["RLS003"])
        self.assertEqual(findings[0].severity, ra.MEDIUM)

    def test_public_write_true_is_critical(self):
        findings = self._with_policy('create policy "open" on public.notes for all using (true);\n')
        self.assertEqual([f.code for f in findings], ["RLS004"])
        self.assertEqual(findings[0].severity, ra.CRITICAL)

    def test_authenticated_write_true_is_high_not_critical(self):
        findings = self._with_policy(
            'create policy "open" on public.notes for update to authenticated using (true);\n'
        )
        self.assertEqual([f.code for f in findings], ["RLS004"])
        self.assertEqual(findings[0].severity, ra.HIGH)

    def test_with_check_true_is_reported(self):
        findings = self._with_policy(
            'create policy "ins" on public.notes for insert to anon with check (true);\n'
        )
        self.assertEqual([f.code for f in findings], ["RLS005"])
        self.assertEqual(findings[0].severity, ra.CRITICAL)

    def test_nested_parens_still_read_as_true(self):
        findings = self._with_policy('create policy "open" on public.notes for select using ((true));\n')
        self.assertEqual([f.code for f in findings], ["RLS003"])

    def test_real_predicate_is_not_flagged(self):
        self.assertEqual(
            self._with_policy(
                'create policy "own" on public.notes for select using (auth.uid() = owner_id);\n'
            ),
            [],
        )

    def test_predicate_mentioning_true_is_not_flagged(self):
        self.assertEqual(
            self._with_policy(
                'create policy "pub" on public.notes for select using (is_published = true);\n'
            ),
            [],
        )

    def test_default_command_is_all(self):
        # No `for` clause means ALL in Postgres, so `using (true)` is a write hole.
        findings = self._with_policy('create policy "open" on public.notes using (true);\n')
        self.assertEqual([f.code for f in findings], ["RLS004"])


class TestSqlHelpers(unittest.TestCase):
    def test_blank_comments_preserves_offsets(self):
        sql = "create table a;\n-- comment\ncreate table b;\n"
        blanked = ra.blank_comments(sql)
        self.assertEqual(len(blanked), len(sql))
        self.assertEqual(blanked.count("\n"), sql.count("\n"))
        self.assertNotIn("comment", blanked)

    def test_string_literal_containing_dashes_survives(self):
        sql = "insert into t values ('a--b');\n"
        self.assertIn("a--b", ra.blank_comments(sql))

    def test_is_always_true(self):
        for expression in ("true", " TRUE ", "(true)", "((  true ))"):
            self.assertTrue(ra.is_always_true(expression), expression)
        for expression in ("auth.uid() = id", "is_public = true", "true and false"):
            self.assertFalse(ra.is_always_true(expression), expression)


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

def service_role_jwt() -> str:
    payload = ra.base64.urlsafe_b64encode(b'{"role":"service_role"}').decode().rstrip("=")
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.%s.c2lnbmF0dXJl" % payload


class TestSecrets(ProjectCase):
    def test_service_role_jwt_is_critical(self):
        self.project.write("lib/db.ts", 'const key = "%s";\n' % service_role_jwt())
        findings = self.project.audit().findings
        self.assertEqual([f.code for f in findings], ["KEY001"])
        self.assertEqual(findings[0].severity, ra.CRITICAL)

    def test_sb_secret_key_is_critical(self):
        self.project.write("lib/db.ts", 'const key = "sb_secret_9aBcDeFgHiJkLmNo";\n')
        self.assertEqual(self.project.codes(), ["KEY001"])

    def test_public_prefixed_service_var_in_code(self):
        self.project.write("lib/db.ts", "process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n")
        self.assertEqual(self.project.codes(), ["KEY002"])

    def test_public_prefixed_secret_in_env_file_with_value(self):
        self.project.write(".env.local", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=abc123\n")
        self.assertEqual(self.project.codes(), ["KEY002"])

    def test_empty_placeholder_in_env_example_is_ignored(self):
        self.project.write(".env.example", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n")
        self.assertEqual(self.project.codes(), [])

    def test_service_key_in_client_component(self):
        self.project.write(
            "components/Panel.tsx",
            "'use client'\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n",
        )
        self.assertEqual(self.project.codes(), ["KEY003"])


# --------------------------------------------------------------------------
# Where the decision is made
# --------------------------------------------------------------------------

class TestAccessControl(ProjectCase):
    def test_client_side_gate_is_review_only(self):
        self.project.write(
            "components/Paywall.tsx",
            "'use client'\nexport default function P({ isPro }) {\n"
            "  return <div>{isPro && <PremiumReport />}</div>;\n}\n",
        )
        findings = self.project.audit().findings
        self.assertEqual([f.code for f in findings], ["GATE001"])
        self.assertEqual(findings[0].severity, ra.REVIEW)
        self.assertEqual(findings[0].confidence, ra.HEURISTIC)

    def test_server_component_gate_is_not_flagged(self):
        self.project.write(
            "app/report/page.tsx",
            "export default function P({ isPro }) { return <div>{isPro && <R />}</div>; }\n",
        )
        self.assertEqual(self.project.codes(), [])

    def test_route_using_service_role_without_auth(self):
        self.project.write(
            "app/api/users/route.ts",
            "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n"
            "export async function GET() { return Response.json(await admin.from('users').select()); }\n",
        )
        findings = self.project.audit().findings
        self.assertEqual([f.code for f in findings], ["API001"])
        self.assertEqual(findings[0].severity, ra.HIGH)
        self.assertEqual(findings[0].confidence, ra.HEURISTIC)

    def test_pages_api_route_is_covered_too(self):
        self.project.write(
            "pages/api/users.ts",
            "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n",
        )
        self.assertEqual(self.project.codes(), ["API001"])

    def test_only_one_gate_finding_per_file(self):
        self.project.write(
            "components/Many.tsx",
            "'use client'\n" + "<div>{isPro && <A />}</div>\n" * 5,
        )
        self.assertEqual(self.project.codes(), ["GATE001"])


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
        self.assertIn("Nothing to scan", result.stdout)

    def test_json_output_is_valid(self):
        self.project.write("db/1.sql", "create table public.notes (id int);\n")
        result = self._run("--path", str(self.project.root), "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["counts"]["critical"], 1)
        self.assertEqual(payload["findings"][0]["code"], "RLS001")
        self.assertEqual(payload["tables"], ["public.notes"])

    def test_strict_fails_on_critical(self):
        self.project.write("db/1.sql", "create table public.notes (id int);\n")
        self.assertEqual(self._run("--path", str(self.project.root), "--strict").returncode, 1)

    def test_strict_passes_on_clean_project(self):
        self.project.write("db/1.sql", SECURE_MIGRATION)
        self.assertEqual(self._run("--path", str(self.project.root), "--strict").returncode, 0)

    def test_strict_does_not_fail_on_review_only(self):
        # Heuristics must never break someone's build.
        self.project.write("components/P.tsx", "'use client'\n<div>{isPro && <A />}</div>\n")
        self.assertEqual(self._run("--path", str(self.project.root), "--strict").returncode, 0)

    def test_report_states_its_limits(self):
        result = self._run("--path", str(self.project.root))
        self.assertIn("What this cannot tell you", result.stdout)


if __name__ == "__main__":
    unittest.main()
