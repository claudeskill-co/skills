#!/usr/bin/env python3
"""
Regression tests for the database guard.

Stdlib `unittest` only, matching the repository's zero-dependency rule.

    python3 -m unittest discover -s tests -v

This one sits in front of every Bash command the agent runs, so the cost of
being wrong is asymmetric in both directions:

  * A false block stops ordinary work, and a guard that stops ordinary work
    gets switched off - after which it protects nothing.
  * A false pass is the Replit incident: a production database dropped during
    an explicit code freeze.

The ordinary-command suite is therefore as load-bearing as the blocking one.
"""

import json
import subprocess
import sys
import unittest
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "db-guard" / "scripts" / "db_guard.py"
sys.path.insert(0, str(SCRIPT.parent))

import db_guard as dg  # noqa: E402


class TestOrdinaryCommandsPass(unittest.TestCase):
    """Anything here being blocked would make the guard unusable."""

    ORDINARY = [
        "ls -la",
        "npm run build",
        "git commit -m 'drop table support for legacy schema'",
        "git log --oneline",
        "echo 'truncate the log file'",
        "rg 'delete from' --type ts",
        "cat migrations/001_drop_table.sql",
        "python manage.py runserver",
        "npm test",
        "docker compose up -d",
        "vim src/db/drop_table.ts",
        # Real database work that is not destructive.
        'psql "$DATABASE_URL" -c "select count(*) from users"',
        'psql -h localhost -c "insert into users (email) values (\'a@b.c\')"',
        "supabase db diff",
        "supabase migration new add_orders",
        "prisma migrate dev --name add_orders",
        "prisma generate",
        # Qualified writes are ordinary work. The quoted value in the SET clause
        # is the case a single-regex version gets wrong.
        'psql "$DATABASE_URL" -c "delete from sessions where expires_at < now()"',
        'psql "$DATABASE_URL" -c "update users set name = \'x\' where id = 3"',
        'psql "$DATABASE_URL" -c "update users set plan = \'pro\', seats = 5 where org_id = 9"',
        'psql "$DATABASE_URL" -c "delete from logs where created_at < now() - interval \'30 days\'"',
    ]

    def test_ordinary_commands_are_allowed(self):
        for command in self.ORDINARY:
            with self.subTest(command):
                self.assertEqual(dg.classify(command).action, dg.ALLOW, command)

    def test_empty_command_is_allowed(self):
        self.assertEqual(dg.classify("").action, dg.ALLOW)
        self.assertEqual(dg.classify("   ").action, dg.ALLOW)

    def test_sql_words_without_a_database_tool_are_ignored(self):
        # The single most important false-positive class: prose and filenames.
        for command in ["echo 'drop table users'", "grep -r 'truncate table' .",
                        "touch drop_table.sql", "git commit -m 'truncate logs'"]:
            with self.subTest(command):
                self.assertEqual(dg.classify(command).action, dg.ALLOW, command)


class TestBlocksProduction(unittest.TestCase):
    """The Replit case: destructive, and not aimed at a local database."""

    def test_drop_table_against_env_url_is_denied(self):
        verdict = dg.classify('psql "$DATABASE_URL" -c "drop table users"')
        self.assertEqual(verdict.action, dg.DENY)
        self.assertEqual(verdict.matched, "drop-table")
        self.assertIn("cannot be read here", verdict.reason)

    def test_drop_database_against_hosted_postgres(self):
        verdict = dg.classify('psql postgres://u:p@db.abcdef.supabase.co:5432/postgres '
                              '-c "drop database postgres"')
        self.assertEqual(verdict.action, dg.DENY)
        self.assertEqual(verdict.target, dg.REMOTE)

    def test_supabase_reset_linked_is_denied(self):
        verdict = dg.classify("supabase db reset --linked")
        self.assertEqual(verdict.action, dg.DENY)
        self.assertEqual(verdict.matched, "supabase-db-reset")

    def test_supabase_reset_with_project_ref_is_denied(self):
        self.assertEqual(dg.classify("supabase db reset --project-ref abcdefgh").action, dg.DENY)

    def test_unqualified_delete_against_remote(self):
        verdict = dg.classify('psql "$DATABASE_URL" -c "delete from users"')
        self.assertEqual(verdict.action, dg.DENY)
        self.assertEqual(verdict.matched, "delete-no-where")

    def test_unqualified_update_against_remote(self):
        verdict = dg.classify('psql "$DATABASE_URL" -c "update users set plan = \'free\'"')
        self.assertEqual(verdict.action, dg.DENY)
        self.assertEqual(verdict.matched, "update-no-where")

    def test_one_qualified_statement_does_not_excuse_an_unqualified_one(self):
        # Two statements, one safe, one not. The unsafe one must still be caught.
        verdict = dg.classify(
            'psql "$DATABASE_URL" -c "delete from a where id = 1; delete from users"')
        self.assertEqual(verdict.action, dg.DENY)
        self.assertEqual(verdict.matched, "delete-no-where")

    def test_truncate_against_neon(self):
        self.assertEqual(
            dg.classify('psql postgres://u:p@ep-x.neon.tech/db -c "truncate orders"').action,
            dg.DENY)

    def test_host_flag_pointing_off_machine(self):
        self.assertEqual(dg.classify('psql -h db.internal.example.com -c "drop table t"').action,
                         dg.DENY)

    def test_prod_in_the_command_is_a_signal(self):
        self.assertEqual(dg.classify('psql -d app_production -c "truncate users"').action, dg.DENY)

    def test_redis_flushall_against_upstash(self):
        self.assertEqual(dg.classify("redis-cli -u redis://x.upstash.io flushall").action, dg.DENY)

    def test_dropdb_is_caught_without_sql(self):
        self.assertEqual(dg.classify("dropdb --host=db.prod.example.com appdb").action, dg.DENY)

    def test_prisma_accept_data_loss(self):
        self.assertEqual(
            dg.classify('DATABASE_URL=$PROD_URL prisma db push --accept-data-loss').action,
            dg.DENY)


class TestAsksOnLocal(unittest.TestCase):
    """Destructive but local: confirm, do not block. Resetting a dev database
    is normal, and blocking it is how the guard gets disabled."""

    def test_local_drop_table_asks(self):
        verdict = dg.classify('psql -h localhost -c "drop table users"')
        self.assertEqual(verdict.action, dg.ASK)
        self.assertEqual(verdict.target, dg.LOCAL)

    def test_bare_supabase_db_reset_asks(self):
        verdict = dg.classify("supabase db reset")
        self.assertEqual(verdict.action, dg.ASK)
        self.assertIn("probably fine", verdict.reason)

    def test_supabase_local_port_asks(self):
        self.assertEqual(
            dg.classify('psql postgres://postgres:postgres@127.0.0.1:54322/postgres '
                        '-c "truncate users"').action,
            dg.ASK)

    def test_sqlite_file_asks(self):
        self.assertEqual(dg.classify('sqlite3 dev.db "drop table users"').action, dg.ASK)

    def test_rails_db_reset_asks(self):
        self.assertEqual(dg.classify("rails db:reset").action, dg.ASK)

    def test_prisma_migrate_reset_without_url_asks(self):
        self.assertEqual(dg.classify("prisma migrate reset").action, dg.ASK)


class TestTargetClassification(unittest.TestCase):
    def test_local_hosts(self):
        for host in ["localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"]:
            with self.subTest(host):
                self.assertEqual(
                    dg.classify_target("psql postgres://u:p@%s:5432/db" % host), dg.LOCAL)

    def test_hosted_providers_are_remote(self):
        for host in ["db.x.supabase.co", "ep-a.neon.tech", "x.rds.amazonaws.com",
                     "y.railway.app", "z.fly.dev", "q.upstash.io"]:
            with self.subTest(host):
                self.assertEqual(
                    dg.classify_target("psql postgres://u:p@%s/db" % host), dg.REMOTE)

    def test_env_variable_is_unknown_not_local(self):
        self.assertEqual(dg.classify_target('psql "$DATABASE_URL"'), dg.UNKNOWN)

    def test_unknown_is_treated_as_production(self):
        # The whole safety argument rests on this.
        verdict = dg.classify('psql "$DATABASE_URL" -c "drop table t"')
        self.assertEqual(verdict.target, dg.UNKNOWN)
        self.assertEqual(verdict.action, dg.DENY)


class TestHookProtocol(unittest.TestCase):
    def _event(self, command, tool="Bash"):
        return json.dumps({
            "session_id": "test", "cwd": "/tmp", "hook_event_name": "PreToolUse",
            "tool_name": tool, "tool_input": {"command": command},
        })

    def _run(self, command, tool="Bash", env=None):
        import os
        environment = dict(os.environ)
        if env:
            environment.update(env)
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--hook"],
            input=self._event(command, tool), capture_output=True, text=True, env=environment,
        )

    def test_allow_is_silent_and_exits_zero(self):
        result = self._run("ls -la")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")
        self.assertEqual(result.stderr.strip(), "")

    def test_deny_exits_two_with_json_on_stderr(self):
        result = self._run('psql "$DATABASE_URL" -c "drop table users"')
        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stderr)
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(payload["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertIn("Blocked", payload["hookSpecificOutput"]["permissionDecisionReason"])

    def test_ask_exits_zero_with_json_on_stdout(self):
        result = self._run("supabase db reset")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_non_bash_tools_are_ignored(self):
        result = self._run("drop table users", tool="Read")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")

    def test_malformed_event_never_breaks_the_session(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--hook"],
            input="not json at all", capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)

    def test_empty_stdin_is_survivable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--hook"],
            input="", capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)

    def test_kill_switch(self):
        result = self._run('psql "$DATABASE_URL" -c "drop table users"',
                           env={"DB_GUARD_DISABLE": "1"})
        self.assertEqual(result.returncode, 0)

    def test_run_hook_accepts_a_stream(self):
        code = dg.run_hook(StringIO(self._event("ls")))
        self.assertEqual(code, 0)


class TestCli(unittest.TestCase):
    def test_command_mode_prints_a_verdict(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--command", 'psql "$DATABASE_URL" -c "drop table t"'],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("DENY", result.stdout)

    def test_json_mode(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--command", "supabase db reset", "--json"],
            capture_output=True, text=True,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["action"], "ask")
        self.assertEqual(payload["matched"], "supabase-db-reset")

    def test_no_arguments_prints_help(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
