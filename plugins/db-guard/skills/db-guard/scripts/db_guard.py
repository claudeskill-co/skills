#!/usr/bin/env python3
"""
Stop an agent from destroying a database it should not be touching.

This runs as a PreToolUse hook. Before any Bash command executes, it asks two
questions:

  1. Would this destroy data that cannot be recovered?
  2. Is it pointed at something that is not clearly a local development database?

Both yes - the command is blocked. Destructive but clearly local - the user is
asked to confirm rather than blocked, because resetting a local database is a
normal Tuesday. Neither - it passes silently, which is almost always.

The bias is deliberate: when the target cannot be determined, it is treated as
production. `psql $DATABASE_URL -c "truncate users"` is unreadable to a static
check, and in an app built this way `DATABASE_URL` usually points at hosted
Postgres.

    # as a hook (what hooks.json calls)
    python3 db_guard.py --hook < event.json

    # to check a single command by hand
    python3 db_guard.py --command 'psql $DATABASE_URL -c "drop table users"'

Standard library only. Reads stdin, writes a verdict, touches nothing else.
Set DB_GUARD_DISABLE=1 to turn it off entirely.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

ALLOW = "allow"
ASK = "ask"
DENY = "deny"

LOCAL = "local"
REMOTE = "remote"
UNKNOWN = "unknown"


@dataclass
class Verdict:
    action: str
    target: str
    reason: str = ""
    matched: str = ""

    def as_dict(self) -> dict:
        return {
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "matched": self.matched,
        }


# --------------------------------------------------------------------------
# Is a database even involved?
#
# A command that merely contains the words "drop table" is not a database
# operation. `git commit -m "drop table support"` must pass without comment.
# Something that actually talks to a database has to be present.
# --------------------------------------------------------------------------

DB_TOOL_RE = re.compile(
    r"\b(?:psql|pg_dump|pg_restore|dropdb|createdb|mysql|mysqladmin|mariadb|"
    r"sqlite3|mongo|mongosh|mongodump|redis-cli|"
    r"supabase|prisma|drizzle-kit|knex|sequelize|typeorm|atlas|flyway|liquibase|"
    r"rails|rake|manage\.py|artisan|alembic|goose|dbmate|turso|wrangler|neonctl)\b"
)

# --------------------------------------------------------------------------
# What counts as unrecoverable
# --------------------------------------------------------------------------

@dataclass
class Rule:
    name: str
    regex: "re.Pattern[str]"
    what: str


SQL_RULES: List[Rule] = [
    Rule("drop-database", re.compile(r"\bdrop\s+database\b", re.I),
         "drops an entire database"),
    Rule("drop-schema", re.compile(r"\bdrop\s+schema\b", re.I),
         "drops a schema and everything in it"),
    Rule("drop-table", re.compile(r"\bdrop\s+table\b", re.I),
         "drops a table and all of its rows"),
    Rule("drop-column", re.compile(r"\balter\s+table\s+\S+\s+drop\s+column\b", re.I),
         "drops a column and the data in it"),
    Rule("truncate", re.compile(r"\btruncate\s+(?:table\s+)?\S", re.I),
         "empties a table"),
]

# DELETE / UPDATE are only unrecoverable when unqualified. `delete from users
# where id = 3` is ordinary work and must not be flagged.
#
# This is scoped to the statement rather than matched in one expression: a
# single regex has to guess where the statement ends, and quoted values inside
# a SET clause ("set name = 'x' where id = 3") end it in the wrong place. That
# misreads a qualified update as a table-wide one, which is exactly the false
# block that gets the guard switched off.
DELETE_HEAD_RE = re.compile(r"\bdelete\s+from\s+[\"'`\w.]+", re.I)
UPDATE_HEAD_RE = re.compile(r"\bupdate\s+[\"'`\w.]+\s+set\b", re.I)
WHERE_RE = re.compile(r"\bwhere\b", re.I)


def _statement_rest(command: str, start: int) -> str:
    """Everything from `start` to the end of that SQL statement."""
    end = command.find(";", start)
    return command[start:] if end == -1 else command[start:end]


def _is_unqualified(command: str, head: "re.Pattern[str]") -> bool:
    for match in head.finditer(command):
        if not WHERE_RE.search(_statement_rest(command, match.end())):
            return True
    return False

CLI_RULES: List[Rule] = [
    Rule("supabase-db-reset", re.compile(r"\bsupabase\s+db\s+reset\b", re.I),
         "drops and recreates the whole database"),
    Rule("prisma-migrate-reset", re.compile(r"\bprisma\s+migrate\s+reset\b", re.I),
         "drops the database and replays every migration"),
    Rule("prisma-data-loss", re.compile(r"\bprisma\s+db\s+push\b[^\n]*--accept-data-loss", re.I),
         "pushes a schema while accepting data loss"),
    Rule("drizzle-force", re.compile(r"\bdrizzle-kit\s+push\b[^\n]*--force", re.I),
         "forces a schema push over the existing data"),
    Rule("dropdb", re.compile(r"\bdropdb\b", re.I),
         "drops an entire database"),
    Rule("mysql-drop", re.compile(r"\bmysqladmin\b[^\n]*\bdrop\b", re.I),
         "drops an entire database"),
    Rule("rails-db-drop", re.compile(r"\b(?:rails|rake)\s+db:(?:drop|reset|purge)\b", re.I),
         "drops or resets the database"),
    Rule("django-flush", re.compile(r"\bmanage\.py\s+flush\b", re.I),
         "deletes every row in every table"),
    Rule("redis-flush", re.compile(r"\bredis-cli\b[^\n]*\bflush(?:all|db)\b", re.I),
         "empties the entire keyspace"),
    Rule("mongo-drop", re.compile(r"\bdropDatabase\s*\(", re.I),
         "drops an entire database"),
    Rule("knex-rollback-all", re.compile(r"\bknex\s+migrate:rollback\b[^\n]*--all", re.I),
         "rolls every migration back"),
]


# --------------------------------------------------------------------------
# Where is it pointed?
# --------------------------------------------------------------------------

LOCAL_HOST_RE = re.compile(
    r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)\b", re.I
)
# Supabase's local stack listens on 54322; docker-compose services are named.
LOCAL_HINT_RE = re.compile(r":54322\b|\bpostgres(?:ql)?://[^/\s]*@(?:db|postgres|database):|--local\b", re.I)

REMOTE_HOST_RE = re.compile(
    r"[\w.-]*\.(?:supabase\.co|neon\.tech|rds\.amazonaws\.com|railway\.app|render\.com|"
    r"planetscale\.com|psdb\.cloud|fly\.dev|upstash\.io|cockroachlabs\.cloud|"
    r"digitalocean\.com|azure\.com|timescale\.com|aivencloud\.com|turso\.io)",
    re.I,
)
# Supabase CLI: --linked and --project-ref both mean the hosted project.
REMOTE_FLAG_RE = re.compile(r"--linked\b|--project-ref\b|--db-url\b|--remote\b", re.I)
PROD_WORD_RE = re.compile(r"\b(?:prod|production|live)\b", re.I)

# An unresolved variable is the common shape, and the dangerous one.
ENV_INDIRECTION_RE = re.compile(
    r"\$\{?[A-Z_][A-Z0-9_]*\}?|\bprocess\.env\.[A-Z_]+", re.I
)
DB_URL_VAR_RE = re.compile(
    r"\$\{?(?:DATABASE_URL|DIRECT_URL|POSTGRES_URL|SUPABASE_DB_URL|DB_URL|PG\w*|"
    r"MYSQL_URL|MONGO_URL|REDIS_URL)\}?", re.I
)

INLINE_HOST_RE = re.compile(r"-h\s+(\S+)|--host[= ](\S+)", re.I)


def classify_target(command: str) -> str:
    """local, remote, or unknown - and unknown is treated as remote later."""
    if REMOTE_FLAG_RE.search(command) or REMOTE_HOST_RE.search(command):
        return REMOTE

    # A URL written out in full is readable, so read it.
    for match in re.finditer(r"\b\w+://[^\s\"']+", command):
        url = match.group(0)
        if LOCAL_HOST_RE.search(url) or ":54322" in url:
            return LOCAL
        return REMOTE

    if DB_URL_VAR_RE.search(command):
        # `psql $DATABASE_URL` - unreadable, and in these projects it usually
        # points at hosted Postgres.
        return UNKNOWN

    if LOCAL_HOST_RE.search(command) or LOCAL_HINT_RE.search(command):
        return LOCAL

    host_match = INLINE_HOST_RE.search(command)
    if host_match:
        host = host_match.group(1) or host_match.group(2) or ""
        return LOCAL if LOCAL_HOST_RE.search(host) else REMOTE

    if PROD_WORD_RE.search(command):
        return REMOTE

    if ENV_INDIRECTION_RE.search(command):
        return UNKNOWN

    return LOCAL if _looks_local_by_default(command) else UNKNOWN


def _looks_local_by_default(command: str) -> bool:
    """
    Tools that only ever act locally unless told otherwise.

    `supabase db reset` with no flags hits the local stack; `sqlite3 dev.db` is
    a file on this machine. Treating these as production would block ordinary
    work every day, which is how a guard gets switched off.
    """
    if re.search(r"\bsqlite3?\b", command, re.I):
        return True
    if re.search(r"\bsupabase\b", command, re.I) and not REMOTE_FLAG_RE.search(command):
        return True
    if re.search(r"\b(?:rails|rake|manage\.py|artisan)\b", command, re.I):
        return True
    if re.search(r"\bprisma\s+migrate\s+reset\b", command, re.I) and not DB_URL_VAR_RE.search(command):
        return True
    return False


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------

def _unqualified_write(command: str) -> Optional[Rule]:
    if _is_unqualified(command, DELETE_HEAD_RE):
        return Rule("delete-no-where", DELETE_HEAD_RE,
                    "deletes every row in the table - there is no WHERE clause")
    if _is_unqualified(command, UPDATE_HEAD_RE):
        return Rule("update-no-where", UPDATE_HEAD_RE,
                    "rewrites every row in the table - there is no WHERE clause")
    return None


def find_destructive(command: str) -> Optional[Rule]:
    """The rule this command trips, or None. CLI rules do not need a DB tool
    present because the tool name is the rule."""
    for rule in CLI_RULES:
        if rule.regex.search(command):
            return rule

    # Raw SQL only counts when something that executes SQL is in the command.
    if not DB_TOOL_RE.search(command):
        return None

    for rule in SQL_RULES:
        if rule.regex.search(command):
            return rule

    return _unqualified_write(command)


def classify(command: str) -> Verdict:
    if not command or not command.strip():
        return Verdict(ALLOW, LOCAL)

    rule = find_destructive(command)
    if rule is None:
        return Verdict(ALLOW, LOCAL)

    target = classify_target(command)

    if target == LOCAL:
        return Verdict(
            ASK, target, matched=rule.name,
            reason="This %s. It looks like a local database, so this is probably fine - "
                   "confirm before it runs." % rule.what,
        )

    where = ("a production or remote database" if target == REMOTE
             else "a database this check cannot identify")
    aside = ("" if target == REMOTE else
             " The connection comes from a variable that cannot be read here, and in "
             "projects like this one it usually points at hosted Postgres.")

    return Verdict(
        DENY, target, matched=rule.name,
        reason="Blocked: this %s, against %s.%s If that is genuinely what you "
               "want, run it yourself outside the agent - and take a backup first."
               % (rule.what, where, aside),
    )


# --------------------------------------------------------------------------
# Hook protocol
# --------------------------------------------------------------------------

def run_hook(stream=None) -> int:
    if os.environ.get("DB_GUARD_DISABLE") == "1":
        return 0

    raw = (stream or sys.stdin).read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except ValueError:
        return 0  # Never break the session over a malformed event.

    if event.get("tool_name") not in (None, "Bash"):
        return 0

    tool_input = event.get("tool_input") or {}
    command = tool_input.get("command") or ""
    verdict = classify(command)

    if verdict.action == ALLOW:
        return 0

    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict.action,
            "permissionDecisionReason": verdict.reason,
        },
        "systemMessage": "db-guard: %s (%s)" % (verdict.action, verdict.matched),
    }

    if verdict.action == DENY:
        sys.stderr.write(json.dumps(payload) + "\n")
        return 2

    sys.stdout.write(json.dumps(payload) + "\n")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="db_guard",
        description="Block destructive database commands aimed at anything that is not "
                    "clearly a local development database.",
    )
    parser.add_argument("--hook", action="store_true",
                        help="run as a PreToolUse hook, reading the event from stdin")
    parser.add_argument("--command", help="classify a single command and print the verdict")
    parser.add_argument("--json", action="store_true", help="print the verdict as JSON")
    args = parser.parse_args(argv)

    if args.hook:
        return run_hook()

    if args.command is None:
        parser.print_help()
        return 0

    verdict = classify(args.command)
    if args.json:
        print(json.dumps(verdict.as_dict(), indent=2))
    else:
        print("%s  %s" % (verdict.action.upper(), verdict.matched or "-"))
        if verdict.reason:
            print(verdict.reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
