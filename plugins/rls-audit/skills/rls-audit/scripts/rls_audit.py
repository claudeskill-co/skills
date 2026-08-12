#!/usr/bin/env python3
"""
Find the access-control gaps that get vibe-coded apps breached.

Four classes of finding, in the order they actually cost people money:

  1. Tables reachable by the browser with row level security switched off.
  2. Policies that are technically on but let everyone through (`using (true)`).
  3. Secret keys sitting somewhere the browser can read them.
  4. Access decided in the browser instead of on the server.

Every finding names a file and a line. Nothing is reported that cannot be
pointed at. Checks that rely on a heuristic rather than a fact are labelled
`review` and never counted as failures.

    python3 rls_audit.py --path .
    python3 rls_audit.py --path . --json
    python3 rls_audit.py --path . --strict     # exit 1 if anything critical

Standard library only. Reads files, never writes, never talks to the network.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
REVIEW = "review"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, REVIEW: 3}

# A finding is `fact` when it follows from the file alone, and `heuristic` when
# it depends on a pattern that a correct codebase could also match. The
# distinction is load-bearing: heuristics are advice, facts are defects.
FACT = "fact"
HEURISTIC = "heuristic"


@dataclass
class Finding:
    code: str
    severity: str
    confidence: str
    title: str
    path: str
    line: int
    detail: str
    fix: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "file": self.path,
            "line": self.line,
            "detail": self.detail,
            "fix": self.fix,
        }


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    sql_files: int = 0
    code_files: int = 0
    tables: List[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.path, f.line),
        )

    def counts(self) -> Dict[str, int]:
        out = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, REVIEW: 0}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out


# --------------------------------------------------------------------------
# Walking the project
# --------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", "node_modules", ".next", "dist", "build", "out", "coverage",
    "__pycache__", ".venv", "venv", ".turbo", ".vercel", "vendor", ".cache",
}

SQL_SUFFIXES = (".sql",)
CODE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".svelte", ".vue")
ENV_NAMES = (".env", ".env.local", ".env.example", ".env.sample", ".env.production")

# Files big enough to be generated are not worth scanning and blow up runtime.
MAX_BYTES = 2_000_000


def walk(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".yarn"))
        # Agent worktrees are copies of the same tree; scanning them reports the
        # same migration once per worktree.
        if os.path.join(".claude", "worktrees") in dirpath:
            dirnames[:] = []
            continue
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (OSError, ValueError):
        return None


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


# --------------------------------------------------------------------------
# SQL: strip comments without moving anything
# --------------------------------------------------------------------------

def blank_comments(sql: str) -> str:
    """
    Replace comments with spaces of identical length.

    Preserving offsets matters: every finding reports a line number derived
    from an index into this string, and a shorter string would report the
    wrong line.
    """
    out = list(sql)
    i = 0
    n = len(sql)
    while i < n:
        char = sql[i]
        if char == "'":  # string literal - skip it whole, comments inside are not comments
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if char == "-" and i + 1 < n and sql[i + 1] == "-":
            j = sql.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if char == "/" and i + 1 < n and sql[i + 1] == "*":
            j = sql.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


IDENT = r'(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)'
QUALIFIED = r'(?:(%s)\s*\.\s*)?(%s)' % (IDENT, IDENT)


def unquote(name: str) -> str:
    return name.strip().strip('"')


def normalise_table(schema: Optional[str], table: str) -> str:
    schema_name = unquote(schema) if schema else "public"
    return "%s.%s" % (schema_name, unquote(table))


def balanced(text: str, open_index: int) -> Tuple[str, int]:
    """Return the contents of the parenthesis group starting at `open_index`."""
    depth = 0
    i = open_index
    n = len(text)
    while i < n:
        char = text[i]
        if char == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:i], i + 1
        i += 1
    return text[open_index + 1:], n


def is_always_true(expression: str) -> bool:
    """`using (true)`, `using ( TRUE )`, `using ((true))` all mean the same thing."""
    collapsed = expression.strip().lower()
    while collapsed.startswith("(") and collapsed.endswith(")"):
        inner = balanced(collapsed, 0)[0]
        if len(inner) + 2 != len(collapsed):
            break
        collapsed = inner.strip()
    return collapsed == "true"


# --------------------------------------------------------------------------
# SQL checks
# --------------------------------------------------------------------------

CREATE_TABLE_RE = re.compile(
    r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?" + QUALIFIED,
    re.IGNORECASE,
)
ENABLE_RLS_RE = re.compile(
    r"\balter\s+table\s+(?:only\s+)?" + QUALIFIED + r"\s+enable\s+row\s+level\s+security",
    re.IGNORECASE,
)
DISABLE_RLS_RE = re.compile(
    r"\balter\s+table\s+(?:only\s+)?" + QUALIFIED + r"\s+disable\s+row\s+level\s+security",
    re.IGNORECASE,
)
CREATE_POLICY_RE = re.compile(
    r"\bcreate\s+policy\s+(%s)\s+on\s+" % IDENT + QUALIFIED,
    re.IGNORECASE,
)
DROP_TABLE_RE = re.compile(
    r"\bdrop\s+table\s+(?:if\s+exists\s+)?" + QUALIFIED,
    re.IGNORECASE,
)

WRITE_COMMANDS = {"all", "insert", "update", "delete"}
PUBLIC_ROLES = {"public", "anon"}


@dataclass
class Policy:
    name: str
    table: str
    command: str
    roles: List[str]
    using: Optional[str]
    check: Optional[str]
    path: str
    line: int


def parse_policy_tail(sql: str, start: int) -> Tuple[str, List[str], Optional[str], Optional[str]]:
    """
    Read the clauses of a CREATE POLICY statement from just past the table name
    up to the terminating semicolon.
    """
    end = sql.find(";", start)
    end = len(sql) if end == -1 else end
    tail = sql[start:end]

    command = "all"
    match = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", tail, re.IGNORECASE)
    if match:
        command = match.group(1).lower()

    roles: List[str] = []
    role_match = re.search(r"\bto\s+([A-Za-z0-9_\"\s,]+?)(?=\busing\b|\bwith\b|$)", tail, re.IGNORECASE)
    if role_match:
        roles = [unquote(r).lower() for r in role_match.group(1).split(",") if unquote(r).strip()]
    if not roles:
        roles = ["public"]  # Postgres default when TO is omitted

    using = None
    using_match = re.search(r"\busing\s*\(", tail, re.IGNORECASE)
    if using_match:
        using = balanced(tail, using_match.end() - 1)[0]

    check = None
    check_match = re.search(r"\bwith\s+check\s*\(", tail, re.IGNORECASE)
    if check_match:
        check = balanced(tail, check_match.end() - 1)[0]

    return command, roles, using, check


def scan_sql(paths: List[str], root: str, report: Report) -> None:
    created: Dict[str, Tuple[str, int]] = {}
    enabled: Dict[str, Tuple[str, int]] = {}
    disabled: Dict[str, Tuple[str, int]] = {}
    dropped = set()
    policies: List[Policy] = []

    for path in paths:
        raw = read(path)
        if raw is None:
            continue
        report.sql_files += 1
        sql = blank_comments(raw)
        rel = os.path.relpath(path, root)

        for match in CREATE_TABLE_RE.finditer(sql):
            table = normalise_table(match.group(1), match.group(2))
            created.setdefault(table, (rel, line_of(sql, match.start())))

        for match in ENABLE_RLS_RE.finditer(sql):
            table = normalise_table(match.group(1), match.group(2))
            enabled[table] = (rel, line_of(sql, match.start()))

        for match in DISABLE_RLS_RE.finditer(sql):
            table = normalise_table(match.group(1), match.group(2))
            disabled[table] = (rel, line_of(sql, match.start()))

        for match in DROP_TABLE_RE.finditer(sql):
            dropped.add(normalise_table(match.group(1), match.group(2)))

        for match in CREATE_POLICY_RE.finditer(sql):
            table = normalise_table(match.group(2), match.group(3))
            command, roles, using, check = parse_policy_tail(sql, match.end())
            policies.append(
                Policy(
                    name=unquote(match.group(1)),
                    table=table,
                    command=command,
                    roles=roles,
                    using=using,
                    check=check,
                    path=rel,
                    line=line_of(sql, match.start()),
                )
            )

    # A table dropped later in the migration history is not a live table.
    live = {t: where for t, where in created.items() if t not in dropped}
    report.tables = sorted(live)

    policied = set(p.table for p in policies)

    for table, (rel, line) in sorted(live.items()):
        # Only `public` is exposed through the Supabase/PostgREST API by default.
        # A table in another schema is not browser-reachable, so absent RLS there
        # is not the same defect and is not reported.
        if not table.startswith("public."):
            continue

        if table in disabled and table not in enabled:
            report.add(Finding(
                code="RLS001",
                severity=CRITICAL,
                confidence=FACT,
                title="Row level security explicitly disabled",
                path=disabled[table][0],
                line=disabled[table][1],
                detail="`%s` is exposed through the API and RLS is switched off. "
                       "Every row is readable and writable by anyone holding the anon key, "
                       "which ships in your client bundle." % table,
                fix="alter table %s enable row level security;  -- then add the policies you meant" % table,
            ))
            continue

        if table not in enabled:
            report.add(Finding(
                code="RLS001",
                severity=CRITICAL,
                confidence=FACT,
                title="Table has no row level security",
                path=rel,
                line=line,
                detail="`%s` is created in the public schema but never has RLS enabled. "
                       "The anon key is public by design, so this table is world-readable "
                       "and probably world-writable." % table,
                fix="alter table %s enable row level security;" % table,
            ))
            continue

        if table not in policied:
            report.add(Finding(
                code="RLS002",
                severity=MEDIUM,
                confidence=FACT,
                title="RLS enabled but no policy defined",
                path=enabled[table][0],
                line=enabled[table][1],
                detail="`%s` has RLS on and zero policies, so Postgres denies every request "
                       "from the anon and authenticated roles. Safe, but the table is unreachable "
                       "- usually a half-finished migration rather than an intention." % table,
                fix="Add the policy you meant, or confirm this table is only touched by the service role.",
            ))

    for policy in policies:
        roles = set(policy.roles)
        public_facing = bool(roles & PUBLIC_ROLES)
        writes = policy.command in WRITE_COMMANDS

        if policy.using is not None and is_always_true(policy.using):
            if writes:
                severity = CRITICAL if public_facing else HIGH
                who = "anyone with the anon key" if public_facing else "any signed-in user"
                report.add(Finding(
                    code="RLS004",
                    severity=severity,
                    confidence=FACT,
                    title="Policy allows unrestricted writes",
                    path=policy.path,
                    line=policy.line,
                    detail="Policy `%s` on `%s` is `for %s to %s using (true)`. "
                           "That lets %s modify or delete every row in the table."
                           % (policy.name, policy.table, policy.command, ", ".join(policy.roles), who),
                    fix="Scope it to the owner, e.g. `using (auth.uid() = user_id)`.",
                ))
            else:
                severity = HIGH if public_facing else MEDIUM
                who = "anyone with the anon key" if public_facing else "any signed-in user"
                report.add(Finding(
                    code="RLS003",
                    severity=severity,
                    confidence=FACT,
                    title="Policy allows unrestricted reads",
                    path=policy.path,
                    line=policy.line,
                    detail="Policy `%s` on `%s` is `for select to %s using (true)`, so %s can read "
                           "every row. Correct for genuinely public content, a breach for anything else."
                           % (policy.name, policy.table, ", ".join(policy.roles), who),
                    fix="If the table holds user data, scope it: `using (auth.uid() = user_id)`.",
                ))

        if policy.check is not None and is_always_true(policy.check) and policy.command in {"all", "insert", "update"}:
            report.add(Finding(
                code="RLS005",
                severity=CRITICAL if public_facing else HIGH,
                confidence=FACT,
                title="Policy accepts any inserted row",
                path=policy.path,
                line=policy.line,
                detail="Policy `%s` on `%s` has `with check (true)`, so a caller can write rows "
                       "attributed to any user, not just themselves."
                       % (policy.name, policy.table),
                fix="Constrain the write: `with check (auth.uid() = user_id)`.",
            ))


# --------------------------------------------------------------------------
# Secret exposure
# --------------------------------------------------------------------------

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
SB_SECRET_RE = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{8,}")
PUBLIC_SERVICE_ENV_RE = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC)_[A-Z0-9_]*"
    r"(?:SERVICE_ROLE|SERVICE_KEY|SECRET)[A-Z0-9_]*"
)
SERVICE_ENV_RE = re.compile(r"\bSUPABASE_SERVICE_ROLE(?:_KEY)?\b|\bSERVICE_ROLE_KEY\b")
USE_CLIENT_RE = re.compile(r"^\s*['\"]use client['\"]", re.MULTILINE)


def decode_jwt_role(payload: str) -> Optional[str]:
    padded = payload + "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", "replace")
    except Exception:
        return None
    match = re.search(r'"role"\s*:\s*"([A-Za-z_]+)"', decoded)
    return match.group(1) if match else None


def scan_secrets(path: str, rel: str, text: str, is_client: bool, report: Report) -> None:
    for match in JWT_RE.finditer(text):
        role = decode_jwt_role(match.group(1))
        if role == "service_role":
            report.add(Finding(
                code="KEY001",
                severity=CRITICAL,
                confidence=FACT,
                title="Service role key hardcoded",
                path=rel,
                line=line_of(text, match.start()),
                detail="This is a Supabase service_role JWT written into the file. It bypasses "
                       "every RLS policy you have. Anyone who reads this file owns the database.",
                fix="Move it to an environment variable, then rotate the key - the old one is burned.",
            ))

    for match in SB_SECRET_RE.finditer(text):
        report.add(Finding(
            code="KEY001",
            severity=CRITICAL,
            confidence=FACT,
            title="Supabase secret key hardcoded",
            path=rel,
            line=line_of(text, match.start()),
            detail="An `sb_secret_` key is written into the file. It bypasses every RLS policy.",
            fix="Move it to an environment variable, then rotate the key.",
        ))

    for match in PUBLIC_SERVICE_ENV_RE.finditer(text):
        report.add(Finding(
            code="KEY002",
            severity=CRITICAL,
            confidence=FACT,
            title="Secret held in a browser-exposed variable",
            path=rel,
            line=line_of(text, match.start()),
            detail="`%s` is prefixed for client exposure, so its value is compiled into the "
                   "JavaScript bundle every visitor downloads." % match.group(0),
            fix="Drop the public prefix and read it only in server code, then rotate the key.",
        ))

    if is_client:
        for match in SERVICE_ENV_RE.finditer(text):
            report.add(Finding(
                code="KEY003",
                severity=CRITICAL,
                confidence=FACT,
                title="Service role key referenced in a client component",
                path=rel,
                line=line_of(text, match.start()),
                detail="This file is marked `'use client'` and reads the service role key. "
                       "Anything a client component reads can end up in the bundle.",
                fix="Move this work into a Server Component, Route Handler or Server Action.",
            ))


def scan_env_file(rel: str, text: str, report: Report) -> None:
    for match in PUBLIC_SERVICE_ENV_RE.finditer(text):
        line = line_of(text, match.start())
        value = text[match.end():text.find("\n", match.end()) if text.find("\n", match.end()) != -1 else len(text)]
        if value.strip().lstrip("=").strip():
            report.add(Finding(
                code="KEY002",
                severity=CRITICAL,
                confidence=FACT,
                title="Secret assigned to a browser-exposed variable",
                path=rel,
                line=line,
                detail="`%s` carries a value and its prefix means the bundler inlines it into "
                       "client JavaScript." % match.group(0),
                fix="Rename it without the public prefix, read it server-side only, and rotate the key.",
            ))


# --------------------------------------------------------------------------
# Where the access decision is made
# --------------------------------------------------------------------------

GATE_IDENTIFIER = re.compile(
    r"\b(?:is|has)(?:_|)(?:pro|paid|premium|admin|subscribed|subscriber|access|active)\b"
    r"|\bsubscription(?:_|)status\b|\buser(?:_|)(?:tier|plan|role)\b",
    re.IGNORECASE,
)
CONDITIONAL_RENDER = re.compile(r"\{\s*[A-Za-z_$][\w$.?]*\s*(?:&&|\?)")
AUTH_CHECK = re.compile(
    r"\bgetUser\b|\bgetSession\b|\bgetClaims\b|\bauth\(\)|\bcurrentUser\b|\brequireAuth\b|\bverifyJwt\b",
    re.IGNORECASE,
)
ROUTE_FILE = re.compile(r"(?:^|[\\/])(?:app|src[\\/]app)[\\/].*[\\/]route\.[cm]?[jt]sx?$")
PAGES_API_FILE = re.compile(r"(?:^|[\\/])pages[\\/]api[\\/]")


def scan_access_control(rel: str, text: str, is_client: bool, report: Report) -> None:
    if is_client:
        for match in CONDITIONAL_RENDER.finditer(text):
            window = text[match.start():match.start() + 160]
            identifier = GATE_IDENTIFIER.search(window)
            if not identifier:
                continue
            report.add(Finding(
                code="GATE001",
                severity=REVIEW,
                confidence=HEURISTIC,
                title="Entitlement checked in the browser",
                path=rel,
                line=line_of(text, match.start()),
                detail="A client component decides what to render from `%s`. If this is the only "
                       "check, the gate is cosmetic - the data is already in the browser and the "
                       "user can flip the flag in devtools." % identifier.group(0),
                fix="Keep the check for appearance, but enforce it server-side too: withhold the "
                    "data in a Server Component or Route Handler, and back it with an RLS policy.",
            ))
            break  # one per file is enough to prompt a look

    is_route = bool(ROUTE_FILE.search(rel.replace(os.sep, "/"))) or bool(PAGES_API_FILE.search(rel.replace(os.sep, "/")))
    if is_route and SERVICE_ENV_RE.search(text) and not AUTH_CHECK.search(text):
        match = SERVICE_ENV_RE.search(text)
        report.add(Finding(
            code="API001",
            severity=HIGH,
            confidence=HEURISTIC,
            title="Route uses the service role with no visible auth check",
            path=rel,
            line=line_of(text, match.start()),
            detail="This handler builds a client with the service role key, which bypasses RLS, "
                   "and no call to getUser/getSession/auth appears in the file. If the caller is "
                   "not identified here, this endpoint is an open door to the whole database.",
            fix="Identify the caller first and return 401 before touching the service client. "
                "If auth happens in shared middleware, this finding is noise - say so and move on.",
        ))


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def audit(root: str) -> Report:
    report = Report()
    sql_paths: List[str] = []

    for path in walk(root):
        name = os.path.basename(path)
        rel = os.path.relpath(path, root)

        if path.endswith(SQL_SUFFIXES):
            sql_paths.append(path)
            continue

        if name in ENV_NAMES or name.startswith(".env."):
            text = read(path)
            if text is not None:
                scan_env_file(rel, text, report)
            continue

        if not path.endswith(CODE_SUFFIXES):
            continue

        text = read(path)
        if text is None:
            continue
        report.code_files += 1
        is_client = bool(USE_CLIENT_RE.search(text[:400]))
        scan_secrets(path, rel, text, is_client, report)
        scan_access_control(rel, text, is_client, report)

    scan_sql(sql_paths, root, report)
    return report


BOX = {CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", REVIEW: "REVIEW"}


def render(report: Report, root: str) -> str:
    lines: List[str] = []
    counts = report.counts()
    findings = report.sorted_findings()

    lines.append("RLS AUDIT  %s" % os.path.abspath(root))
    lines.append("scanned %d SQL file(s), %d source file(s), found %d table(s)"
                 % (report.sql_files, report.code_files, len(report.tables)))
    lines.append("")

    if not findings:
        if report.sql_files == 0 and report.code_files == 0:
            lines.append("Nothing to scan here. Point --path at the project root.")
        else:
            lines.append("No access-control defects found in what can be checked statically.")
        lines.append("")
    else:
        lines.append("%d critical  %d high  %d medium  %d to review"
                     % (counts[CRITICAL], counts[HIGH], counts[MEDIUM], counts[REVIEW]))
        lines.append("")

        for finding in findings:
            lines.append("[%s] %s  (%s)" % (BOX[finding.severity], finding.title, finding.code))
            lines.append("  %s:%d" % (finding.path, finding.line))
            lines.append("  %s" % finding.detail)
            lines.append("  fix: %s" % finding.fix)
            if finding.confidence == HEURISTIC:
                lines.append("  note: pattern-matched, not proven. Confirm before acting.")
            lines.append("")

    lines.append("What this cannot tell you")
    lines.append("  - whether the policies that exist are the policies you meant")
    lines.append("  - anything about tables created through the Supabase dashboard rather than a migration")
    lines.append("  - whether a key that leaked has already been used")
    lines.append("  - whether any of this is still true after your next deploy")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rls_audit",
        description="Find row level security and access-control gaps in a project.",
    )
    parser.add_argument("--path", default=".", help="project root to scan (default: current directory)")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 when a critical or high finding is present")
    args = parser.parse_args(argv)

    root = args.path
    if not os.path.isdir(root):
        message = "no such directory: %s" % root
        if args.json:
            print(json.dumps({"error": message, "findings": []}, indent=2))
        else:
            print("RLS AUDIT")
            print(message)
        return 0

    report = audit(root)

    if args.json:
        print(json.dumps({
            "root": os.path.abspath(root),
            "scanned": {"sql": report.sql_files, "source": report.code_files},
            "tables": report.tables,
            "counts": report.counts(),
            "findings": [f.as_dict() for f in report.sorted_findings()],
        }, indent=2))
    else:
        print(render(report, root))

    if args.strict:
        counts = report.counts()
        if counts[CRITICAL] or counts[HIGH]:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
