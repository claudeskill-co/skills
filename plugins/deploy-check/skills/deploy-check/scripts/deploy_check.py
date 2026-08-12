#!/usr/bin/env python3
"""
Find the gap between what runs on your laptop and what runs in production.

Nothing here is a vulnerability in the usual sense. These are the defects that
make a launch fail at the worst possible moment: a variable that only exists on
your machine, a staging site writing to the live database, type errors waved
through at build time, and no headers on anything.

Four questions, in the order they ruin a launch day:

  1. Will it boot? (configuration that exists locally and nowhere else)
  2. Is it pointed at the right database?
  3. Did the build actually check anything?
  4. Is anything in front of it - headers, limits, a health endpoint?

Every finding names a file and a line. Nothing is reported that cannot be
pointed at. Checks that rely on a heuristic rather than a fact are labelled
`review` and never counted as failures.

    python3 deploy_check.py --path .
    python3 deploy_check.py --path . --json
    python3 deploy_check.py --path . --strict     # exit 1 if anything critical

Standard library only. Reads files, never writes, never talks to the network,
and never reads a value out of your environment - only the names.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
REVIEW = "review"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, REVIEW: 3}

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
    code_files: int = 0
    env_files: List[str] = field(default_factory=list)
    routes: List[str] = field(default_factory=list)
    is_project: bool = False

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

CODE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".svelte", ".vue", ".py")
CONFIG_NAMES = (
    "next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs",
    "vite.config.js", "vite.config.ts", "vercel.json", "netlify.toml",
    "package.json", "svelte.config.js", "nuxt.config.ts",
)

MAX_BYTES = 2_000_000
MAX_ENV_FINDINGS = 8


def walk(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".yarn"))
        if os.path.basename(dirpath) == ".claude":
            dirnames[:] = [d for d in dirnames if d != "worktrees"]
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


BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"(?m)//[^\n]*")
HASH_COMMENT = re.compile(r"(?m)#[^\n]*")


def blank_comments(text: str, hashes: bool = False) -> str:
    """Blank rather than strip, so every reported line number stays put.

    Config files go through this too, and it matters in both directions: a
    commented-out `ignoreBuildErrors` is not a finding, and a commented-out
    headers block is not a reason to stay quiet about missing headers.
    """
    def blank(match: "re.Match[str]") -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    out = LINE_COMMENT.sub(blank, BLOCK_COMMENT.sub(blank, text))
    if hashes:
        out = HASH_COMMENT.sub(blank, out)
    return out


TEST_PATH_RE = re.compile(
    # Canonical across every Ship-Safe scanner - keep in sync. A conformance
    # test in plugins/ship-check/tests asserts all four classify the same
    # paths identically; four independent copies of this had already drifted
    # into four different answers, and ship-check merged the disagreement into
    # a self-contradicting verdict.
    #
    # `demo` and `examples` are deliberately absent. A directory called demo/
    # in someone else's repository is far more likely to be real code than a
    # throwaway fixture, and downgrading it silently is how a scanner returns
    # CLEAR on a live key.
    r"(^|/)(tests?|__tests__|__mocks__|mocks?|spec|specs|fixtures?|testdata"
    r"|e2e|cypress|\.storybook|stories)(/|$)"
    r"|\.(test|spec|stories|fixture)\.[cm]?[jt]sx?$"
    r"|(^|/)test_[^/]+\.py$|_test\.py$|(^|/)conftest\.py$",
    re.I,
)


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH_RE.search(rel.replace(os.sep, "/")))


# --------------------------------------------------------------------------
# Environment files
# --------------------------------------------------------------------------

# Any env file whose name says "example" documents what the project needs, and
# a project may split that across several - `.env.example` for the local stack
# and `.env.local.example` for the app is the shape the Next.js reference
# implementation uses. Matching only `.env.example` reported every documented
# variable in that repo as undocumented.
TEMPLATE_ENV_RE = re.compile(r"example|sample|template|defaults", re.I)
PRODUCTION_ENV_NAMES = (".env.production", ".env.production.local")
LOCAL_ENV_NAMES = (".env", ".env.local", ".env.development", ".env.development.local")

ENV_LINE_RE = re.compile(r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$""")


def parse_env(text: str) -> Dict[str, Tuple[str, int]]:
    """name -> (value, line). Values are read but never printed in full."""
    out: Dict[str, Tuple[str, int]] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = ENV_LINE_RE.match(raw)
        if not match:
            continue
        value = match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[match.group(1)] = (value, number)
    return out


# Names the platform provides. Asking a user to document PORT or VERCEL_URL in
# their own env template is noise, and noise is what gets a tool switched off.
PROVIDED_ENV = {
    "NODE_ENV", "PORT", "HOST", "HOSTNAME", "CI", "TZ", "PATH", "HOME", "PWD", "USER", "SHELL",
    "VERCEL", "VERCEL_ENV", "VERCEL_URL", "VERCEL_REGION", "VERCEL_GIT_COMMIT_SHA",
    "VERCEL_PROJECT_PRODUCTION_URL", "NEXT_PUBLIC_VERCEL_URL", "NEXT_RUNTIME", "NEXT_PHASE",
    "RAILWAY_ENVIRONMENT", "RENDER", "RENDER_EXTERNAL_URL", "FLY_APP_NAME", "NETLIFY",
    "AWS_REGION", "AWS_LAMBDA_FUNCTION_NAME", "GITHUB_ACTIONS", "npm_lifecycle_event",
    "ANALYZE", "DEBUG", "NODE_OPTIONS", "npm_package_version",
    # Supplied by Claude Code to hooks and plugin scripts, not by your deploy.
    "CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_CODE_ENTRYPOINT",
}

ENV_USE_RE = re.compile(
    r"""process\.env\.([A-Za-z_][A-Za-z0-9_]*)"""
    r"""|process\.env\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]"""
    r"""|import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)"""
    r"""|Deno\.env\.get\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\)"""
    r"""|os\.environ(?:\.get)?[\[(]\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]"""
)


def env_names_used(text: str) -> Set[str]:
    names: Set[str] = set()
    for match in ENV_USE_RE.finditer(text):
        for group in match.groups():
            if group:
                names.add(group)
    return names


# --------------------------------------------------------------------------
# Config patterns
# --------------------------------------------------------------------------

IGNORE_BUILD_ERRORS_RE = re.compile(r"ignoreBuildErrors\s*:\s*true")
IGNORE_LINT_RE = re.compile(r"ignoreDuringBuilds\s*:\s*true")
SOURCEMAP_RE = re.compile(r"productionBrowserSourceMaps\s*:\s*true|sourcemap\s*:\s*true")
STATIC_EXPORT_RE = re.compile(r"""output\s*:\s*['"]export['"]""")

HEADER_MARKERS_RE = re.compile(
    r"Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|"
    r"X-Content-Type-Options|Referrer-Policy|Permissions-Policy|"
    r"async\s+headers\s*\(|['\"]headers['\"]\s*:", re.I)

CORS_WILDCARD_RE = re.compile(
    r"""['"]?Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]""", re.I)
CORS_CREDENTIALS_RE = re.compile(
    r"""['"]?Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?true""", re.I)

RATE_LIMIT_RE = re.compile(
    r"ratelimit|rate_limit|rateLimit|@upstash/ratelimit|express-rate-limit|"
    r"arcjet|slowDown|throttle|bottleneck|limiter", re.I)

SENSITIVE_ROUTE_RE = re.compile(
    r"auth|login|signin|sign-in|signup|register|otp|magic|reset|forgot|"
    r"ai|chat|complete|generate|embed|upload|contact|subscribe|invite|send",
    re.I)

ROUTE_FILE_RE = re.compile(r"(^|/)app/.*/route\.(ts|js|mjs)$|(^|/)pages/api/|(^|/)api/.*\.(ts|js|py)$")
HEALTH_PATH_RE = re.compile(r"(^|/)(health|healthz|_health|status|ping|ready)(/|\.)", re.I)

LOG_ENV_RE = re.compile(r"console\.(log|info|debug|warn|error)\s*\([^)]*process\.env(?!\.NODE_ENV)")

DEBUG_ON_RE = re.compile(r"^(DEBUG|NEXT_PUBLIC_DEBUG|VERBOSE|LOG_LEVEL|NODE_ENV)$")

DB_URL_NAMES = (
    "DATABASE_URL", "POSTGRES_URL", "POSTGRES_PRISMA_URL", "DIRECT_URL", "MONGODB_URI",
    "SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_URL", "REDIS_URL", "TURSO_DATABASE_URL",
)

LOCAL_HOST_RE = re.compile(r"localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|\.local\b")


def host_of(value: str) -> Optional[str]:
    """The host part of a connection string, without credentials."""
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://(?:[^@/]*@)?([^/:?#]+)", value.strip())
    return match.group(1).lower() if match else None


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def check_env_drift(root: str, env: Dict[str, Dict[str, Tuple[str, int]]],
                    used: Dict[str, Tuple[str, int]], report: Report) -> None:
    """Configuration that exists on this machine and nowhere else."""
    templates = sorted(n for n in env if TEMPLATE_ENV_RE.search(n))
    # Prefer the conventional name when reporting, but treat every template as
    # documentation - splitting them across two files is normal.
    example_name = ".env.example" if ".env.example" in templates else (
        templates[0] if templates else None)

    if example_name is None:
        if not used and not any(n in env for n in LOCAL_ENV_NAMES):
            return
        first = sorted(used.items())[0] if used else None
        report.add(Finding(
            code="DEP001",
            severity=REVIEW,
            confidence=HEURISTIC,
            title="No env template, so nothing records what this needs to boot",
            path=first[1][0] if first else ".env",
            line=first[1][1] if first else 1,
            detail="This project reads %d environment variable(s) and has no .env.example. The list "
                   "of what production must be given exists only in your head and in your shell."
                   % len(used),
            fix="Commit a .env.example with every name and no values. It is the only artefact that "
                "tells a deploy - or a future you - what is required.",
        ))
        return

    documented: Set[str] = set()
    for name in templates:
        documented.update(env[name])

    local_names: Set[str] = set()
    for name in LOCAL_ENV_NAMES:
        local_names.update(env.get(name, {}))

    missing_used = sorted(n for n in used if n not in documented and n not in PROVIDED_ENV)
    for name in missing_used[:MAX_ENV_FINDINGS]:
        path, line = used[name]
        report.add(Finding(
            code="DEP001",
            severity=MEDIUM,
            confidence=HEURISTIC,
            title="`%s` is read by the code and absent from %s" % (name, example_name),
            path=path,
            line=line,
            detail="Nothing records that production needs this. It works locally because it is in "
                   "your shell or your .env, and the failure on deploy is usually an undefined "
                   "value passed on silently rather than a crash at boot.",
            fix="Add `%s=` to %s. If it is genuinely optional, give it a default in code so an "
                "absent value cannot become the string 'undefined'." % (name, example_name),
        ))
    if len(missing_used) > MAX_ENV_FINDINGS:
        report.add(Finding(
            code="DEP001",
            severity=MEDIUM,
            confidence=HEURISTIC,
            title="%d more variables are read by the code and absent from %s"
                  % (len(missing_used) - MAX_ENV_FINDINGS, example_name),
            path=example_name,
            line=1,
            detail="Listed here rather than one finding each: %s"
                   % ", ".join(missing_used[MAX_ENV_FINDINGS:]),
            fix="Add each name to %s with an empty value." % example_name,
        ))

    only_local = sorted(n for n in local_names
                        if n not in documented and n not in PROVIDED_ENV and n not in used)
    if only_local:
        # One finding listing them all, not one each. These are the weakest
        # signal this tool produces - a library reading a variable through its
        # own config counts as "not read anywhere this can see" - and eight
        # separate review lines for a weak signal is how a report gets skimmed.
        source = next(n for n in LOCAL_ENV_NAMES if only_local[0] in env.get(n, {}))
        shown = only_local[:MAX_ENV_FINDINGS]
        more = "" if len(only_local) <= MAX_ENV_FINDINGS else \
            ", and %d more" % (len(only_local) - MAX_ENV_FINDINGS)
        report.add(Finding(
            code="DEP002",
            severity=REVIEW,
            confidence=HEURISTIC,
            title="%d variable(s) set locally and documented nowhere" % len(only_local),
            path=source,
            line=env[source][only_local[0]][1],
            detail="%s%s. Each is set on this machine, absent from %s, and not read anywhere this "
                   "can see. Some will be dead configuration; others are read by a library through "
                   "its own config, in which case production does not have them."
                   % (", ".join(shown), more, example_name),
            fix="Delete what is dead. Add the rest to %s so the next deploy gets them too."
                % example_name,
        ))


def check_database_separation(env: Dict[str, Dict[str, Tuple[str, int]]], report: Report) -> None:
    """Staging writing to the live database is a silent, expensive mistake."""
    prod_name = next((n for n in PRODUCTION_ENV_NAMES if n in env), None)
    if prod_name is None:
        return

    for local_name in LOCAL_ENV_NAMES:
        local = env.get(local_name)
        if not local:
            continue
        for key in DB_URL_NAMES:
            if key not in local or key not in env[prod_name]:
                continue
            local_value, local_line = local[key]
            prod_value, _ = env[prod_name][key]
            if not local_value or local_value != prod_value:
                continue
            if LOCAL_HOST_RE.search(local_value):
                continue
            host = host_of(local_value) or "the same host"
            report.add(Finding(
                code="DEP003",
                severity=HIGH,
                confidence=FACT,
                title="%s is identical in %s and %s" % (key, local_name, prod_name),
                path=local_name,
                line=local_line,
                detail="Development and production are pointed at %s. Every migration you try, every "
                       "row you delete while debugging, and every seed script happens to real "
                       "customer data - and it will not look like a mistake until it is one." % host,
                fix="Create a second project or database for development and point %s at it. If you "
                    "only ever want one, at least take a backup before any local migration." % local_name,
            ))


def check_build_config(rel: str, text: str, report: Report) -> None:
    for regex, code, title, detail, fix in (
        (IGNORE_BUILD_ERRORS_RE, "DEP004", "Type errors are ignored at build time",
         "`ignoreBuildErrors: true` means the build succeeds with type errors in it. The errors do "
         "not go away - they become runtime failures on whichever page a user opens first.",
         "Remove the flag and fix what it was hiding. If it was added to unblock one deploy, that "
         "deploy shipped every error in the project."),
        (IGNORE_LINT_RE, "DEP004", "Lint is skipped at build time",
         "`ignoreDuringBuilds: true` turns off the checks that catch missing dependency arrays, "
         "unreachable code and unused awaits before they reach a user.",
         "Remove the flag, or narrow it to the specific rules that were noisy."),
        (SOURCEMAP_RE, "DEP006", "Source maps are published to production",
         "The full original source, including comments and internal names, is downloadable by "
         "anyone. Anything you thought was hidden in the bundle is not.",
         "Turn it off for production builds, or upload maps to your error tracker instead of "
         "serving them."),
    ):
        match = regex.search(text)
        if not match:
            continue
        report.add(Finding(
            code=code,
            severity=MEDIUM,
            confidence=FACT,
            title=title,
            path=rel,
            line=line_of(text, match.start()),
            detail=detail,
            fix=fix,
        ))


def check_static_export(rel: str, text: str, report: Report) -> None:
    match = STATIC_EXPORT_RE.search(text)
    if match:
        report.add(Finding(
            code="DEP008",
            severity=HIGH,
            confidence=FACT,
            title="Static export is on, and this project has server routes",
            path=rel,
            line=line_of(text, match.start()),
            detail="`output: 'export'` emits static files only. Route handlers, server actions and "
                   "middleware are not included - the build usually succeeds and the endpoints "
                   "simply 404 in production while working perfectly in dev.",
            fix="Drop `output: 'export'` and deploy to a runtime that serves the routes, or move "
                "the server work somewhere that will actually run.",
        ))


def check_cors(rel: str, text: str, report: Report) -> None:
    match = CORS_WILDCARD_RE.search(text)
    if not match:
        return
    credentialed = bool(CORS_CREDENTIALS_RE.search(text))
    report.add(Finding(
        code="DEP007",
        severity=HIGH if credentialed else MEDIUM,
        confidence=FACT,
        title="Any site may call this endpoint" + (" with the user's cookies" if credentialed else ""),
        path=rel,
        line=line_of(text, match.start()),
        detail=("Access-Control-Allow-Origin is `*` and credentials are allowed, so any page a user "
                "visits can make authenticated requests here as them."
                if credentialed else
                "Access-Control-Allow-Origin is `*`, so any site can call this endpoint. Fine for a "
                "genuinely public API, expensive for anything that costs you money per call."),
        fix="Replace `*` with an explicit list of your own origins. Browsers reject `*` with "
            "credentials anyway, so this configuration is not doing what it looks like.",
    ))


def check_logged_env(rel: str, text: str, report: Report) -> None:
    match = LOG_ENV_RE.search(text)
    if not match:
        return
    report.add(Finding(
        code="DEP012",
        severity=MEDIUM,
        confidence=HEURISTIC,
        title="Environment values are written to the logs",
        path=rel,
        line=line_of(text, match.start()),
        detail="Whatever this prints lands in your hosting provider's log stream, which is retained, "
               "searchable, and readable by anyone with dashboard access. Debug logging is the most "
               "common way a key that was never committed still leaks.",
        fix="Log the name, never the value. If you need to confirm a variable is set, print "
            "`Boolean(process.env.X)`.",
    ))


def check_production_env_values(env: Dict[str, Dict[str, Tuple[str, int]]], report: Report) -> None:
    for name in PRODUCTION_ENV_NAMES:
        values = env.get(name)
        if not values:
            continue
        for key, (value, line) in sorted(values.items()):
            if not DEBUG_ON_RE.match(key):
                continue
            lowered = value.strip().lower()
            if key == "NODE_ENV":
                if lowered and lowered != "production":
                    report.add(Finding(
                        code="DEP010",
                        severity=HIGH,
                        confidence=FACT,
                        title="NODE_ENV is `%s` in %s" % (value, name),
                        path=name,
                        line=line,
                        detail="Frameworks branch on this. Outside production you get development "
                               "error pages with stack traces, no minification, and caching "
                               "disabled - on the live site.",
                        fix="Set NODE_ENV=production, or remove the line and let the platform set it.",
                    ))
                continue
            if lowered in ("true", "1", "debug", "verbose", "trace"):
                report.add(Finding(
                    code="DEP010",
                    severity=MEDIUM,
                    confidence=FACT,
                    title="%s=%s in %s" % (key, value, name),
                    path=name,
                    line=line,
                    detail="Debug output is enabled in production. It is noisy, it is slow, and it "
                           "routinely prints request bodies and tokens into the log stream.",
                    fix="Turn it off in %s and leave it on locally." % name,
                ))


def check_project_level(root: str, report: Report, configs: Dict[str, str],
                        has_rate_limit: bool, has_health: bool,
                        sensitive_routes: List[str]) -> None:
    """One finding each, not one per file - these are absences, and an absence
    repeated across forty files is one problem, not forty."""
    if not report.is_project:
        return

    anchor = next((n for n in ("next.config.ts", "next.config.mjs", "next.config.js",
                               "vercel.json", "package.json") if n in configs), None)

    if anchor and not any(HEADER_MARKERS_RE.search(text) for text in configs.values()):
        report.add(Finding(
            code="DEP005",
            severity=MEDIUM,
            confidence=HEURISTIC,
            title="No security headers configured anywhere",
            path=anchor,
            line=1,
            detail="No CSP, HSTS, X-Frame-Options or Referrer-Policy appears in any config file or "
                   "middleware. Every audited sample of AI-built apps finds this: the app works "
                   "perfectly and can be framed, sniffed and downgraded by anyone.",
            fix="Add a headers() block in next.config, or a headers array in vercel.json. Start with "
                "X-Frame-Options, X-Content-Type-Options and Referrer-Policy - they cost nothing and "
                "break nothing. Add a CSP after, carefully.",
        ))

    if sensitive_routes and not has_rate_limit:
        report.add(Finding(
            code="DEP009",
            severity=MEDIUM,
            confidence=HEURISTIC,
            title="No rate limiting in front of %d sensitive route(s)" % len(sensitive_routes),
            path=sensitive_routes[0],
            line=1,
            detail="Routes handling auth, uploads or model calls are reachable at whatever rate a "
                   "script can manage, and no limiter appears anywhere in the project. On a metered "
                   "API this is someone else spending your money; on auth it is credential stuffing.",
            fix="Put a limiter in front of these routes - @upstash/ratelimit is the usual choice on "
                "serverless because it needs no persistent process. Limit by IP and by account.",
        ))

    if report.routes and not has_health:
        report.add(Finding(
            code="DEP011",
            severity=REVIEW,
            confidence=HEURISTIC,
            title="No health endpoint",
            path=report.routes[0],
            line=1,
            detail="Nothing answers a plain 'are you up' request, so an outage is discovered by a "
                   "user rather than by a monitor. This matters more once anyone depends on the app "
                   "than it does today.",
            fix="Add /api/health returning 200 and a version string, then point a free uptime "
                "monitor at it.",
        ))


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def audit(root: str) -> Report:
    report = Report()
    env: Dict[str, Dict[str, Tuple[str, int]]] = {}
    configs: Dict[str, str] = {}
    used: Dict[str, Tuple[str, int]] = {}
    sensitive_routes: List[str] = []
    has_rate_limit = False
    has_health = False
    has_server_routes = False
    static_export_config: Optional[Tuple[str, str]] = None

    for path in walk(root):
        name = os.path.basename(path)
        rel = os.path.relpath(path, root)
        posix = rel.replace(os.sep, "/")

        if name.startswith(".env") and not name.endswith((".ts", ".js", ".d.ts")):
            text = read(path)
            if text is not None:
                env[name] = parse_env(text)
                report.env_files.append(name)
            continue

        if name in CONFIG_NAMES and os.sep not in rel:
            text = read(path)
            if text is not None:
                configs[name] = blank_comments(text, hashes=name.endswith(".toml"))
                report.is_project = True
            continue

        if not path.endswith(CODE_SUFFIXES) or is_test_path(rel):
            continue

        raw = read(path)
        if raw is None:
            continue
        text = blank_comments(raw)
        report.code_files += 1

        for env_name in env_names_used(text):
            used.setdefault(env_name, (rel, 1))

        # Record the first real line for each name, so the finding points at
        # the use rather than the top of the file.
        for match in ENV_USE_RE.finditer(text):
            for group in match.groups():
                if group and used.get(group, (None, 1))[1] == 1:
                    used[group] = (rel, line_of(text, match.start()))

        if RATE_LIMIT_RE.search(text):
            has_rate_limit = True
        if HEADER_MARKERS_RE.search(text):
            configs.setdefault("middleware:" + rel, text)

        is_route = bool(ROUTE_FILE_RE.search(posix))
        if is_route:
            has_server_routes = True
            report.routes.append(rel)
            if HEALTH_PATH_RE.search(posix):
                has_health = True
            elif SENSITIVE_ROUTE_RE.search(posix):
                sensitive_routes.append(rel)

        check_cors(rel, text, report)
        check_logged_env(rel, text, report)

    for name, text in list(configs.items()):
        if name.startswith("middleware:"):
            continue
        check_build_config(name, text, report)
        if STATIC_EXPORT_RE.search(text):
            static_export_config = (name, text)
        if RATE_LIMIT_RE.search(text):
            has_rate_limit = True

    if static_export_config and has_server_routes:
        check_static_export(static_export_config[0], static_export_config[1], report)

    if report.env_files or used:
        report.is_project = True

    check_env_drift(root, env, used, report)
    check_database_separation(env, report)
    check_production_env_values(env, report)
    check_project_level(root, report, configs, has_rate_limit, has_health, sensitive_routes)
    return report


BOX = {CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", REVIEW: "REVIEW"}


def render(report: Report, root: str) -> str:
    lines: List[str] = []
    counts = report.counts()
    findings = report.sorted_findings()

    lines.append("DEPLOY CHECK  %s" % os.path.abspath(root))
    lines.append("scanned %d source file(s), %d env file(s), found %d route(s)"
                 % (report.code_files, len(report.env_files), len(report.routes)))
    lines.append("")

    if not findings:
        if report.code_files == 0 and not report.env_files:
            lines.append("Nothing to scan here. Point --path at the project root.")
        else:
            lines.append("No deploy defects found in what can be checked statically.")
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
    lines.append("  - what is actually set in your hosting dashboard, which is the real config")
    lines.append("  - whether your database has backups, or whether anyone has restored one")
    lines.append("  - whether the app survives its first hundred concurrent users")
    lines.append("  - whether anything is watching while you sleep")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="deploy_check",
        description="Find the gap between what runs locally and what will run in production.",
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
            print("DEPLOY CHECK")
            print(message)
        return 0

    report = audit(root)

    if args.json:
        print(json.dumps({
            "root": os.path.abspath(root),
            "scanned": {"source": report.code_files, "env": report.env_files},
            "routes": report.routes,
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
