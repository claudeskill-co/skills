#!/usr/bin/env python3
"""
Find the credentials your project is leaking, and say which ones are already gone.

Four questions, in the order that decides what you do next:

  1. Is a live key written into a file?
  2. Is a secret sitting in a variable the bundler ships to the browser?
  3. Is a file full of secrets tracked by git - and was it ever committed?
  4. Is a secret baked into a Dockerfile or a CI workflow?

Secrets are never printed in full. A report that quotes the key is one more
place the key exists.

    python3 secret_sweep.py --path .
    python3 secret_sweep.py --path . --json
    python3 secret_sweep.py --path . --strict     # exit 1 if anything critical

Standard library only. Reads files, never writes, never talks to the network.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# Model - deliberately identical to the other Ship-Safe scanners so the
# umbrella can merge their JSON without translating anything.
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


DOWNGRADE = {CRITICAL: REVIEW, HIGH: REVIEW, MEDIUM: REVIEW, REVIEW: REVIEW}


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    files: int = 0
    test_findings: int = 0
    safe_env_secrets: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_maybe_test(self, finding: Finding, in_test_path: bool) -> None:
        """A finding in a test path is shown, but never allowed to fail a build."""
        if in_test_path and finding.severity != REVIEW:
            finding.severity = DOWNGRADE[finding.severity]
            finding.confidence = HEURISTIC
            finding.detail += (" This sits in a test or fixture path, so it is most likely "
                               "a synthetic value - check it rather than rotating blind.")
            self.test_findings += 1
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
# Walking
# --------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", "node_modules", ".next", "dist", "build", "out", "coverage",
    "__pycache__", ".venv", "venv", ".turbo", ".vercel", "vendor", ".cache",
}

BINARY_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".svg", ".pdf",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".zip",
    ".gz", ".tgz", ".lock", ".map",
)

MAX_BYTES = 2_000_000


def walk(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        # Agent worktrees are copies of the same tree; scanning them turns one
        # finding into six identical ones.
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


def mask(secret: str) -> str:
    """Show enough to identify the key, never enough to use it."""
    stripped = secret.strip().strip("'\"")
    if len(stripped) <= 8:
        return "*" * len(stripped)
    return "%s%s%s" % (stripped[:4], "*" * 8, stripped[-2:])


# --------------------------------------------------------------------------
# Provider patterns
#
# Each entry is a credential that is worth money the moment it is read. The
# `live` flag separates keys that work in production from test keys, because
# telling somebody their Stripe test key leaked is how you get uninstalled.
# --------------------------------------------------------------------------

@dataclass
class Pattern:
    code: str
    name: str
    regex: "re.Pattern[str]"
    live: bool = True
    rotate: str = ""


PATTERNS: List[Pattern] = [
    Pattern("SEC001", "Stripe live secret key",
            re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}"),
            rotate="Roll it in the Stripe dashboard: Developers - API keys."),
    Pattern("SEC002", "Stripe test secret key",
            re.compile(r"\b[sr]k_test_[A-Za-z0-9]{16,}"), live=False,
            rotate="Harmless against real money, but move it out of source anyway."),
    Pattern("SEC003", "Stripe webhook signing secret",
            re.compile(r"\bwhsec_[A-Za-z0-9]{16,}"),
            rotate="Roll it in the Stripe dashboard under the endpoint's details."),
    Pattern("SEC004", "OpenAI API key",
            re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}"),
            rotate="Revoke it at platform.openai.com/api-keys."),
    Pattern("SEC005", "Anthropic API key",
            re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}"),
            rotate="Revoke it in the Anthropic console under API keys."),
    Pattern("SEC006", "AWS access key id",
            re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            rotate="Deactivate it in IAM, then delete it. Check CloudTrail for use."),
    Pattern("SEC007", "Google API key",
            re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
            rotate="Regenerate it in the Google Cloud console, and add key restrictions."),
    Pattern("SEC008", "GitHub token",
            re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}"),
            rotate="Revoke it in GitHub settings - Developer settings - Tokens."),
    Pattern("SEC009", "Slack token",
            re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
            rotate="Revoke it in the Slack app's OAuth settings."),
    Pattern("SEC010", "SendGrid API key",
            re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
            rotate="Delete it in SendGrid under Settings - API Keys."),
    Pattern("SEC011", "Twilio auth token",
            re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
            rotate="Rotate it in the Twilio console."),
    Pattern("SEC012", "Razorpay live key",
            re.compile(r"\brzp_live_[A-Za-z0-9]{10,}"),
            rotate="Regenerate it in the Razorpay dashboard under API keys."),
    Pattern("SEC013", "Supabase secret key",
            re.compile(r"\bsb_secret_[A-Za-z0-9_-]{8,}"),
            rotate="Roll it in the Supabase dashboard under Project settings - API."),
    Pattern("SEC014", "Private key block",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
            rotate="Generate a new key pair. Treat the old one as public."),
    Pattern("SEC015", "Database URL with an inline password",
            re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
                       r"[^\s:'\"]+:[^\s@'\"]{6,}@[^\s'\"/]+"),
            rotate="Change the database password, then move the URL into the environment."),
]

# Supabase/PostgREST JWTs are role-bearing; only service_role is a secret.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")

PUBLIC_PREFIX = r"(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC|GATSBY)"
PUBLIC_SECRET_NAME_RE = re.compile(
    r"\b%s_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|TOKEN|API_KEY)[A-Z0-9_]*" % PUBLIC_PREFIX
)

# The ways a variable is actually read from the environment. Used to confirm
# that a matched name is a real env var rather than a lookalike identifier.
ENV_ACCESS_RE = re.compile(
    r"process\.env[.\[]\s*['\"]?$|import\.meta\.env[.\[]\s*['\"]?$|"
    r"Deno\.env\.get\(\s*['\"]$|\benv[.\[]\s*['\"]?$|getenv\(\s*['\"]$"
)

USE_CLIENT_RE = re.compile(r"^\s*['\"]use client['\"]", re.MULTILINE)

# A name that should never hold a literal in source.
SECRET_NAME_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?TOKEN|PRIVATE_?KEY|AUTH_?TOKEN|CLIENT_?SECRET))\b"
    r"\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]",
    re.IGNORECASE,
)

PLACEHOLDER_RE = re.compile(
    # A value that starts with $ is a reference to a variable, not the value of one.
    r"^(?:\$|your|my|the|some|test|dummy|fake|sample|example|placeholder|changeme|change_me|"
    r"replace|insert|todo|xxx+|abc+|123+|foo|bar|secret|password|<.*>|\.\.\.|process\.env)",
    re.IGNORECASE,
)

# Test fixtures are full of credential-shaped strings that are not credentials.
# Screaming about them is how a scanner gets uninstalled, so findings in these
# paths are downgraded to `review` rather than reported as leaks - visible, but
# never able to fail a build. `--include-tests` turns the downgrade off.
TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|testdata|e2e|cypress|"
    r"\.storybook|stories)(?:/|$)"
    r"|\.(?:test|spec|stories|fixture)\.[cm]?[jt]sx?$"
    r"|(?:^|/)test_[^/]+\.py$|_test\.py$|(?:^|/)conftest\.py$"
)

ENV_NAME_RE = re.compile(r"^\.env(?:\..*)?$")
DOCKERFILE_RE = re.compile(r"^Dockerfile(?:\..*)?$|^Containerfile$", re.IGNORECASE)
CI_PATH_RE = re.compile(r"\.(?:github/workflows|gitlab-ci|circleci)/|\.gitlab-ci\.ya?ml$|"
                        r"^\.travis\.ya?ml$|^azure-pipelines\.ya?ml$")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = float(len(value))
    return -sum((n / total) * math.log(n / total, 2) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    stripped = value.strip().strip("'\"")
    if len(stripped) < 8:
        return True
    if PLACEHOLDER_RE.match(stripped):
        return True
    if len(set(stripped)) <= 3:  # xxxxxxxx, aaaaaaaa
        return True
    # A real credential is dense. English words and paths are not.
    if shannon_entropy(stripped) < 3.0:
        return True
    return False


def decode_jwt_role(payload: str) -> Optional[str]:
    padded = payload + "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", "replace")
    except Exception:
        return None
    match = re.search(r'"role"\s*:\s*"([A-Za-z_]+)"', decoded)
    return match.group(1) if match else None


# --------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------

def git(root: str, *args: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "-C", root] + list(args),
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def is_repo(root: str) -> bool:
    return git(root, "rev-parse", "--is-inside-work-tree") is not None


def tracked_files(root: str) -> Optional[set]:
    output = git(root, "ls-files")
    if output is None:
        return None
    return set(line.strip() for line in output.splitlines() if line.strip())


def ever_committed(root: str, relative: str) -> bool:
    output = git(root, "log", "--all", "--oneline", "--", relative)
    return bool(output and output.strip())


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def scan_patterns(rel: str, text: str, report: Report, in_env: bool, in_test: bool) -> None:
    seen: set = set()

    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(0)
            key = (pattern.code, value)
            if key in seen:
                continue
            seen.add(key)

            if pattern.code == "SEC004" and "sk-ant-" in value:
                continue  # Anthropic keys also match the OpenAI shape; SEC005 owns them.

            severity = CRITICAL if pattern.live else MEDIUM
            report.add_maybe_test(Finding(
                code=pattern.code,
                severity=severity,
                confidence=FACT,
                title="%s in %s" % (pattern.name, "an env file" if in_env else "source"),
                path=rel,
                line=line_of(text, match.start()),
                detail="Found `%s`. This is a recognisable %s, not a guess."
                       % (mask(value), pattern.name.lower()),
                fix=pattern.rotate or "Move it into the environment and rotate it.",
            ), in_test)

    for match in JWT_RE.finditer(text):
        if decode_jwt_role(match.group(1)) == "service_role":
            report.add_maybe_test(Finding(
                code="SEC016",
                severity=CRITICAL,
                confidence=FACT,
                title="Supabase service_role key",
                path=rel,
                line=line_of(text, match.start()),
                detail="A service_role JWT. It bypasses every row level security policy "
                       "you have, so whoever reads it owns the database.",
                fix="Roll it in Supabase under Project settings - API, then move it into the environment.",
            ), in_test)


def scan_generic_assignments(rel: str, text: str, report: Report, in_test: bool) -> None:
    for match in SECRET_NAME_RE.finditer(text):
        name, value = match.group(1), match.group(2)
        if looks_like_placeholder(value):
            continue
        # Already reported by a provider pattern? Then this adds nothing.
        if any(p.regex.search(value) for p in PATTERNS):
            continue
        report.add_maybe_test(Finding(
            code="SEC020",
            severity=HIGH,
            confidence=HEURISTIC,
            title="Credential-shaped literal assigned in source",
            path=rel,
            line=line_of(text, match.start()),
            detail="`%s` is set to `%s` - a dense value in a variable named like a secret. "
                   "No provider signature matched, so this may be something harmless."
                   % (name, mask(value)),
            fix="If it is a real credential, move it into the environment and rotate it. "
                "If it is not, ignore this.",
        ), in_test)


def scan_public_exposure(rel: str, text: str, report: Report, is_client: bool, in_test: bool) -> None:
    in_env_file = bool(ENV_NAME_RE.match(os.path.basename(rel)))

    for match in PUBLIC_SECRET_NAME_RE.finditer(text):
        name = match.group(0)
        tail_end = text.find("\n", match.end())
        tail = text[match.end():tail_end if tail_end != -1 else len(text)]

        # The name has to actually be an environment variable. A bare identifier
        # that happens to match - a constant, a regex, a comment - is not a leak,
        # and reporting one costs more trust than the finding is worth.
        if in_env_file:
            # In an env file, an empty assignment is a template, not a leak.
            if not tail.strip().lstrip("=").strip():
                continue
            if not re.match(r"\s*=", tail):
                continue
        elif not ENV_ACCESS_RE.search(text[max(0, match.start() - 32):match.start()]):
            continue
        report.add_maybe_test(Finding(
            code="SEC021",
            severity=CRITICAL,
            confidence=FACT,
            title="Secret held in a browser-exposed variable",
            path=rel,
            line=line_of(text, match.start()),
            detail="`%s` carries a prefix that tells the bundler to inline its value into "
                   "the JavaScript every visitor downloads." % name,
            fix="Drop the public prefix, read it only in server code, and rotate the value.",
        ), in_test)

    if is_client:
        for match in re.finditer(r"\bprocess\.env\.([A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD)[A-Z0-9_]*)", text):
            if match.group(1).startswith(("NEXT_PUBLIC", "VITE", "PUBLIC", "EXPO_PUBLIC")):
                continue  # already covered above
            report.add_maybe_test(Finding(
                code="SEC022",
                severity=CRITICAL,
                confidence=FACT,
                title="Server secret read from a client component",
                path=rel,
                line=line_of(text, match.start()),
                detail="This file is marked `'use client'` and reads `%s`. Anything a client "
                       "component reads can end up in the bundle." % match.group(1),
                fix="Move this into a Server Component, Route Handler or Server Action.",
            ), in_test)


def scan_build_config(rel: str, text: str, report: Report, in_test: bool) -> None:
    name = os.path.basename(rel)
    normalised = rel.replace(os.sep, "/")

    if DOCKERFILE_RE.match(name):
        for match in re.finditer(
            r"^\s*(?:ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*(?:SECRET|PASSWORD|KEY|TOKEN)[A-Za-z0-9_]*)"
            r"\s*[= ]\s*(\S+)", text, re.MULTILINE | re.IGNORECASE,
        ):
            if looks_like_placeholder(match.group(2)):
                continue
            report.add_maybe_test(Finding(
                code="SEC030",
                severity=HIGH,
                confidence=FACT,
                title="Secret baked into an image layer",
                path=rel,
                line=line_of(text, match.start()),
                detail="`%s` is set in the Dockerfile, so its value is stored in the image "
                       "layer and readable by anyone who pulls the image - deleting it in a "
                       "later layer does not remove it." % match.group(1),
                fix="Pass it at runtime, or use a build secret mount.",
            ), in_test)

    if CI_PATH_RE.search(normalised):
        for match in re.finditer(
            r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:SECRET|PASSWORD|KEY|TOKEN)[A-Za-z0-9_]*)\s*:\s*(\S+)",
            text, re.MULTILINE | re.IGNORECASE,
        ):
            value = match.group(2)
            if value.startswith(("${{", "$", "{{", "'${{", '"${{')) or looks_like_placeholder(value):
                continue
            report.add_maybe_test(Finding(
                code="SEC031",
                severity=HIGH,
                confidence=FACT,
                title="Secret written into a CI workflow",
                path=rel,
                line=line_of(text, match.start()),
                detail="`%s` holds a literal in a workflow file, which is committed and "
                       "visible to anyone who can read the repository." % match.group(1),
                fix="Move it into the provider's encrypted secrets and reference it, e.g. "
                    "${{ secrets.NAME }}.",
            ), in_test)


def scan_git_hygiene(root: str, report: Report) -> set:
    """
    Judge each env file, and return the ones that are safe.

    An env file that git ignores and has never seen is not a leak - it is the
    correct place for credentials to live. Reporting every key inside one as
    critical is how a scanner teaches people to ignore it.
    """
    safe: set = set()

    if not is_repo(root):
        return safe
    tracked = tracked_files(root)
    if tracked is None:
        return safe

    gitignore = read(os.path.join(root, ".gitignore")) or ""
    ignores_env = bool(re.search(r"^\s*\.env", gitignore, re.MULTILINE))

    for path in walk(root):
        name = os.path.basename(path)
        if not ENV_NAME_RE.match(name):
            continue
        if name in (".env.example", ".env.sample", ".env.template"):
            continue

        rel = os.path.relpath(path, root)
        normalised = rel.replace(os.sep, "/")

        if normalised not in tracked and not ever_committed(root, normalised) and ignores_env:
            safe.add(rel)

        if normalised in tracked:
            report.add(Finding(
                code="SEC040",
                severity=CRITICAL,
                confidence=FACT,
                title="Environment file is tracked by git",
                path=rel,
                line=1,
                detail="`%s` is committed. Everything in it is in the repository history, "
                       "and on every clone and fork that has ever been made." % normalised,
                fix="git rm --cached %s, add it to .gitignore, then rotate every value in it. "
                    "Removing the file does not remove it from history." % normalised,
            ))
        elif ever_committed(root, normalised):
            report.add(Finding(
                code="SEC041",
                severity=CRITICAL,
                confidence=FACT,
                title="Environment file was committed in the past",
                path=rel,
                line=1,
                detail="`%s` is untracked now, but it exists in the git history. Anyone with "
                       "the repository can read the values it held." % normalised,
                fix="Rotate every credential it ever contained. Rewriting history helps only "
                    "if no clone or fork already has it.",
            ))
        elif not ignores_env:
            report.add(Finding(
                code="SEC042",
                severity=HIGH,
                confidence=FACT,
                title="Environment file is not ignored",
                path=rel,
                line=1,
                detail="`%s` is not committed yet, and nothing in .gitignore covers it. "
                       "One `git add -A` puts it in the repository." % normalised,
                fix="Add `.env*` to .gitignore, keeping an exception for .env.example.",
            ))

    return safe


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def count_secrets(text: str) -> int:
    """How many credentials a file holds, for reporting without listing them."""
    found = set()
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            found.add(match.group(0))
    for match in JWT_RE.finditer(text):
        if decode_jwt_role(match.group(1)) == "service_role":
            found.add(match.group(0))
    return len(found)


def sweep(root: str, include_tests: bool = False) -> Report:
    report = Report()

    # Judge the env files first: whether a credential inside one matters at all
    # depends on whether git can see the file.
    safe_env = scan_git_hygiene(root, report)

    for path in walk(root):
        if path.endswith(BINARY_SUFFIXES):
            continue
        rel = os.path.relpath(path, root)
        name = os.path.basename(path)
        text = read(path)
        if text is None:
            continue

        report.files += 1
        in_env = bool(ENV_NAME_RE.match(name))
        is_example = name in (".env.example", ".env.sample", ".env.template")
        is_client = bool(USE_CLIENT_RE.search(text[:400]))
        in_test = (not include_tests) and bool(TEST_PATH_RE.search(rel.replace(os.sep, "/")))

        # A key inside an ignored, never-committed env file is in the right
        # place. The exposure question is answered by the git checks, not by
        # listing every value the file holds.
        if in_env and rel in safe_env:
            report.safe_env_secrets += count_secrets(text)
            continue

        if not is_example:
            scan_patterns(rel, text, report, in_env, in_test)
            scan_generic_assignments(rel, text, report, in_test)
        scan_public_exposure(rel, text, report, is_client, in_test)
        scan_build_config(rel, text, report, in_test)

    return report


BOX = {CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", REVIEW: "REVIEW"}


def render(report: Report, root: str) -> str:
    lines: List[str] = []
    counts = report.counts()
    findings = report.sorted_findings()

    lines.append("SECRET SWEEP  %s" % os.path.abspath(root))
    lines.append("scanned %d file(s)" % report.files)
    lines.append("")

    if report.safe_env_secrets:
        lines.append("%d credential(s) sit in env files that git ignores and has never seen."
                     % report.safe_env_secrets)
        lines.append("That is where they belong, so they are not listed below.")
        lines.append("")

    if not findings:
        if report.files == 0:
            lines.append("Nothing to scan here. Point --path at the project root.")
        else:
            lines.append("No exposed credentials found.")
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

        if counts[CRITICAL]:
            lines.append("Rotate before you do anything else. A key that has been on disk is")
            lines.append("burned whether or not you can prove someone read it.")
            lines.append("")

        if report.test_findings:
            lines.append("%d finding(s) sit in test or fixture paths and were downgraded to review,"
                         % report.test_findings)
            lines.append("because that is where synthetic keys live. Re-run with --include-tests")
            lines.append("to see them at full severity.")
            lines.append("")

    lines.append("What this cannot tell you")
    lines.append("  - whether a leaked key has already been used, which needs provider logs")
    lines.append("  - anything about secrets in a service you have already deployed to")
    lines.append("  - whether a credential shape it does not recognise is sitting in plain sight")
    lines.append("  - whether this stays true after your next commit")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secret_sweep",
        description="Find credentials committed, exposed to the browser, or baked into builds.",
    )
    parser.add_argument("--path", default=".", help="project root to scan (default: current directory)")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 when a critical or high finding is present")
    parser.add_argument("--include-tests", action="store_true",
                        help="report findings in test and fixture paths at full severity "
                             "(they are downgraded to review by default)")
    args = parser.parse_args(argv)

    root = args.path
    if not os.path.isdir(root):
        message = "no such directory: %s" % root
        if args.json:
            print(json.dumps({"error": message, "findings": []}, indent=2))
        else:
            print("SECRET SWEEP")
            print(message)
        return 0

    report = sweep(root, include_tests=args.include_tests)

    if args.json:
        print(json.dumps({
            "root": os.path.abspath(root),
            "scanned": {"files": report.files, "inTestPaths": report.test_findings},
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
