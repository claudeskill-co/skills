#!/usr/bin/env python3
"""
Run the whole Ship-Safe suite and answer one question: is this safe to launch?

Four scanners, one report, one verdict. Each scanner is a separate plugin that
works perfectly well on its own; this runs whichever of them are installed,
merges the findings, removes the duplicates that come from two tools noticing
the same line, and grades the result.

The verdict is the point, and it is honest about two things most tools are not:

  * **Coverage.** A scanner that is not installed did not pass - it did not
    run. Every report says which of the four ran and which did not, and a
    partial run can never be graded clear.
  * **Confidence.** A grade is driven by facts. Heuristics are shown, counted
    separately, and never on their own the reason something is blocked.

    python3 ship_check.py --path .
    python3 ship_check.py --path . --json
    python3 ship_check.py --path . --strict      # exit 1 unless the verdict is clear

Standard library only. Reads files, never writes, never talks to the network.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
REVIEW = "review"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, REVIEW: 3}
FACT = "fact"
HEURISTIC = "heuristic"

# Verdicts, worst first. The wording is deliberate: none of them says "safe".
BLOCKED = "BLOCKED"
RISKY = "RISKY"
CLEAR = "CLEAR"
PARTIAL = "INCOMPLETE"

SCAN_TIMEOUT = 180
# Four scanners at 180s each could hang a pre-commit hook for twelve minutes.
# The budget is shared, so the whole run is bounded no matter how many run.
TOTAL_BUDGET = 300

# Kept identical to the scanners' own copy - see the conformance test below.
TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|__mocks__|mocks?|spec|specs|fixtures?|testdata"
    r"|e2e|cypress|\.storybook|stories)(/|$)"
    r"|\.(test|spec|stories|fixture)\.[cm]?[jt]sx?$"
    r"|(^|/)test_[^/]+\.py$|_test\.py$|(^|/)conftest\.py$",
    re.I,
)


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH_RE.search(rel.replace(os.sep, "/")))


# Codes that mean "a credential is in the wrong place". These are the only
# findings two scanners legitimately report about the same line, so they are
# the only ones allowed to merge across tools. Everything else keeps its own
# identity - collapsing two different defects at one line destroyed the second
# one's fix text, which is the whole reason a user reads the report.
CREDENTIAL_CODES = {"PAY005", "PAY006", "PAY007"}
CREDENTIAL_PREFIXES = ("SEC", "KEY")


def family(code: str) -> str:
    if code in CREDENTIAL_CODES or code.startswith(CREDENTIAL_PREFIXES):
        return "credential"
    return code


@dataclass
class Scanner:
    plugin: str
    script: str
    covers: str


SCANNERS = (
    Scanner("rls-audit", "rls_audit.py", "access control"),
    Scanner("secret-sweep", "secret_sweep.py", "secrets"),
    Scanner("stripe-check", "stripe_check.py", "payments"),
    Scanner("deploy-check", "deploy_check.py", "deploy readiness"),
)

# db-guard is not in the list on purpose. It is a PreToolUse hook, not a
# scanner - there is nothing for it to report about a directory, and pretending
# to have "run" it would be the exact overclaim this tool exists to avoid.
HOOK_PLUGIN = "db-guard"


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
    source: str
    also: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        out = {
            "code": self.code,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "file": self.path,
            "line": self.line,
            "detail": self.detail,
            "fix": self.fix,
            "source": self.source,
        }
        if self.also:
            out["also_reported_by"] = self.also
        return out


@dataclass
class ScanResult:
    plugin: str
    covers: str
    ran: bool
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None


# --------------------------------------------------------------------------
# Finding the scanners
# --------------------------------------------------------------------------

def candidate_roots(explicit: Optional[str]) -> List[str]:
    """Places a sibling plugin might live, most specific first.

    Claude Code does not guarantee that two plugins from one marketplace end up
    adjacent on disk, so this looks in several plausible places rather than
    assuming a layout. Anything not found is reported as not found - never
    quietly skipped.
    """
    # An explicit --scanners is exclusive: if you say where they are, looking
    # anywhere else would silently contradict you, and would make a coverage
    # report impossible to trust.
    if explicit:
        return [explicit] if os.path.isdir(explicit) else []

    roots: List[str] = []
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if plugin_root:
        roots.append(os.path.dirname(os.path.abspath(plugin_root)))

    # scripts/ -> ship-check/ -> skills/ -> plugins/ship-check/ -> plugins/
    here = os.path.abspath(os.path.dirname(__file__))
    roots.append(os.path.abspath(os.path.join(here, "..", "..", "..", "..")))
    roots.append(os.path.abspath(os.path.join(here, "..", "..", "..", "..", "..")))

    seen: List[str] = []
    for root in roots:
        if root and os.path.isdir(root) and root not in seen:
            seen.append(root)
    return seen


def locate(scanner: Scanner, roots: List[str]) -> Optional[str]:
    for root in roots:
        path = os.path.join(root, scanner.plugin, "skills", scanner.plugin, "scripts", scanner.script)
        if os.path.isfile(path):
            return path
    return None


def hook_installed(roots: List[str]) -> bool:
    for root in roots:
        if os.path.isfile(os.path.join(root, HOOK_PLUGIN, "hooks", "hooks.json")):
            return True
    return False


# --------------------------------------------------------------------------
# Running them
# --------------------------------------------------------------------------

def run_scanner(scanner: Scanner, script: str, root: str,
                deadline: Optional[float] = None) -> ScanResult:
    result = ScanResult(plugin=scanner.plugin, covers=scanner.covers, ran=False)

    budget = SCAN_TIMEOUT
    if deadline is not None:
        budget = min(SCAN_TIMEOUT, max(0.0, deadline - time.monotonic()))
        if budget <= 0:
            result.error = "skipped: the %ds budget for the whole run was already spent" % TOTAL_BUDGET
            return result

    try:
        completed = subprocess.run(
            [sys.executable, script, "--path", root, "--json"],
            capture_output=True, text=True, timeout=budget,
        )
    except subprocess.TimeoutExpired:
        result.error = "timed out after %ds" % int(budget)
        return result
    except OSError as error:
        result.error = "could not start: %s" % error
        return result

    if not completed.stdout.strip():
        result.error = "produced no output (exit %d)" % completed.returncode
        return result

    try:
        payload = json.loads(completed.stdout)
    except ValueError:
        result.error = "output was not valid JSON"
        return result

    if "error" in payload and not payload.get("findings"):
        result.error = str(payload["error"])
        return result

    result.ran = True
    for raw in payload.get("findings", []):
        result.findings.append(Finding(
            code=str(raw.get("code", "?")),
            severity=str(raw.get("severity", REVIEW)),
            confidence=str(raw.get("confidence", HEURISTIC)),
            title=str(raw.get("title", "")),
            path=str(raw.get("file", "")),
            line=int(raw.get("line", 1) or 1),
            detail=str(raw.get("detail", "")),
            fix=str(raw.get("fix", "")),
            source=scanner.plugin,
        ))
    return result


# --------------------------------------------------------------------------
# Merging
# --------------------------------------------------------------------------

def merge(results: List[ScanResult]) -> List[Finding]:
    """One finding per place, not one per tool that noticed it.

    Two scanners legitimately overlap - a live Stripe key is both a secret and
    a payments defect - and the same line reported twice reads as two problems.
    The most severe version wins and names the others.
    """
    by_place: Dict[Tuple[str, int, str], Finding] = {}
    order: List[Tuple[str, int, str]] = []

    for result in results:
        for finding in result.findings:
            key = (finding.path, finding.line, family(finding.code))
            existing = by_place.get(key)
            if existing is None:
                by_place[key] = finding
                order.append(key)
                continue
            keep, drop = existing, finding
            if SEVERITY_ORDER.get(finding.severity, 9) < SEVERITY_ORDER.get(existing.severity, 9):
                keep, drop = finding, existing
                by_place[key] = finding
            # Carry the loser's own words, not just its code. A bare
            # "also reported by: deploy-check (DEP004)" tells the user nothing
            # about what to actually do.
            label = "%s (%s): %s - %s" % (drop.source, drop.code, drop.title, drop.fix)
            if label not in keep.also:
                keep.also.append(label)

    merged = [by_place[key] for key in order]
    merged.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.path, f.line))
    return merged


def counts_of(findings: List[Finding]) -> Dict[str, int]:
    out = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, REVIEW: 0}
    for finding in findings:
        out[finding.severity] = out.get(finding.severity, 0) + 1
    return out


def grade(findings: List[Finding], results: List[ScanResult]) -> Tuple[str, str]:
    """The verdict, and one sentence saying why.

    Facts drive it. A heuristic can raise a report to INCOMPLETE but never to
    BLOCKED on its own - being loudly wrong is how a pre-flight check stops
    being run at all.
    """
    ran = [r for r in results if r.ran]
    missing = [r for r in results if not r.ran]

    facts = [f for f in findings if f.confidence == FACT]
    critical = [f for f in facts if f.severity == CRITICAL]
    high = [f for f in facts if f.severity == HIGH]

    if critical:
        return BLOCKED, ("%d proven critical finding(s). Anything here is exploitable by someone who "
                         "has done nothing more than open your site." % len(critical))
    if high:
        return RISKY, ("%d proven high-severity finding(s) and nothing critical. None of these is an "
                       "open door on its own; each is a door left unlocked." % len(high))

    # A heuristic never blocks - being loudly wrong is how a pre-flight check
    # stops being run at all - but it does not vanish either. It raises the
    # verdict off clear and says exactly what it is.
    unproven = [f for f in findings
                if f.confidence != FACT and f.severity in (CRITICAL, HIGH)]
    if unproven:
        return RISKY, ("%d unproven finding(s) at critical or high severity, and nothing proven "
                       "above medium. These are pattern matches - read them before you decide."
                       % len(unproven))

    if not ran:
        return PARTIAL, "No scanner ran, so nothing was checked."
    if missing:
        return PARTIAL, ("%d of %d scanners ran. Nothing blocking was found in what was checked, and "
                         "%s went unchecked." % (len(ran), len(results),
                                                 " and ".join(r.covers for r in missing)))
    return CLEAR, ("All %d scanners ran and found nothing proven above medium. That is not the same "
                   "as safe - see the limits below." % len(ran))


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

BOX = {CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", REVIEW: "REVIEW"}

VERDICT_LINE = {
    BLOCKED: "BLOCKED   do not deploy this",
    RISKY: "RISKY     deployable, with known holes",
    CLEAR: "CLEAR     nothing proven blocking",
    PARTIAL: "INCOMPLETE  not everything was checked",
}


def render(findings: List[Finding], results: List[ScanResult], verdict: str,
           reason: str, root: str, hook: bool, show_all: bool) -> str:
    lines: List[str] = []
    counts = counts_of(findings)

    lines.append("SHIP CHECK  %s" % os.path.abspath(root))
    lines.append("")
    lines.append(VERDICT_LINE[verdict])
    lines.append("  %s" % reason)
    lines.append("")

    lines.append("Coverage")
    for result in results:
        if result.ran:
            lines.append("  ran      %-14s %-20s %d finding(s)"
                         % (result.plugin, result.covers, len(result.findings)))
        else:
            lines.append("  MISSING  %-14s %-20s %s"
                         % (result.plugin, result.covers, result.error or "not installed"))
    # Deliberately "found" rather than "ran": db-guard is a PreToolUse hook, so
    # this can see that the plugin is on disk but not whether it is enabled in
    # the user's settings. Claiming it is protecting them would be the overclaim
    # this whole report exists to avoid.
    lines.append("  %-8s %-14s %-20s %s"
                 % ("found" if hook else "MISSING", HOOK_PLUGIN, "destructive commands",
                    "a hook, so nothing to scan - confirm it is enabled"
                    if hook else "not installed - nothing is stopping a destructive command"))

    # A CLEAR verdict must never be silent about what it demoted. Everything
    # under a test or fixture path is downgraded by the scanners, so a project
    # whose real code lives in such a directory could otherwise be waved
    # through with live credentials in it.
    demoted = [f for f in findings if f.severity == REVIEW and is_test_path(f.path)]
    if demoted:
        places = sorted({os.path.dirname(f.path) or "." for f in demoted})
        lines.append("  note     %d finding(s) downgraded as test or fixture paths: %s"
                     % (len(demoted), ", ".join(places[:4])))
        lines.append("           if that is your real code, re-run the scanner with --include-tests")
    lines.append("")

    if not findings:
        lines.append("No findings.")
        lines.append("")
    else:
        lines.append("%d critical  %d high  %d medium  %d to review"
                     % (counts[CRITICAL], counts[HIGH], counts[MEDIUM], counts[REVIEW]))
        lines.append("")

        shown = findings if show_all else [f for f in findings if f.severity != REVIEW]
        for finding in shown:
            lines.append("[%s] %s  (%s / %s)"
                         % (BOX[finding.severity], finding.title, finding.source, finding.code))
            lines.append("  %s:%d" % (finding.path, finding.line))
            lines.append("  %s" % finding.detail)
            lines.append("  fix: %s" % finding.fix)
            if finding.also:
                lines.append("  also reported by: %s" % ", ".join(finding.also))
            if finding.confidence == HEURISTIC:
                lines.append("  note: pattern-matched, not proven. Confirm before acting.")
            lines.append("")

        hidden = len(findings) - len(shown)
        if hidden:
            lines.append("%d review-level finding(s) hidden. Run with --all to see them." % hidden)
            lines.append("")

    lines.append("What a clear result does not mean")
    lines.append("  - it does not mean the app is safe; it means four scanners found nothing proven")
    lines.append("  - none of this sees your hosting dashboard, where the real configuration lives")
    lines.append("  - none of this knows whether your database has a backup anyone has restored")
    lines.append("  - none of this is still true after your next deploy. This is a snapshot.")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ship_check",
        description="Run the Ship-Safe suite and grade whether a project is safe to launch.",
    )
    parser.add_argument("--path", default=".", help="project root to scan (default: current directory)")
    parser.add_argument("--scanners", default=None,
                        help="directory holding the sibling plugins, if they are not found automatically")
    parser.add_argument("--json", action="store_true", help="emit the merged report as JSON")
    parser.add_argument("--all", action="store_true", dest="show_all",
                        help="include review-level findings in the text report")
    # Two different failures, two different flags. Conflating them meant the
    # primary CI use case failed closed for a coverage reason rather than a
    # security one, every time a scanner was not installed.
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 when the verdict is BLOCKED or RISKY")
    parser.add_argument("--require-full-coverage", action="store_true",
                        dest="require_coverage",
                        help="exit 1 when any scanner did not run")
    args = parser.parse_args(argv)

    root = args.path
    if not os.path.isdir(root):
        message = "no such directory: %s" % root
        if args.json:
            print(json.dumps({"error": message, "findings": []}, indent=2))
        else:
            print("SHIP CHECK")
            print(message)
        return 0

    roots = candidate_roots(args.scanners)
    deadline = time.monotonic() + TOTAL_BUDGET
    results: List[ScanResult] = []
    for scanner in SCANNERS:
        script = locate(scanner, roots)
        if script is None:
            results.append(ScanResult(plugin=scanner.plugin, covers=scanner.covers, ran=False,
                                      error="not installed"))
            continue
        results.append(run_scanner(scanner, script, root, deadline))

    hook = hook_installed(roots)
    findings = merge(results)
    verdict, reason = grade(findings, results)

    if args.json:
        print(json.dumps({
            "root": os.path.abspath(root),
            "verdict": verdict,
            "reason": reason,
            "coverage": [
                {"plugin": r.plugin, "covers": r.covers, "ran": r.ran,
                 "findings": len(r.findings), "error": r.error}
                for r in results
            ] + [{"plugin": HOOK_PLUGIN, "covers": "destructive commands",
                  "ran": hook, "findings": 0,
                  "error": None if hook else "not installed"}],
            "counts": counts_of(findings),
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
    else:
        print(render(findings, results, verdict, reason, root, hook, args.show_all))

    if args.strict and verdict in (BLOCKED, RISKY):
        return 1
    if args.require_coverage and any(not r.ran for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
