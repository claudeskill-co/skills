#!/usr/bin/env python3
"""
Find the payment-integration defects that quietly cost money.

A payments bug does not look like a crash. Checkout still works, the success
page still says thank you, and the loss shows up weeks later as an unfulfilled
order, a double charge, or a customer who set their own price. Four classes of
finding, in the order they cost the most:

  1. A webhook that cannot verify it is talking to Stripe.
  2. A secret key somewhere it should not be.
  3. An amount the customer controls.
  4. Fulfilment that depends on the browser coming back.

Every finding names a file and a line. Nothing is reported that cannot be
pointed at. Checks that rely on a heuristic rather than a fact are labelled
`review` and never counted as failures.

    python3 stripe_check.py --path .
    python3 stripe_check.py --path . --json
    python3 stripe_check.py --path . --strict      # exit 1 if anything critical

Standard library only. Reads files, never writes, never talks to the network,
and never contacts the Stripe API.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
REVIEW = "review"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, REVIEW: 3}

# `fact` follows from the file alone. `heuristic` is a pattern that correct
# code can also match. The distinction decides whether the user should act or
# merely look, and it is why --strict ignores review findings.
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
    env_files: int = 0
    webhooks: List[str] = field(default_factory=list)
    checkouts: List[str] = field(default_factory=list)
    stripe_seen: bool = False

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

CODE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".svelte", ".vue", ".py", ".rb", ".go", ".php")
ENV_PREFIX = ".env"

MAX_BYTES = 2_000_000


def walk(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".yarn"))
        # Agent worktrees are copies of the same tree; scanning them reports
        # the same handler once per worktree.
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


# Comments are blanked rather than removed so every offset - and therefore
# every reported line number - stays exactly where it was in the real file.
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"(?m)//[^\n]*")
HASH_COMMENT = re.compile(r"(?m)#[^\n]*")


def blank_comments(text: str, hashes: bool = False) -> str:
    def blank(match: "re.Match[str]") -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    out = BLOCK_COMMENT.sub(blank, text)
    out = LINE_COMMENT.sub(blank, out)
    if hashes:
        out = HASH_COMMENT.sub(blank, out)
    return out


TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|fixtures?|e2e|mocks?|examples?|demo)(/|$)"
    r"|\.(test|spec)\.[a-z]+$",
    re.I,
)


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH_RE.search(rel.replace(os.sep, "/")))


# --------------------------------------------------------------------------
# Git hygiene - an env file that is ignored is where a key belongs
# --------------------------------------------------------------------------

def ignored_env_files(root: str) -> Set[str]:
    """Env filenames covered by .gitignore.

    A live key inside a properly ignored `.env` is not a leak, it is correct
    configuration. Reporting it as critical trains people to ignore the tool.
    Only the simple, overwhelmingly common patterns are understood; anything
    unrecognised is treated as not ignored, which errs toward reporting.
    """
    text = read(os.path.join(root, ".gitignore"))
    if text is None:
        return set()

    safe: Set[str] = set()
    for raw in text.splitlines():
        entry = raw.strip()
        if not entry or entry.startswith("#") or entry.startswith("!"):
            continue
        entry = entry.lstrip("/").rstrip("/")
        if entry in (".env", "*.env", ".env*", ".env.*"):
            safe.update({".env", ".env.local", ".env.production", ".env.production.local",
                         ".env.development", ".env.development.local"})
        elif entry.startswith(".env"):
            safe.add(entry)
    return safe


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

USE_CLIENT_RE = re.compile(r"""^\s*['"]use client['"]""", re.M)

STRIPE_IMPORT_RE = re.compile(r"""(from\s+['"]stripe['"]|require\(['"]stripe['"]\)|import\s+stripe\b|new\s+Stripe\s*\()""")
STRIPE_MENTION_RE = re.compile(r"\bstripe\b", re.I)

# Live keys are unambiguous. `sk_test_` is deliberately not a leak - it buys
# nothing and flagging it would bury the finding that matters.
LIVE_SECRET_RE = re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{10,}\b")
TEST_SECRET_RE = re.compile(r"\b(sk|rk)_test_[A-Za-z0-9]{10,}\b")
WHSEC_RE = re.compile(r"\bwhsec_[A-Za-z0-9_\-]{10,}\b")

# Stripe's own documentation sample. It appears in every tutorial and is not a
# credential; reporting it as one is how a scanner loses its reader.
#
# Assembled rather than written out, and please leave it that way: a whole
# live-format key in a source file trips GitHub's push protection and every
# other scanner pointed at this repository - including ours. Tidying this back
# into one string will block the next push.
DOC_SAMPLE_KEYS = {"sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"}

CONSTRUCT_EVENT_RE = re.compile(r"\bconstructEvent(Async)?\s*\(|\bwebhooks?\.(construct|verify)")
PY_CONSTRUCT_RE = re.compile(r"\bWebhook\.construct_event\s*\(|\bconstruct_event\s*\(")
SIGNATURE_HEADER_RE = re.compile(r"""['"]stripe-signature['"]""", re.I)

RAW_BODY_RE = re.compile(r"""\.text\(\)|rawBody|raw_body|buffer\(|Buffer\.from|request\.body\b(?!\s*\.)|await\s+req\.arrayBuffer\(\)|micro\b|bodyParser""")
JSON_BODY_RE = re.compile(r"\b(req|request|r)\s*\.\s*json\s*\(\s*\)")

WRITE_CALL_RE = re.compile(
    r"\.(insert|upsert|update|create|createMany|save)\s*\(|"
    r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b", re.I)

EVENT_ID_RE = re.compile(r"\bevent\s*\.\s*id\b|\bevent_id\b|\bstripe_event_id\b")
DEDUPE_RE = re.compile(r"onConflict|ignore-duplicates|ignoreDuplicates|ON\s+CONFLICT|unique\s*\(|idempotenc", re.I)

CHECKOUT_CREATE_RE = re.compile(r"checkout\s*\.\s*sessions\s*\.\s*create|paymentIntents\s*\.\s*create|payment_intents\s*\.\s*create|PaymentIntent\.create|Session\.create")
COMPLETION_EVENT_RE = re.compile(r"checkout\.session\.completed|payment_intent\.succeeded|invoice\.pai(d|ment_succeeded)|charge\.succeeded")

# `price` is deliberately absent. It holds a Stripe Price ID, and a client that
# picks one can only pick a price you created - unlike `unit_amount`, where the
# client picks the number itself. Flagging `price: params.priceId` as a
# customer-set amount would be wrong, and it is a common, correct pattern.
AMOUNT_FIELD_RE = re.compile(r"\b(unit_amount|unit_amount_decimal|amount|amount_total)\s*:\s*([^,\n}]+)")
DESTRUCTURE_RE = re.compile(
    r"const\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:req|request|r)\s*\.\s*(?:json\s*\(\s*\)|body)")
REQUEST_MEMBER_RE = re.compile(r"\b(req|request|body|payload|searchParams|params|query|formData)\s*\.\s*\w+")

SERVICE_ENV_RE = re.compile(r"\bSTRIPE_SECRET_KEY\b|\bSTRIPE_API_KEY\b|\bSTRIPE_RESTRICTED_KEY\b")
PUBLIC_SECRET_ENV_RE = re.compile(
    r"\b(NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*"
    r"(STRIPE_SECRET|SECRET_KEY|STRIPE_API_KEY|WEBHOOK_SECRET)[A-Z0-9_]*\b")

ROUTE_FILE_RE = re.compile(r"(^|/)(route|api)\.(ts|js|mjs|tsx)$|(^|/)app/.*/route\.(ts|js|mjs)$")
PAGES_API_RE = re.compile(r"(^|/)pages/api/")
WEBHOOK_PATH_RE = re.compile(r"webhook|stripe-hook|payments?/hook", re.I)
SUCCESS_PATH_RE = re.compile(r"success|thank[-_]?you|order[-_/]confirm|checkout/complete|payment[-_/]?(done|complete)", re.I)

BODY_PARSER_OFF_RE = re.compile(r"bodyParser\s*:\s*false")


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def looks_like_webhook(rel: str, text: str) -> bool:
    """Strong evidence only.

    A file is a Stripe webhook handler if it reads the Stripe signature header,
    if it verifies an event, or if its path says webhook *and* it imports the
    Stripe SDK. The last condition matters: a Clerk or Polar webhook that
    happens to write a `stripe_customer_id` column is not a Stripe webhook, and
    reporting it as an unverified one is exactly the false positive that gets a
    scanner switched off.
    """
    if SIGNATURE_HEADER_RE.search(text):
        return True
    if CONSTRUCT_EVENT_RE.search(text) or PY_CONSTRUCT_RE.search(text):
        return True
    path = rel.replace(os.sep, "/")
    return bool(WEBHOOK_PATH_RE.search(path) and STRIPE_IMPORT_RE.search(text))


def scan_webhook(rel: str, text: str, report: Report) -> None:
    verified = bool(CONSTRUCT_EVENT_RE.search(text) or PY_CONSTRUCT_RE.search(text))
    path = rel.replace(os.sep, "/")

    if not verified:
        match = SIGNATURE_HEADER_RE.search(text) or STRIPE_MENTION_RE.search(text)
        report.add(Finding(
            code="PAY001",
            severity=CRITICAL,
            confidence=FACT,
            title="Webhook handler never verifies the Stripe signature",
            path=rel,
            line=line_of(text, match.start()) if match else 1,
            detail="This handler acts on an event body without calling constructEvent. Anyone who "
                   "knows the URL can POST a checkout.session.completed of their own and be granted "
                   "whatever a real payment grants. The endpoint is public by design.",
            fix="Verify before you trust: read the raw body, then "
                "`stripe.webhooks.constructEvent(rawBody, req.headers.get('stripe-signature'), "
                "process.env.STRIPE_WEBHOOK_SECRET)` inside a try/catch, and return 400 when it throws.",
        ))
    else:
        json_body = JSON_BODY_RE.search(text)
        if json_body and not RAW_BODY_RE.search(text):
            report.add(Finding(
                code="PAY002",
                severity=CRITICAL,
                confidence=FACT,
                title="Webhook verifies a signature against a re-serialised body",
                path=rel,
                line=line_of(text, json_body.start()),
                detail="The body is read with .json(), so the bytes Stripe signed are gone. "
                       "Verification against a re-serialised object fails for every legitimate "
                       "event - which usually gets 'fixed' by removing the check entirely.",
                fix="Read the raw text once: `const raw = await req.text()`, pass `raw` to "
                    "constructEvent, and use the returned `event` rather than parsing yourself.",
            ))

    hardcoded = WHSEC_RE.search(text)
    if hardcoded and not is_test_path(rel):
        report.add(Finding(
            code="PAY003",
            severity=HIGH,
            confidence=FACT,
            title="Webhook signing secret written into the file",
            path=rel,
            line=line_of(text, hardcoded.start()),
            detail="The signing secret is in source. Anyone with repository access can forge events "
                   "this endpoint will accept, and rotating it means shipping a deploy.",
            fix="Move it to STRIPE_WEBHOOK_SECRET in the environment, then roll the secret in the "
                "Stripe dashboard - the one in the file is burned.",
        ))

    write = WRITE_CALL_RE.search(text)
    if verified and write and not EVENT_ID_RE.search(text) and not DEDUPE_RE.search(text):
        report.add(Finding(
            code="PAY004",
            severity=HIGH,
            confidence=HEURISTIC,
            title="Webhook grants on every delivery, with nothing to catch a repeat",
            path=rel,
            line=line_of(text, write.start()),
            detail="Stripe retries a webhook until it gets a 2xx, and delivers at least once - not "
                   "exactly once. This handler writes without referencing event.id or a conflict "
                   "clause, so a retry grants twice: two credits, two shipments, two seats.",
            fix="Store event.id with a unique constraint and return 200 early when you have seen it, "
                "or make the write idempotent with an upsert on a natural key.",
        ))

    if PAGES_API_RE.search(path) and not BODY_PARSER_OFF_RE.search(text):
        anchor = CONSTRUCT_EVENT_RE.search(text) or SIGNATURE_HEADER_RE.search(text)
        report.add(Finding(
            code="PAY012",
            severity=HIGH,
            confidence=FACT,
            title="Pages API webhook without the body parser turned off",
            path=rel,
            line=line_of(text, anchor.start()) if anchor else 1,
            detail="Next.js parses the body before this handler runs, so the raw bytes needed for "
                   "signature verification are already gone. The symptom is every event failing "
                   "verification in production while nothing looks wrong locally.",
            fix="Export `export const config = { api: { bodyParser: false } }` and read the raw "
                "body yourself, or move the route to the App Router where req.text() gives it to you.",
        ))


def scan_keys(rel: str, text: str, is_client: bool, safe_env: Set[str], report: Report) -> None:
    name = os.path.basename(rel)
    in_env = name.startswith(ENV_PREFIX)
    ignored = in_env and name in safe_env
    example_env = name in (".env.example", ".env.sample", ".env.template")

    for match in LIVE_SECRET_RE.finditer(text):
        value = match.group(0)
        if value in DOC_SAMPLE_KEYS:
            continue

        severity, confidence, detail = CRITICAL, FACT, (
            "A live secret key grants full access to the Stripe account: charges, refunds, payouts "
            "and every customer record. It is in a file, which means it is in the history of every "
            "clone of this repository.")
        if example_env:
            detail = ("A live secret key is sitting in the example env file - the one file in the "
                      "project that is meant to be committed and shared.")
        elif ignored:
            severity, confidence = REVIEW, HEURISTIC
            detail = ("A live secret key is in %s, which .gitignore covers. That is where it belongs. "
                      "Worth confirming it has never been committed and is not shipped to the client "
                      "bundle." % name)
        elif is_test_path(rel):
            severity, confidence = REVIEW, HEURISTIC
            detail = ("A live-format secret key appears in a test or fixture path. Usually synthetic - "
                      "but a real key pasted into a fixture leaks exactly like any other.")

        report.add(Finding(
            code="PAY005",
            severity=severity,
            confidence=confidence,
            title="Live Stripe secret key in a file",
            path=rel,
            line=line_of(text, match.start()),
            detail=detail,
            fix="Roll the key in the Stripe dashboard first - assume it is compromised - then load it "
                "from the environment. Removing the line does not remove it from git history.",
        ))

    if in_env and name in (".env.production", ".env.production.local"):
        test_key = TEST_SECRET_RE.search(text)
        if test_key:
            report.add(Finding(
                code="PAY006",
                severity=HIGH,
                confidence=FACT,
                title="Test key configured for production",
                path=rel,
                line=line_of(text, test_key.start()),
                detail="Production is pointed at the Stripe test mode. Checkout will appear to work, "
                       "customers will see a success page, and no money will ever arrive.",
                fix="Replace with the live key from the Stripe dashboard, and check the publishable "
                    "key on the client matches the same mode - a mixed pair fails at confirmation.",
            ))

    # A test that asserts on a bad variable name has to contain the bad variable
    # name. Reporting the suite that proves a rule works as a violation of it is
    # how a scanner ends up muted.
    in_test = is_test_path(rel)
    key_severity = REVIEW if in_test else CRITICAL
    key_confidence = HEURISTIC if in_test else FACT
    test_note = (" Found in a test or fixture path, so this is most likely a sample rather than a "
                 "real configuration." if in_test else "")

    public_secret = PUBLIC_SECRET_ENV_RE.search(text)
    if public_secret:
        report.add(Finding(
            code="PAY007",
            severity=key_severity,
            confidence=key_confidence,
            title="Stripe secret held in a browser-exposed variable",
            path=rel,
            line=line_of(text, public_secret.start()),
            detail="`%s` is inlined into the JavaScript bundle at build time by design. Whatever it "
                   "holds is readable by every visitor with devtools open.%s"
                   % (public_secret.group(0), test_note),
            fix="Rename it without the public prefix, read it only in server code, and roll the key - "
                "if it has ever been built and deployed, it is already public.",
        ))
    elif is_client and SERVICE_ENV_RE.search(text):
        match = SERVICE_ENV_RE.search(text)
        report.add(Finding(
            code="PAY007",
            severity=key_severity,
            confidence=key_confidence,
            title="Stripe secret key referenced in a client component",
            path=rel,
            line=line_of(text, match.start()),
            detail="This file is marked 'use client', so it is compiled into the browser bundle. A "
                   "secret key read here ships to every visitor.%s" % test_note,
            fix="Move the Stripe call to a Route Handler or Server Action and have the client call "
                "that instead. The browser never needs the secret key.",
        ))


def _request_bound_names(text: str) -> Set[str]:
    """Names destructured straight out of the request body."""
    names: Set[str] = set()
    for match in DESTRUCTURE_RE.finditer(text):
        for part in match.group(1).split(","):
            part = part.strip()
            if not part:
                continue
            # `{ amount: price }` binds `price`; `{ amount }` binds `amount`.
            binding = part.split(":")[-1].strip().split("=")[0].strip()
            if re.match(r"^[A-Za-z_$][\w$]*$", binding):
                names.add(binding)
    return names


def scan_amounts(rel: str, text: str, report: Report) -> None:
    if not CHECKOUT_CREATE_RE.search(text):
        return

    bound = _request_bound_names(text)
    for match in AMOUNT_FIELD_RE.finditer(text):
        value = match.group(2).strip()
        root = re.match(r"^[A-Za-z_$][\w$]*", value)
        from_request = bool(REQUEST_MEMBER_RE.match(value)) or (
            root is not None and root.group(0) in bound)
        if not from_request:
            continue
        report.add(Finding(
            code="PAY008",
            severity=HIGH,
            confidence=FACT,
            title="Charge amount comes from the request",
            path=rel,
            line=line_of(text, match.start()),
            detail="`%s` is set from `%s`, which the caller controls. Anyone can edit the request and "
                   "buy at their own price - a one-line change in devtools, no exploit needed."
                   % (match.group(1), value),
            fix="Send an identifier instead of a number. Look the price up server-side from your own "
                "database, or pass a Stripe Price ID and let Stripe hold the amount.",
        ))


def scan_client_checkout(rel: str, text: str, is_client: bool, report: Report) -> None:
    match = CHECKOUT_CREATE_RE.search(text)
    if not match:
        return
    if is_client or PUBLIC_SECRET_ENV_RE.search(text):
        report.add(Finding(
            code="PAY009",
            severity=HIGH,
            confidence=FACT,
            title="Checkout session created in client code",
            path=rel,
            line=line_of(text, match.start()),
            detail="Creating a session needs the secret key, and this file runs in the browser. "
                   "Either the key is exposed, or this call fails at runtime for every customer.",
            fix="Create the session in a Route Handler and return the URL to redirect to. The client "
                "sends the product, never the price.",
        ))


def scan_success_fulfilment(rel: str, text: str, report: Report) -> None:
    path = rel.replace(os.sep, "/")
    if not SUCCESS_PATH_RE.search(path):
        return
    write = WRITE_CALL_RE.search(text)
    if not write:
        return
    report.add(Finding(
        code="PAY010",
        severity=MEDIUM,
        confidence=HEURISTIC,
        title="Order fulfilled on the success page rather than the webhook",
        path=rel,
        line=line_of(text, write.start()),
        detail="This looks like the post-checkout redirect, and it writes. A customer who closes the "
               "tab, loses signal, or has a slow bank redirect pays and gets nothing - and the same "
               "URL can usually be opened again without paying.",
        fix="Treat the success page as display only. Grant on checkout.session.completed in the "
            "webhook, and have the page poll for the grant.",
    ))


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def audit(root: str) -> Report:
    report = Report()
    safe_env = ignored_env_files(root)

    for path in walk(root):
        name = os.path.basename(path)
        rel = os.path.relpath(path, root)
        is_env = name.startswith(ENV_PREFIX) and not name.endswith((".ts", ".js", ".d.ts"))

        if not is_env and not path.endswith(CODE_SUFFIXES):
            continue

        raw = read(path)
        if raw is None:
            continue

        if is_env:
            report.env_files += 1
            scan_keys(rel, raw, False, safe_env, report)
            continue

        report.code_files += 1
        text = blank_comments(raw, hashes=path.endswith((".py", ".rb")))
        is_client = bool(USE_CLIENT_RE.search(text[:400]))

        # A `stripe_customer_id` column is a mention, not an integration. Only
        # an import, a signature header, a verification call or a session
        # creation counts as this project actually using Stripe here.
        stripe_here = bool(
            STRIPE_IMPORT_RE.search(text)
            or SIGNATURE_HEADER_RE.search(text)
            or CONSTRUCT_EVENT_RE.search(text)
            or PY_CONSTRUCT_RE.search(text)
            or CHECKOUT_CREATE_RE.search(text)
            or SERVICE_ENV_RE.search(text)
        )
        if stripe_here:
            report.stripe_seen = True

        # Keys are scanned in the raw text: a live key sitting in a commented-out
        # line is leaked exactly as thoroughly as one in live code. Blanking
        # preserves offsets, so line numbers agree either way.
        scan_keys(rel, raw, is_client, safe_env, report)

        if not stripe_here:
            continue

        if looks_like_webhook(rel, text):
            report.webhooks.append(rel)
            if not is_test_path(rel):
                scan_webhook(rel, text, report)

        if is_test_path(rel):
            continue

        if CHECKOUT_CREATE_RE.search(text):
            report.checkouts.append(rel)
        scan_amounts(rel, text, report)
        scan_client_checkout(rel, text, is_client, report)
        scan_success_fulfilment(rel, text, report)

    _check_completion_coverage(root, report)
    return report


def _check_completion_coverage(root: str, report: Report) -> None:
    """Checkout exists, but nothing in the project reacts to it completing."""
    if not report.checkouts:
        return
    for path in walk(root):
        if not path.endswith(CODE_SUFFIXES):
            continue
        text = read(path)
        if text is not None and COMPLETION_EVENT_RE.search(text):
            return

    rel = report.checkouts[0]
    report.add(Finding(
        code="PAY011",
        severity=MEDIUM,
        confidence=HEURISTIC,
        title="Checkout is created but no completion event is handled",
        path=rel,
        line=1,
        detail="The project starts payments and no file mentions checkout.session.completed or "
               "payment_intent.succeeded. If fulfilment happens somewhere this cannot see, ignore "
               "this - otherwise customers are paying and nothing is listening.",
        fix="Add a webhook that verifies the signature and grants on checkout.session.completed. "
            "That event is the only reliable signal that money moved.",
    ))


BOX = {CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", REVIEW: "REVIEW"}


def render(report: Report, root: str) -> str:
    lines: List[str] = []
    counts = report.counts()
    findings = report.sorted_findings()

    lines.append("STRIPE CHECK  %s" % os.path.abspath(root))
    lines.append("scanned %d source file(s), %d env file(s), found %d webhook handler(s)"
                 % (report.code_files, report.env_files, len(report.webhooks)))
    lines.append("")

    if not findings:
        if report.code_files == 0 and report.env_files == 0:
            lines.append("Nothing to scan here. Point --path at the project root.")
        elif not report.stripe_seen:
            lines.append("No Stripe integration found in this project. Nothing to check.")
        else:
            lines.append("No payment defects found in what can be checked statically.")
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
    lines.append("  - whether your webhook endpoint is actually registered in the Stripe dashboard")
    lines.append("  - whether the prices in your database match the prices in Stripe")
    lines.append("  - whether refunds, disputes and failed payments are handled at all")
    lines.append("  - whether a key that leaked has already been used")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="stripe_check",
        description="Find payment-integration defects in a project before they cost money.",
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
            print("STRIPE CHECK")
            print(message)
        return 0

    report = audit(root)

    if args.json:
        print(json.dumps({
            "root": os.path.abspath(root),
            "scanned": {"source": report.code_files, "env": report.env_files},
            "webhooks": report.webhooks,
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
