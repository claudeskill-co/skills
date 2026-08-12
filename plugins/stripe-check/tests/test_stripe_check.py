#!/usr/bin/env python3
"""
Regression tests for the payments checker.

Stdlib `unittest` only, matching the repository's zero-dependency rule.

    python3 -m unittest discover -s tests -v

The false-positive suites carry as much weight as the detection ones. A
payments scanner that cries wolf about a correct integration gets muted, and a
muted scanner is worth less than no scanner: it leaves the reader believing
something was checked.
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
SCRIPT = ROOT / "skills" / "stripe-check" / "scripts" / "stripe_check.py"
sys.path.insert(0, str(SCRIPT.parent))

import stripe_check as sc  # noqa: E402


class ProjectCase(unittest.TestCase):
    """Builds a throwaway project tree and audits it."""

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

    def audit(self):
        return sc.audit(self.root)

    def codes(self):
        return [f.code for f in self.audit().sorted_findings()]

    def finding(self, code):
        matches = [f for f in self.audit().findings if f.code == code]
        self.assertTrue(matches, "expected a %s finding, got %s" % (code, self.codes()))
        return matches[0]


# A webhook written the way the Stripe docs write it. Nothing here may be
# reported: this is the shape users are told to copy.
GOOD_WEBHOOK = """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const raw = await req.text();
  const sig = req.headers.get("stripe-signature");
  let event;
  try {
    event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return new Response("bad signature", { status: 400 });
  }
  if (event.type === "checkout.session.completed") {
    await db.from("grants").upsert({ event_id: event.id }, { onConflict: "event_id" });
  }
  return new Response("ok");
}
"""


class TestCorrectIntegrationIsSilent(ProjectCase):

    def test_documented_webhook_produces_nothing(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.assertEqual(self.codes(), [])

    def test_server_checkout_with_price_id_produces_nothing(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const { productId } = await req.json();
  const price = await lookupPrice(productId);
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: price.stripe_price_id, quantity: 1 }],
  });
  return Response.json({ url: session.url });
}
""")
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.assertEqual(self.codes(), [])

    def test_project_without_stripe_produces_nothing(self):
        self.write("app/page.tsx", "export default function Page() { return <div>hi</div>; }")
        self.write("lib/db.ts", "export const db = createClient(process.env.DATABASE_URL);")
        report = self.audit()
        self.assertEqual(report.findings, [])
        self.assertFalse(report.stripe_seen)

    def test_stripe_customer_id_column_is_not_an_integration(self):
        """A column name is a mention, not a Stripe integration."""
        self.write("supabase/functions/clerk-webhook/route.ts", """
export async function POST(req) {
  const body = await req.json();
  await db.from("profiles").insert({ stripe_customer_id: body.data.id });
  return new Response("ok");
}
""")
        self.assertEqual(self.codes(), [])

    def test_empty_project_is_clean(self):
        report = self.audit()
        self.assertEqual(report.findings, [])
        self.assertEqual(report.code_files, 0)


class TestSignatureVerification(ProjectCase):

    def test_unverified_webhook_is_critical(self):
        self.write("app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
export async function POST(req) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await db.from("subscriptions").insert({ user_id: event.data.object.metadata.userId });
  }
  return new Response("ok");
}
""")
        finding = self.finding("PAY001")
        self.assertEqual(finding.severity, sc.CRITICAL)
        self.assertEqual(finding.confidence, sc.FACT)

    def test_constructevent_satisfies_the_check(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.assertNotIn("PAY001", self.codes())

    def test_python_construct_event_satisfies_the_check(self):
        self.write("api/stripe_webhook.py", """
import stripe

def handler(request):
    payload = request.data
    sig = request.headers["stripe-signature"]
    event = stripe.Webhook.construct_event(payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"])
    return event
""")
        self.assertNotIn("PAY001", self.codes())

    def test_signature_header_alone_identifies_a_webhook(self):
        """Even outside a path called webhook."""
        self.write("server/handlers/payments.ts", """
import Stripe from "stripe";
export async function handle(req) {
  const sig = req.headers["stripe-signature"];
  const event = JSON.parse(req.body);
  return event;
}
""")
        self.assertIn("PAY001", self.codes())

    def test_json_body_with_verification_is_pay002(self):
        self.write("app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const body = await req.json();
  const event = stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature"),
    process.env.STRIPE_WEBHOOK_SECRET);
  return new Response("ok");
}
""")
        finding = self.finding("PAY002")
        self.assertEqual(finding.severity, sc.CRITICAL)
        self.assertNotIn("PAY001", self.codes())

    def test_raw_text_body_is_not_pay002(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.assertNotIn("PAY002", self.codes())

    def test_pay001_and_pay002_are_mutually_exclusive(self):
        """A handler is either unverified or verified badly, never both."""
        self.write("app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
export async function POST(req) { const e = await req.json(); return new Response("ok"); }
""")
        codes = self.codes()
        self.assertIn("PAY001", codes)
        self.assertNotIn("PAY002", codes)


class TestSigningSecret(ProjectCase):

    def test_hardcoded_whsec_is_reported(self):
        self.write("app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const raw = await req.text();
  const event = stripe.webhooks.constructEvent(raw, req.headers.get("stripe-signature"),
    "whsec_9sdKJ2laksjdSDF83kdjfSDF9");
  return new Response("ok");
}
""")
        self.assertEqual(self.finding("PAY003").severity, sc.HIGH)

    def test_whsec_in_a_test_file_is_not_reported(self):
        self.write("tests/webhook.test.ts", """
import Stripe from "stripe";
const stripe = new Stripe("sk_test_abc123456789");
const secret = "whsec_9sdKJ2laksjdSDF83kdjfSDF9";
const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);
""")
        self.assertNotIn("PAY003", self.codes())


class TestIdempotency(ProjectCase):

    def test_write_without_event_id_is_flagged(self):
        self.write("app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const raw = await req.text();
  const event = stripe.webhooks.constructEvent(raw, req.headers.get("stripe-signature"),
    process.env.STRIPE_WEBHOOK_SECRET);
  await db.from("credits").insert({ user_id: event.data.object.client_reference_id, amount: 100 });
  return new Response("ok");
}
""")
        finding = self.finding("PAY004")
        self.assertEqual(finding.severity, sc.HIGH)
        self.assertEqual(finding.confidence, sc.HEURISTIC)

    def test_event_id_reference_clears_it(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.assertNotIn("PAY004", self.codes())

    def test_on_conflict_clears_it(self):
        self.write("app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const raw = await req.text();
  const e = stripe.webhooks.constructEvent(raw, req.headers.get("stripe-signature"), process.env.WH);
  await db.from("credits").insert({ id: e.data.object.id }, { onConflict: "id" });
  return new Response("ok");
}
""")
        self.assertNotIn("PAY004", self.codes())

    def test_unverified_webhook_is_not_also_flagged_for_idempotency(self):
        """Signature first. Two findings on one line is noise, not rigour."""
        self.write("app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
export async function POST(req) {
  const event = await req.json();
  await db.from("credits").insert({ amount: 100 });
  return new Response("ok");
}
""")
        codes = self.codes()
        self.assertIn("PAY001", codes)
        self.assertNotIn("PAY004", codes)


class TestPagesApiBodyParser(ProjectCase):

    def test_missing_body_parser_config_is_flagged(self):
        self.write("pages/api/webhooks/stripe.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export default async function handler(req, res) {
  const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"],
    process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: true });
}
""")
        self.assertEqual(self.finding("PAY012").severity, sc.HIGH)

    def test_body_parser_false_clears_it(self):
        self.write("pages/api/webhooks/stripe.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export const config = { api: { bodyParser: false } };
export default async function handler(req, res) {
  const event = stripe.webhooks.constructEvent(await buffer(req),
    req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: true });
}
""")
        self.assertNotIn("PAY012", self.codes())

    def test_app_router_webhook_is_not_flagged(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.assertNotIn("PAY012", self.codes())


# Synthetic, and assembled rather than written out. A whole live-format key in
# a committed file trips GitHub's push protection - it blocked this very branch
# on the first attempt - and would be flagged by our own scanners too. Joining
# it back into one literal will block the next push.
LIVE_KEY = "sk_" + "live_" + "51QxAbCdEfGhIjKlMnOpQrStUv"
DOC_SAMPLE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"


class TestKeys(ProjectCase):

    def test_live_key_in_source_is_critical(self):
        self.write("lib/billing.ts", 'import Stripe from "stripe";\nexport const stripe = new Stripe("%s");\n' % LIVE_KEY)
        finding = self.finding("PAY005")
        self.assertEqual(finding.severity, sc.CRITICAL)
        self.assertEqual(finding.line, 2)

    def test_live_key_in_a_comment_is_still_reported(self):
        self.write("lib/billing.ts", 'import Stripe from "stripe";\n// old key: %s\n' % LIVE_KEY)
        self.assertEqual(self.finding("PAY005").line, 2)

    def test_stripe_documentation_sample_is_not_a_leak(self):
        """It appears in every tutorial. Flagging it is how a scanner gets muted."""
        self.write("lib/billing.ts",
                   'import Stripe from "stripe";\n'
                   'export const stripe = new Stripe("%s");\n' % DOC_SAMPLE_KEY)
        self.assertNotIn("PAY005", self.codes())

    def test_key_in_a_gitignored_env_file_is_only_review(self):
        """That is where a key belongs. Calling it critical trains people to mute the tool."""
        self.write(".gitignore", "node_modules\n.env*\n")
        self.write(".env.local", "STRIPE_SECRET_KEY=%s\n" % LIVE_KEY)
        finding = self.finding("PAY005")
        self.assertEqual(finding.severity, sc.REVIEW)

    def test_key_in_an_untracked_env_file_without_gitignore_is_critical(self):
        self.write(".env.local", "STRIPE_SECRET_KEY=%s\n" % LIVE_KEY)
        self.assertEqual(self.finding("PAY005").severity, sc.CRITICAL)

    def test_key_in_the_example_env_file_is_critical(self):
        self.write(".gitignore", ".env*\n")
        self.write(".env.example", "STRIPE_SECRET_KEY=%s\n" % LIVE_KEY)
        finding = self.finding("PAY005")
        self.assertEqual(finding.severity, sc.CRITICAL)
        self.assertIn("meant to be committed", finding.detail)

    def test_key_in_a_fixture_is_downgraded(self):
        self.write("tests/fixtures/keys.ts", 'const k = "%s";\n' % LIVE_KEY)
        self.assertEqual(self.finding("PAY005").severity, sc.REVIEW)

    def test_test_key_is_not_reported_as_a_leak(self):
        self.write("lib/billing.ts",
                   'import Stripe from "stripe";\nconst stripe = new Stripe("sk_test_51QxAbCdEfGh");\n')
        self.assertNotIn("PAY005", self.codes())

    def test_test_key_in_production_env_is_flagged(self):
        self.write(".env.production", "STRIPE_SECRET_KEY=sk_test_51QxAbCdEfGhIjKl\n")
        self.assertEqual(self.finding("PAY006").severity, sc.HIGH)

    def test_test_key_in_local_env_is_not_flagged(self):
        self.write(".env.local", "STRIPE_SECRET_KEY=sk_test_51QxAbCdEfGhIjKl\n")
        self.assertNotIn("PAY006", self.codes())

    def test_public_prefixed_secret_is_critical(self):
        self.write("app/checkout/page.tsx",
                   "const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n")
        self.assertEqual(self.finding("PAY007").severity, sc.CRITICAL)

    def test_public_publishable_key_is_correct_and_silent(self):
        self.write("app/checkout/page.tsx",
                   "const key = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;\n")
        self.assertNotIn("PAY007", self.codes())

    def test_secret_key_in_a_client_component_is_critical(self):
        self.write("components/Buy.tsx", """'use client';
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export default function Buy() { return <button>Buy</button>; }
""")
        self.assertEqual(self.finding("PAY007").severity, sc.CRITICAL)

    def test_public_secret_in_a_test_file_is_downgraded(self):
        """A test that asserts on the bad name has to contain the bad name.

        Found by running this scanner against its own repository, where it
        reported its own test suite as two critical leaks.
        """
        self.write("tests/test_keys.py",
                   'text = "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;"\n')
        self.assertEqual(self.finding("PAY007").severity, sc.REVIEW)

    def test_one_pay007_per_file_at_most(self):
        self.write("components/Buy.tsx", """'use client';
const a = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
const b = process.env.STRIPE_SECRET_KEY;
export default function Buy() { return null; }
""")
        self.assertEqual([c for c in self.codes() if c == "PAY007"], ["PAY007"])

    def test_secret_key_in_a_server_file_is_silent(self):
        self.write("lib/stripe.ts",
                   'import Stripe from "stripe";\n'
                   "export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\n")
        self.assertNotIn("PAY007", self.codes())


class TestCustomerControlledAmounts(ProjectCase):

    def test_amount_read_off_the_request_is_flagged(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const body = await req.json();
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { currency: "usd", unit_amount: body.amount }, quantity: 1 }],
  });
  return Response.json({ url: session.url });
}
""")
        finding = self.finding("PAY008")
        self.assertEqual(finding.severity, sc.HIGH)
        self.assertEqual(finding.confidence, sc.FACT)

    def test_destructured_amount_is_flagged(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const { amount, productId } = await req.json();
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { unit_amount: amount }, quantity: 1 }],
  });
  return Response.json({ url: session.url });
}
""")
        self.assertIn("PAY008", self.codes())

    def test_renamed_destructured_amount_is_flagged(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const { total: cents } = await req.json();
  const session = await stripe.paymentIntents.create({ amount: cents, currency: "inr" });
  return Response.json({ id: session.id });
}
""")
        self.assertIn("PAY008", self.codes())

    def test_amount_from_a_database_lookup_is_silent(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const { productId } = await req.json();
  const product = await db.products.find(productId);
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { unit_amount: product.price_cents }, quantity: 1 }],
  });
  return Response.json({ url: session.url });
}
""")
        self.assertNotIn("PAY008", self.codes())

    def test_literal_amount_is_silent(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST() {
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { unit_amount: 14900 }, quantity: 1 }],
  });
  return Response.json({ url: session.url });
}
""")
        self.assertNotIn("PAY008", self.codes())

    def test_client_supplied_price_id_is_not_an_amount(self):
        """A Price ID from the client can only name a price you created.

        `unit_amount` lets the caller pick the number; `price` does not. The
        reference implementation passes a client-chosen price ID, so flagging
        this would report the canonical correct pattern as a defect.
        """
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const { priceId } = await req.json();
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: priceId, quantity: 1 }],
  });
  return Response.json({ url: session.url });
}
""")
        self.assertNotIn("PAY008", self.codes())

    def test_amount_in_a_params_object_passed_to_create(self):
        """Real integrations build the params object separately."""
        self.write("utils/stripe/server.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function checkout(request) {
  const body = await request.json();
  const params = {
    line_items: [{ price_data: { currency: "usd", unit_amount: body.amount }, quantity: 1 }],
    mode: "payment",
  };
  return await stripe.checkout.sessions.create(params);
}
""")
        self.assertIn("PAY008", self.codes())


class TestClientSideCheckout(ProjectCase):

    def test_session_created_in_a_client_component(self):
        self.write("components/Buy.tsx", """'use client';
import Stripe from "stripe";
const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY);
export default function Buy() {
  const go = async () => {
    const session = await stripe.checkout.sessions.create({ line_items: [] });
  };
  return <button onClick={go}>Buy</button>;
}
""")
        self.assertEqual(self.finding("PAY009").severity, sc.HIGH)

    def test_redirect_to_checkout_from_the_client_is_fine(self):
        """The published pattern: client redirects, server created the session."""
        self.write("components/Buy.tsx", """'use client';
import { loadStripe } from "@stripe/stripe-js";
const stripe = await loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);
export default function Buy() {
  const go = async () => {
    const res = await fetch("/api/checkout", { method: "POST" });
    const { url } = await res.json();
    window.location.href = url;
  };
  return <button onClick={go}>Buy</button>;
}
""")
        self.assertEqual(self.codes(), [])


class TestFulfilment(ProjectCase):

    def test_write_on_the_success_page_is_flagged(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.write("app/checkout/success/page.tsx", """
import Stripe from "stripe";
export default async function Success({ searchParams }) {
  await db.from("orders").update({ status: "paid" }).eq("id", searchParams.session_id);
  return <p>Thank you</p>;
}
""")
        finding = self.finding("PAY010")
        self.assertEqual(finding.severity, sc.MEDIUM)
        self.assertEqual(finding.confidence, sc.HEURISTIC)

    def test_success_page_that_only_reads_is_silent(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.write("app/checkout/success/page.tsx", """
import Stripe from "stripe";
export default async function Success({ searchParams }) {
  const order = await db.from("orders").select("*").eq("id", searchParams.session_id).single();
  return <p>Thank you, order {order.id}</p>;
}
""")
        self.assertEqual(self.codes(), [])

    def test_checkout_with_no_completion_handler_anywhere(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST() {
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: "price_1Qabcdef", quantity: 1 }],
  });
  return Response.json({ url: session.url });
}
""")
        self.assertEqual(self.finding("PAY011").severity, sc.MEDIUM)

    def test_completion_handled_elsewhere_clears_it(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST() {
  const session = await stripe.checkout.sessions.create({ line_items: [] });
  return Response.json({ url: session.url });
}
""")
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        self.assertNotIn("PAY011", self.codes())

    def test_no_checkout_means_no_completion_finding(self):
        self.write("lib/stripe.ts",
                   'import Stripe from "stripe";\nexport const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\n')
        self.assertNotIn("PAY011", self.codes())


class TestWalkAndHygiene(ProjectCase):

    def test_node_modules_is_skipped(self):
        self.write("node_modules/stripe/index.js", 'const k = "%s";\n' % LIVE_KEY)
        self.assertEqual(self.codes(), [])

    def test_agent_worktrees_are_skipped(self):
        """Otherwise the same handler is reported once per worktree."""
        self.write(".claude/worktrees/a/app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
export async function POST(req) { const e = await req.json(); return new Response("ok"); }
""")
        self.assertEqual(self.codes(), [])

    def test_line_numbers_survive_comment_blanking(self):
        self.write("app/api/checkout/route.ts", """/*
 * A long block comment that must not shift any line numbers.
 * It runs across several lines on purpose.
 */
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST(req) {
  const { amount } = await req.json();
  const s = await stripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: amount } }] });
  return Response.json({ url: s.url });
}
""")
        self.assertEqual(self.finding("PAY008").line, 9)

    def test_commented_out_code_does_not_trigger_a_finding(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK + """
// const event = await req.json();
// await db.from("credits").insert({ amount: 100 });
""")
        self.assertEqual(self.codes(), [])


class TestCli(ProjectCase):

    def run_cli(self, *args):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = sc.main(["--path", self.root] + list(args))
        return code, buffer.getvalue()

    def test_clean_project_exits_zero_under_strict(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        code, out = self.run_cli("--strict")
        self.assertEqual(code, 0)
        self.assertIn("No payment defects found", out)

    def test_critical_finding_fails_strict(self):
        self.write("lib/billing.ts", 'import Stripe from "stripe";\nconst s = new Stripe("%s");\n' % LIVE_KEY)
        code, _ = self.run_cli("--strict")
        self.assertEqual(code, 1)

    def test_review_only_finding_passes_strict(self):
        """A heuristic must never break someone's build."""
        self.write(".gitignore", ".env*\n")
        self.write(".env.local", "STRIPE_SECRET_KEY=%s\n" % LIVE_KEY)
        code, _ = self.run_cli("--strict")
        self.assertEqual(code, 0)

    def test_without_strict_findings_still_exit_zero(self):
        self.write("lib/billing.ts", 'import Stripe from "stripe";\nconst s = new Stripe("%s");\n' % LIVE_KEY)
        code, _ = self.run_cli()
        self.assertEqual(code, 0)

    def test_json_output_is_parseable_and_shaped(self):
        self.write("app/api/webhooks/stripe/route.ts", """
import Stripe from "stripe";
export async function POST(req) { const e = await req.json(); return new Response("ok"); }
""")
        _, out = self.run_cli("--json")
        payload = json.loads(out)
        self.assertIn("findings", payload)
        self.assertIn("counts", payload)
        self.assertEqual(payload["findings"][0]["code"], "PAY001")
        self.assertIn("file", payload["findings"][0])
        self.assertIn("line", payload["findings"][0])

    def test_missing_directory_does_not_crash(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = sc.main(["--path", os.path.join(self.root, "nope"), "--strict"])
        self.assertEqual(code, 0)
        self.assertIn("no such directory", buffer.getvalue())

    def test_report_always_states_its_limits(self):
        self.write("app/api/webhooks/stripe/route.ts", GOOD_WEBHOOK)
        _, out = self.run_cli()
        self.assertIn("What this cannot tell you", out)

    def test_project_without_stripe_says_so(self):
        self.write("app/page.tsx", "export default function P() { return null; }")
        _, out = self.run_cli()
        self.assertIn("No Stripe integration found", out)

    def test_heuristic_findings_are_labelled_in_the_report(self):
        self.write("app/api/checkout/route.ts", """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export async function POST() {
  const s = await stripe.checkout.sessions.create({ line_items: [] });
  return Response.json({ url: s.url });
}
""")
        _, out = self.run_cli()
        self.assertIn("pattern-matched, not proven", out)


if __name__ == "__main__":
    unittest.main()
