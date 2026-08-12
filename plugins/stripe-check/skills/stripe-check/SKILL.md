---
name: stripe-check
description: Audit a Stripe integration for the defects that quietly cost money - webhooks that never verify a signature, charge amounts the customer controls, secret keys in the browser bundle, and fulfilment that depends on the buyer's tab staying open. Use when the user asks whether their payments are safe or set up correctly, mentions Stripe, checkout, webhooks, subscriptions, a signature verification error, double charges, orders that were paid but not fulfilled, or says they are about to take real payments or go live.
---

# Stripe check

A payments bug does not look like a crash. Checkout still works, the success
page still says thank you, and the loss arrives later as an order nobody
fulfilled, a customer charged twice, or a stranger who bought a $149 plan for
one rupee because the amount was in the request body.

This finds those, and refuses to invent the rest.

## Run it first, read second

```bash
python3 scripts/stripe_check.py --path .
```

Point `--path` at the project root — the directory holding `app/`, `pages/` or
`package.json`. It reads files, writes nothing, never touches the network, and
never calls the Stripe API. A large project takes well under a second.

Two other modes:

```bash
python3 scripts/stripe_check.py --path . --json     # for piping or storing
python3 scripts/stripe_check.py --path . --strict   # exit 1 on critical/high, for CI
```

`--strict` deliberately ignores `review` findings. A heuristic must never break
someone's build.

If the report says **"No Stripe integration found"**, stop and say so — do not
go hunting for payment code that is not there. The project may use Razorpay,
Polar, Paddle or Lemon Squeezy, none of which this checks.

## What it checks

**The webhook — where forged events get in**

| Code | Finding |
|---|---|
| `PAY001` | A handler that acts on events without calling `constructEvent` |
| `PAY002` | A signature verified against `req.json()` — the signed bytes are already gone |
| `PAY003` | The `whsec_` signing secret hardcoded in the file |
| `PAY004` | A grant written with no `event.id` and no conflict clause — a retry grants twice |
| `PAY012` | A `pages/api` webhook without `bodyParser: false` |

**The keys**

| Code | Finding |
|---|---|
| `PAY005` | A live `sk_live_` / `rk_live_` key written into a file |
| `PAY006` | A test key configured in `.env.production` |
| `PAY007` | A secret in a `NEXT_PUBLIC_` / `VITE_` variable, or read in a `'use client'` file |

**The money**

| Code | Finding |
|---|---|
| `PAY008` | `unit_amount` or `amount` set from the request body — the customer picks the price |
| `PAY009` | A checkout session created in client code |
| `PAY010` | The order fulfilled on the success page instead of the webhook |
| `PAY011` | Checkout is created but nothing in the project handles its completion |

The **publishable key is not flagged**. `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` is
public by design, and flagging it would teach the user to ignore this tool. Nor
is `sk_test_` in source treated as a leak — it buys nothing, and reporting it
buries the finding that matters.

`price: priceId` is **not** reported even when the ID comes from the client. A
Price ID can only name a price you already created; `unit_amount` lets the
caller choose the number. Only the second is a hole.

## How to report the results

Findings carry a confidence, and it changes what you should say.

- **`fact`** — follows from the file itself. `PAY001` means that endpoint will
  accept an event anyone can POST. State it plainly.
- **`heuristic`** — a pattern correct code can also match. `PAY004` fires when a
  verified handler writes without referencing `event.id`. If dedupe happens in a
  database constraint this cannot see, the finding is noise. Say so and move on
  rather than defending it.

Work in this order, because it is the order that matters:

1. **`PAY005` / `PAY007`** first. A leaked live key makes every other finding
   irrelevant — it is full account access. Fix, then **tell the user to roll the
   key**, because the old one is burned the moment it hit a file.
2. **`PAY001` / `PAY002`**. An unverified webhook is a free-money endpoint.
3. **`PAY008`**, then `PAY009`.
4. **`PAY004`**, `PAY010`, `PAY011` — confirm with the user before changing
   anything, since fulfilment logic often lives across several files.

Never restate a finding as worse than its severity. Never claim a vulnerability
you cannot point at with a file and a line.

## Writing the fix

The webhook is where most of these are fixed, and the order of the first three
lines is the whole point:

```ts
export async function POST(req: Request) {
  const raw = await req.text();                       // raw bytes, before anything parses them
  const sig = req.headers.get("stripe-signature")!;

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return new Response("bad signature", { status: 400 });   // never 500 - Stripe retries those
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    await db.from("grants").upsert(
      { event_id: event.id, user_id: session.metadata!.userId },
      { onConflict: "event_id" },                     // a retry now does nothing, twice
    );
  }
  return new Response("ok");                          // 2xx, or Stripe keeps redelivering
}
```

Three things to say out loud when writing this:

- **`req.text()` must come before anything else reads the body.** A body can
  only be consumed once, and `constructEvent` needs the exact bytes Stripe
  signed.
- **`event.id` with a unique constraint is the whole of idempotency.** Stripe
  guarantees at-least-once delivery, not exactly-once. Without it, one network
  blip is two shipments.
- **Return 2xx even when you ignore the event type.** A non-2xx tells Stripe to
  retry forever.

For `PAY008`, the fix is to stop sending a number at all — take a product ID,
look the price up server-side, or pass a Stripe Price ID and let Stripe hold the
amount. Do not sanitise the client's number; there is no safe version of it.

Before rewriting a fulfilment path, ask the user where they intend to grant
access. Do not guess it from a filename.

## Say what this cannot see

Close every report with the limits, because a clean result is not the same as
being safe, and a user who thinks it is will get hurt:

- Whether the webhook endpoint is **registered in the Stripe dashboard at all**.
  A perfect handler nobody points at is the most common silent failure here, and
  it is invisible to static analysis. Tell the user to check.
- Whether the prices in their database match the prices in Stripe.
- Whether refunds, disputes and failed payments are handled anywhere.
- Whether a key that leaked has already been used — that needs the Stripe logs.
- Anything about Razorpay, Polar, Paddle or Lemon Squeezy.

Say that plainly. Overstating a clean result is the one failure this tool cannot
recover from.
