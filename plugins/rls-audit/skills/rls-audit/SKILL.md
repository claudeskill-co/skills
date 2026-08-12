---
name: rls-audit
description: Audit a Supabase or Postgres app for access-control holes before it ships - tables with row level security switched off, policies that let everyone through, service role keys reachable from the browser, and paywalls enforced only in client code. Use when the user asks whether their app is safe to launch, mentions RLS, row level security, Supabase policies, a security or pre-launch audit, a leaked or exposed API key, whether their paywall or auth can be bypassed, or says they are about to deploy or go live.
---

# RLS audit

Most apps that leak user data do not get hacked. They get *read* — by anyone who
opens devtools, copies the anon key that ships in every bundle, and queries the
database directly. Row level security is the only thing standing in the way, and
in a fast-built app it is usually the thing nobody switched on.

This finds the gaps that cost people their business, and refuses to invent the
rest.

## Run it first, read second

```bash
python3 scripts/rls_audit.py --path .
```

Point `--path` at the project root — the directory holding `supabase/`,
`app/` or `package.json`. It reads files, writes nothing, and never
touches the network. A large project takes well under a second.

Two other modes:

```bash
python3 scripts/rls_audit.py --path . --json     # for piping or storing
python3 scripts/rls_audit.py --path . --strict   # exit 1 on critical/high, for CI
```

`--strict` deliberately ignores `review` findings. A heuristic must never break
someone's build.

## What it checks

**In SQL migrations**

| Code | Finding |
|---|---|
| `RLS001` | A table in the `public` schema with RLS never enabled, or explicitly disabled |
| `RLS002` | RLS enabled but no policy — Postgres denies everything, usually a half-finished migration |
| `RLS003` | `for select ... using (true)` — everyone reads every row |
| `RLS004` | `using (true)` on a write command — everyone modifies every row |
| `RLS005` | `with check (true)` — a caller can write rows attributed to anyone |

Only the `public` schema is flagged, because only `public` is exposed through
the API. Tables dropped later in the migration history are not reported.

**In source and env files**

| Code | Finding |
|---|---|
| `KEY001` | A `service_role` JWT or `sb_secret_` key written into a file |
| `KEY002` | A secret held in a `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_` variable |
| `KEY003` | The service role key referenced inside a `'use client'` component |
| `GATE001` | An entitlement (`isPro`, `hasAccess`, `subscription_status`) decided in the browser |
| `API001` | A route handler using the service role with no visible auth check |

The anon key is **not** flagged. It is public by design, and flagging it would
teach the user to ignore this tool.

## How to report the results

Findings carry a confidence, and it changes what you should say.

- **`fact`** — follows from the file itself. State it plainly. `RLS001` on a
  table holding user data is not a suggestion; it means that data is readable
  by anyone right now.
- **`heuristic`** — a pattern that correct code can also match. `API001` fires
  when a route uses the service role and no auth call appears *in that file*.
  If the project authenticates in middleware, the finding is noise. Say so and
  move on rather than defending it.

Never restate a finding as worse than its severity. Never claim a vulnerability
you cannot point at with a file and a line.

Work in this order, because it is the order that matters:

1. **`KEY001` / `KEY002`** first. A leaked service key makes every other
   finding irrelevant — it bypasses all policies. Fix, then **tell the user to
   rotate the key**, because the old one is burned the moment it hit a file.
2. **`RLS001`** on anything holding user data, payment records or email
   addresses.
3. **`RLS004` / `RLS005`**, then `RLS003`.
4. **`GATE001` / `API001`** — confirm with the user before changing anything.

## Writing the fix

Turning RLS on with no policy locks the table completely, which breaks the app
in a way that looks like a different bug. Always enable *and* scope in the same
change:

```sql
alter table public.profiles enable row level security;

create policy "profiles are readable by their owner"
  on public.profiles for select
  to authenticated
  using (auth.uid() = id);

create policy "profiles are writable by their owner"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);
```

`using` controls which rows can be *seen*; `with check` controls which rows can
be *written*. An update policy needs both, or a user can edit their own row into
someone else's.

Before writing any policy, ask the user who is supposed to see the data. Do not
guess a predicate from a column name — `user_id` is the common case, not a rule.

## Say what this cannot see

Close every report with the limits, because a clean result is not the same as
being safe, and a user who thinks it is will get hurt:

- Tables created through the Supabase dashboard rather than a migration file are
  invisible to this. If the user built their schema by clicking, this tool has
  checked almost nothing — tell them directly and offer to dump the schema.
- Whether the policies that exist are the policies they *meant* is not
  statically knowable.
- Whether a key that leaked has already been used requires log access.
- Whether any of this is still true after the next deploy requires watching, not
  scanning.

Say that plainly. Overstating a clean result is the one failure this tool cannot
recover from.
