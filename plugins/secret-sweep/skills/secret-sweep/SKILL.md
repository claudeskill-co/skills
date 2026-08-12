---
name: secret-sweep
description: Find credentials your project is leaking - API keys and tokens written into source, secrets in browser-exposed variables, env files tracked by git or sitting in its history, and keys baked into Dockerfiles or CI workflows. Use when the user asks whether they have leaked a key, mentions exposed or committed secrets, .env in git, a compromised or rotated API key, an unexpected bill on an API account, or wants a pre-launch check before making a repository public or shipping.
---

# Secret sweep

A leaked key does not announce itself. It shows up as a bill, or as somebody
else's traffic on your account. This finds the credentials that are reachable
by someone who should not have them — and, just as importantly, stays quiet
about the ones that are exactly where they belong.

## Run it first, read second

```bash
python3 scripts/secret_sweep.py --path .
```

```bash
python3 scripts/secret_sweep.py --path . --json           # for piping or storing
python3 scripts/secret_sweep.py --path . --strict          # exit 1 on critical/high
python3 scripts/secret_sweep.py --path . --include-tests   # stop excusing fixtures
```

It reads files and runs `git log`. It writes nothing and never sends anything
anywhere. **Secrets are never printed in full** — findings show a masked prefix,
because a report that quotes the key is one more place the key exists.

## What it looks for

**Recognisable credentials** (`SEC001`–`SEC016`) — Stripe live and webhook
secrets, OpenAI, Anthropic, AWS, Google, GitHub, Slack, SendGrid, Twilio,
Razorpay, Supabase secret keys, private key blocks, and database URLs with an
inline password. A Stripe *test* key is reported at medium, not critical,
because telling someone their test key leaked is how you get uninstalled.

**Browser exposure** (`SEC021`, `SEC022`) — a secret in a `NEXT_PUBLIC_` /
`VITE_` / `EXPO_PUBLIC_` variable, or a server secret read from a `'use client'`
component. Only counted when the name is genuinely used as an environment
variable, not when an identifier merely looks like one.

**Build configuration** (`SEC030`, `SEC031`) — secrets baked into a Dockerfile
layer or written literally into a CI workflow.

**Git exposure** (`SEC040`–`SEC042`) — an env file tracked by git, one that
appears in history even though it is untracked now, or one that nothing in
`.gitignore` covers.

**Anything credential-shaped** (`SEC020`) — a dense value assigned to a
secret-looking name that matched no known provider. Heuristic by construction.

## Two things it deliberately does not report

**Keys in a properly ignored env file.** If `.env` is in `.gitignore` and git
has never seen it, the credentials inside are in the correct place. The report
counts them and says so rather than listing them as findings. Treating that as
a leak trains people to ignore the tool.

**Fixtures.** Findings in `tests/`, `__tests__/`, `*.spec.ts`, `fixtures/` and
friends are downgraded to `review`, because synthetic credentials live there by
design. They are still shown. `--include-tests` restores full severity when the
user genuinely wants to audit test data.

## How to report the results

Order matters more here than anywhere else in the suite, because the clock is
running on anything that has already been exposed.

1. **`SEC040` / `SEC041` first.** A committed env file means every credential it
   held is public to anyone with a clone. **Tell the user to rotate every value
   in it**, and be explicit that deleting the file does not remove it from
   history — a fork or clone made yesterday still has it.
2. **Live provider keys in source** (`SEC001`, `SEC006`, `SEC012`, `SEC016`…).
   Move to the environment, then rotate. The `fix` field names where to rotate
   for each provider — use it, do not generalise.
3. **`SEC021` / `SEC022`.** These are already in the bundle every visitor
   downloads. Same rule: fix, then rotate.
4. **`SEC030` / `SEC031`.** An image layer keeps a secret even if a later layer
   deletes it.
5. **`SEC020`** last, and only after the user confirms it is real.

**Rotation is not optional and not a follow-up task.** A key that has sat on
disk or in a repository is burned whether or not anyone can prove it was read.
Say that plainly rather than softening it — and never tell a user they are
"probably fine" because the repository is private. Repositories change
visibility, and forks do not.

When a finding is `heuristic`, say so. If the user tells you `SEC020` is a
fixture or a fake, accept it and move on rather than defending the finding.

## Say what this cannot see

Close every report with the limits:

- Whether a leaked key has **already been used** needs the provider's logs, not
  a file scan. If anything critical turns up, tell the user to check billing and
  access logs on that provider before assuming no harm was done.
- Secrets already set in a deployed environment — Vercel, Railway, Fly, a server
  — are invisible here.
- A credential shape it does not recognise will sit in plain sight, unreported.
- None of this stays true after the next commit.

A clean sweep means nothing was found in the files on disk today. It does not
mean nothing has leaked.
