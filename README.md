# ClaudeSkill

**Pre-flight checks for apps built fast.**

Shipping something you mostly prompted into existence? These find what will
break you before your users do — the table you forgot to lock, the key that
ended up in the browser bundle, the paywall that is only a conditional render.

Not a list of links to other people's repos. Every skill here is written,
tested in CI, and packaged so it installs on whichever Claude you actually use —
the CLI, the desktop app, or claude.ai in a browser.

The Ship-Safe suite is **MIT** and always free. Run it on anything, including
work you sell.

**[claudeskill.co](https://claudeskill.co)** — browse the catalogue.

```bash
/plugin marketplace add claudeskill-co/skills
/plugin install ship-check@claudeskill
```

Then ask Claude: *"is this app safe to launch?"* You get one answer and the
reasons behind it:

```
SHIP CHECK  ~/projects/my-app

BLOCKED   do not deploy this
  1 proven critical finding(s). Anything here is exploitable by someone who
  has done nothing more than open your site.

Coverage
  ran      rls-audit      access control       3 finding(s)
  ran      secret-sweep   secrets              1 finding(s)
  ran      stripe-check   payments             0 finding(s)
  ran      deploy-check   deploy readiness     4 finding(s)
  found    db-guard       destructive commands a hook, so nothing to scan

[CRITICAL] Table has no row level security  (rls-audit / RLS001)
  supabase/migrations/001_init.sql:4
  `public.profiles` is reachable with the anon key that ships in your bundle.
  Anyone can read every row.
```

Two rules make that verdict worth something:

- **A scanner that is not installed did not pass — it did not run.** Coverage is
  printed every time, and a partial run is never graded clear.
- **A guess never blocks.** Only findings that follow from the file itself can
  produce `BLOCKED`. Pattern matches say so, and are counted separately.

`CLEAR` does not mean safe. It means four scanners found nothing proven — and
the report says exactly that, in those words.

## Install

### Claude Code (CLI)

```
/plugin marketplace add claudeskill-co/skills
/plugin install ship-check@claudeskill

# ship-check runs whichever of these are present, and says which are not
/plugin install rls-audit@claudeskill
/plugin install secret-sweep@claudeskill
/plugin install stripe-check@claudeskill
/plugin install deploy-check@claudeskill
/plugin install db-guard@claudeskill
```

`/plugin marketplace update claudeskill` pulls new skills as they land.

### Claude Desktop app

1. Download the skill's `.zip` from [the latest release](https://github.com/claudeskill-co/skills/releases/latest)
   (or from its page on claudeskill.co)
2. Claude → **Customize** (bottom left) → **Skills** → **+** → **Upload a skill**
3. Pick the zip, then toggle the skill on

Requires code execution to be enabled in Settings → Capabilities.

### claude.ai (web)

Settings → **Capabilities** → **Skills** → upload the same `.zip`.
Available on Pro, Max, Team and Enterprise with code execution enabled.

> Skills do not sync between surfaces. A skill uploaded to claude.ai is not
> present in Claude Code or on the API — install it wherever you want it.

Some skills are CLI-only because they read files on your machine. Those ship no
zip, and their page says so rather than offering a download that would do nothing.

## The catalogue

### Ship-Safe — free, MIT

| Skill | What it does | Surfaces |
|---|---|---|
| [ship-check](plugins/ship-check) | Runs the four scanners below, merges them, and grades whether this is safe to launch. **Start here.** | CLI |
| [rls-audit](plugins/rls-audit) | Tables with row level security off, policies that let everyone through, keys the browser can read, paywalls enforced only in client code | CLI |
| [secret-sweep](plugins/secret-sweep) | Credentials in source, in browser-exposed variables, in Docker and CI, and in git history after you deleted them | CLI |
| [stripe-check](plugins/stripe-check) | Webhooks that never verify a signature, charge amounts the customer controls, keys in the browser bundle, fulfilment that depends on the buyer's tab staying open | CLI |
| [deploy-check](plugins/deploy-check) | Variables that exist only on your machine, development pointed at the live database, type errors waved through at build time, missing headers and limits | CLI |
| [db-guard](plugins/db-guard) | **Blocks** DROP, TRUNCATE and WHERE-less DELETE against anything that is not clearly a local database — before the command runs | CLI |

`db-guard` is the one that stops something rather than reporting it. It installs
a `PreToolUse` hook, so a destructive command aimed at production never
executes:

```
$ supabase db reset --linked
db-guard: deny (supabase-db-reset)
Blocked: this drops and recreates the whole database, against a production or
remote database. If that is genuinely what you want, run it yourself outside
the agent - and take a backup first.
```

Destructive but clearly local? It asks instead of blocking — resetting a dev
database is normal work, and a guard that blocks normal work gets switched off.

### Everything else

| Skill | What it does | Surfaces |
|---|---|---|
| [token-screener](plugins/token-screener) | Where your Claude spend went, and which of it was avoidable | CLI |
| [unit-economics](plugins/unit-economics) | What an order actually earns after GST, shipping, payment fees and COD returns | CLI, Desktop, web |

`registry.json` is the machine-readable version of both tables, and the website
renders from it. Every skill's row there is generated from the plugin tree, so
what this page claims and what Claude Code installs cannot drift apart.

## Why you would trust these

A scanner is only worth running if it is right about code it has never seen.
These are tested two ways, and **389 tests** run on every push across Python
3.9, 3.11 and 3.13.

**Against code known to be correct.** `vercel/nextjs-subscription-payments` is
the canonical Stripe + Supabase reference app. `stripe-check` finds nothing in
it, and correctly identifies its webhook as a webhook. Mutating that real repo
to drop `constructEvent`, and again to read `unit_amount` off the request body,
produces the right finding at the right line both times.

**Against our own work, which is where the interesting failures were.** Every
one of these was a false positive found by running the tools on real projects
rather than on fixtures, and each is now a regression test:

- Keys inside a properly gitignored `.env` reported as critical. That is where
  keys belong.
- Security *documentation* reported as a vulnerability, because it contained an
  example connection string under a "never hardcode credentials" heading.
- The Next.js reference app graded `BLOCKED` over `.env.local.example` — a file
  that is *meant* to be committed.
- Our own site graded `BLOCKED` over the deliberately vulnerable fixture it
  ships to demonstrate these tools.
- `rls-audit` flagging a health endpoint that reports
  `Boolean(process.env.SERVICE_ROLE_KEY)` — which is exactly what `deploy-check`
  tells you to do instead of logging the value. Our own two tools contradicted
  each other; a conformance suite now asserts they never can again.

We run the suite on `claudeskill.co` itself. `deploy-check` reported four things
about our own site, and all four are fixed.

## What these will not do

`rls-audit` reads migration files. If you built your schema by clicking around
the Supabase dashboard, it has checked almost nothing, and it tells you so
rather than returning a clean result you would have believed.

`deploy-check` cannot see your hosting dashboard, which is where the real
configuration lives. A project can pass every check here and still be missing
every variable in production.

`stripe-check` cannot tell whether your webhook is registered in the Stripe
dashboard at all — a perfect handler nobody points at is the most common silent
failure in payments, and it is invisible to static analysis.

Static analysis sees one moment in time. It cannot tell you whether a key that
leaked has already been used, or whether any of it is still true after your
next deploy.

Findings under `tests/`, `fixtures/` and `testdata/` are downgraded, because a
deliberately broken sample is not a production defect — and the report says how
many it demoted, so a clean result is never quietly bought. `demo/` and
`examples/` are **not** downgraded: a directory called `demo` in a real project
is more often shipped code than a throwaway.

## Get told when a skill lands

New skills, and the occasional writeup of a failure mode we found in the wild.
No more than one a month.

**[Sign up on claudeskill.co](https://claudeskill.co)** — one field, and the
form tells you honestly if it failed rather than thanking you and dropping the
address.

## Repository layout

```
.claude-plugin/marketplace.json   generated - what Claude Code reads
registry.json                     generated - what claudeskill.co reads
plugins/<slug>/
  .claude-plugin/plugin.json      plugin manifest
  catalog.json                    catalogue metadata (audience, surfaces, tier)
  skills/<name>/SKILL.md          the skill itself
  tests/                          whatever the skill needs to prove it works
scripts/
  validate-skills.mjs             frontmatter, naming and identity rules
  gen-registry.mjs                regenerates both catalogue files
  build-zips.mjs                  dist/<skill>.zip for the upload surfaces
```

## Adding a skill

```bash
mkdir -p plugins/my-skill/skills/my-skill
# write .claude-plugin/plugin.json, catalog.json and skills/my-skill/SKILL.md
node scripts/gen-registry.mjs      # regenerate the catalogue
node scripts/validate-skills.mjs   # check it before anyone else does
node scripts/build-zips.mjs        # package it
```

Two rules the validator enforces because Anthropic's loaders do:

- A skill `name` may not contain `claude` or `anthropic`, and must be
  lowercase-kebab, 64 characters or fewer.
- The `description` must say **what it does and when to use it** — that string
  is the only signal Claude has for deciding whether to trigger the skill.

Never hand-edit `marketplace.json` or `registry.json`; CI fails if they do not
match the plugin tree.

## Releasing

Tag `v*`. CI validates, tests, builds the zips and attaches them to the release,
which is where the site's download links point.

## Licence

The **Ship-Safe suite is MIT** — free for anything, including commercial work.
Each of those plugins carries its own `LICENSE`.

Everything else is Business Source License 1.1: source is public and free for
personal and internal commercial use; reselling it as a product or service
requires a licence. Converts to Apache 2.0 on 2030-08-10. See [LICENSE](LICENSE).

---

Not affiliated with, endorsed by, or sponsored by Anthropic. Claude and Claude
Code are trademarks of Anthropic, PBC.
