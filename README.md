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
/plugin install rls-audit@claudeskill
```

Then ask Claude: *"is this app safe to launch?"*

## Install

### Claude Code (CLI)

```
/plugin marketplace add claudeskill-co/skills
/plugin install unit-economics@claudeskill
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
| [rls-audit](plugins/rls-audit) | Tables with row level security off, policies that let everyone through, keys the browser can read, paywalls enforced only in client code | CLI |
| [secret-sweep](plugins/secret-sweep) | Credentials in source, in browser-exposed variables, in Docker and CI, and in git history after you deleted them | CLI |
| [db-guard](plugins/db-guard) | **Blocks** DROP, TRUNCATE and WHERE-less DELETE against anything that is not clearly a local database — before the command runs | CLI |

More landing here: `stripe-check`, `deploy-check`, and `ship-check` to run the
lot as one gate.

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

`registry.json` is the machine-readable version of that table, and the website
renders from it.

## What these will not do

`rls-audit` reads migration files. If you built your schema by clicking around
the Supabase dashboard, it has checked almost nothing, and it tells you so
rather than returning a clean result you would have believed.

Static analysis sees one moment in time. It cannot tell you whether a key that
leaked has already been used, or whether any of it is still true after your
next deploy.

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
