---
name: db-guard
description: Block destructive database commands before they run - DROP, TRUNCATE, unqualified DELETE or UPDATE, and resets like supabase db reset or prisma migrate reset - whenever they are aimed at anything that is not clearly a local development database. Use when the user asks to protect their database, mentions dropping or truncating tables, resetting or wiping a database, running a migration against production, is worried an agent will delete their data, or asks what db-guard blocked and why.
---

# Database guard

This is the only skill in the suite that stops something happening rather than
reporting on it. It installs a `PreToolUse` hook, so it runs before every Bash
command — including the ones you are about to run yourself.

The case it exists for is documented: in July 2025 an agent dropped a
production database during an explicit code freeze, then reported that rollback
was impossible. It was wrong about that too. Nothing in a prompt prevents this.
A hook does.

## How it decides

Two questions, in order:

1. **Would this destroy data that cannot be recovered?**
2. **Is it pointed at something that is not clearly a local database?**

| Situation | Outcome |
|---|---|
| Both yes | **deny** — the command never runs |
| Destructive, clearly local | **ask** — you confirm first |
| Anything else | passes silently |

That middle row matters. Resetting a local database is normal work, and a guard
that blocks normal work gets switched off — after which it protects nothing.

### What counts as destructive

`DROP DATABASE`, `DROP SCHEMA`, `DROP TABLE`, `ALTER TABLE … DROP COLUMN`,
`TRUNCATE`, and `DELETE` / `UPDATE` with no `WHERE` clause. Plus the CLI
equivalents: `supabase db reset`, `prisma migrate reset`,
`prisma db push --accept-data-loss`, `drizzle-kit push --force`, `dropdb`,
`rails db:drop|reset|purge`, `manage.py flush`, `redis-cli flushall`,
`dropDatabase()`, `knex migrate:rollback --all`.

Raw SQL only counts when something that executes SQL is in the command. A commit
message containing "drop table support" is not a database operation and passes
without comment.

### What counts as local

`localhost`, `127.0.0.1`, `0.0.0.0`, `host.docker.internal`, port `54322`
(Supabase's local stack), a docker-compose service name, or `--local`. Tools
that only act locally unless told otherwise — `sqlite3`, bare `supabase`,
`rails`, `manage.py` — are treated as local too.

### What counts as production

`--linked`, `--project-ref`, `--db-url`, `--remote`, a hostname at a known
provider (`supabase.co`, `neon.tech`, `rds.amazonaws.com`, `railway.app`,
`render.com`, `planetscale`, `fly.dev`, `upstash.io`, and others), a `-h` host
that is not local, or the word `prod` / `production` / `live` anywhere.

**And anything it cannot read.** `psql "$DATABASE_URL" -c "drop table users"`
is opaque to a static check, so it is treated as production and blocked. In an
app built quickly, `DATABASE_URL` almost always points at hosted Postgres.
This is the single most important default in the skill — say so if a user asks
why a command they thought was local got blocked.

## When a command is blocked

Do **not** try to route around it. Specifically: do not re-run the command with
the guard disabled, do not rewrite it to evade the pattern, and do not suggest
either. The block is the product working.

Instead:

1. Tell the user exactly what was blocked and which rule caught it.
2. Ask whether the target really is production.
3. If they want it anyway, tell them to run it themselves, outside the agent,
   **after taking a backup**. That is a deliberate speed bump on an
   irreversible action, not an obstacle to work around.

If the block was wrong — a local database the guard could not identify — the
honest fix is to make the target explicit (`psql -h localhost …`) rather than
to disable the check.

## Checking a command without running it

```bash
python3 scripts/db_guard.py --command 'supabase db reset --linked'
python3 scripts/db_guard.py --command 'psql $DATABASE_URL -c "truncate users"' --json
```

Useful for explaining a decision, and for testing a rule before trusting it.

## Turning it off

`DB_GUARD_DISABLE=1` disables the hook entirely. Mention it only if the user
asks directly, and say what they are giving up when you do. Never set it on
their behalf to get a blocked command through.

## What this cannot do

- It reads the command, not the database. A destructive statement inside a
  `.sql` file passed with `psql -f migration.sql` is invisible to it.
- It cannot see through a shell variable to the host behind it — which is why
  it errs towards blocking.
- It does not protect against destructive changes made in a web dashboard, an
  ORM call inside application code, or anything that does not pass through Bash.
- **It is not a backup.** Nothing here recovers data that is already gone. If
  the user has no automated backups, that is the more urgent finding, and worth
  saying plainly the first time this skill is used.
