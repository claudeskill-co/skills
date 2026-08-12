---
name: deploy-check
description: Find the gap between what runs locally and what will run in production - environment variables that exist only on this machine, development pointed at the live database, type errors waved through at build time, missing security headers, no rate limiting and no health endpoint. Use when the user is about to deploy, launch or go live, asks whether their app is production-ready, mentions Vercel, Railway, Render or environment variables, or reports that something works locally but breaks in production.
---

# Deploy check

Nothing here is a vulnerability in the usual sense. These are the defects that
make a launch fail at the worst possible moment: a variable that exists only in
your shell, a staging site quietly writing to the live database, a build that
checked nothing, and no headers on anything.

The failure mode is specific and worth naming — **it all works on your machine**.
That is not evidence of anything, and this tool exists to say so.

## Run it first, read second

```bash
python3 scripts/deploy_check.py --path .
```

Point `--path` at the project root — the directory holding `package.json` or
`next.config`. It reads files, writes nothing, never touches the network, and
**never reads a value out of your environment** — only names from files.

Two other modes:

```bash
python3 scripts/deploy_check.py --path . --json     # for piping or storing
python3 scripts/deploy_check.py --path . --strict   # exit 1 on critical/high, for CI
```

`--strict` deliberately ignores `review` findings. A heuristic must never break
someone's build.

## What it checks

**Will it boot?**

| Code | Finding |
|---|---|
| `DEP001` | A variable the code reads that no env template documents |
| `DEP002` | Variables set locally, documented nowhere, and read nowhere visible |

Any env file whose name says *example*, *sample* or *template* counts as
documentation, and several are unioned — `.env.example` plus
`.env.local.example` is a normal split. Platform-provided names (`NODE_ENV`,
`PORT`, `VERCEL_URL`, and the `CLAUDE_*` variables handed to hook scripts) are
never reported.

**Is it pointed at the right database?**

| Code | Finding |
|---|---|
| `DEP003` | The same remote database URL in a development and a production env file |

Both pointing at `localhost` is not a finding — neither of those is production.

**Did the build check anything?**

| Code | Finding |
|---|---|
| `DEP004` | `ignoreBuildErrors` or `ignoreDuringBuilds` set to true |
| `DEP006` | Source maps published to production |
| `DEP008` | `output: 'export'` in a project that has server routes |

**Is anything in front of it?**

| Code | Finding |
|---|---|
| `DEP005` | No security headers in any config file or middleware |
| `DEP007` | `Access-Control-Allow-Origin: *`, and worse with credentials |
| `DEP009` | No rate limiter anywhere, with auth/upload/model routes present |
| `DEP010` | `NODE_ENV` not production, or a debug flag on, in a production env file |
| `DEP011` | No health endpoint |
| `DEP012` | An environment value written to the logs |

Absences are reported **once**, not once per file. Ten unprotected auth routes
are one problem, and listing them ten times is how a report gets skimmed past.

## How to report the results

Findings carry a confidence, and it changes what you should say.

- **`fact`** — follows from the file itself. `DEP003` means both environments
  resolve to the same host. `DEP010` means the value is written down. State
  these plainly.
- **`heuristic`** — a pattern correct code can also match. `DEP001` fires when a
  name is read in code and absent from the template; a project configured
  entirely through a hosting dashboard will light this up while being perfectly
  fine. `DEP002` is the weakest signal here — a library reading its own config
  counts as "read nowhere visible." Say so and move on rather than defending it.

Work in this order:

1. **`DEP003`** first, and stop to confirm it. Everything else is recoverable;
   a development script against the production database is not.
2. **`DEP010`**, then **`DEP001`** — the two ways a deploy comes up wrong.
3. **`DEP008`**, **`DEP004`** — the build lied to you.
4. **`DEP005`**, `DEP007`, `DEP009`, `DEP012`, `DEP011` — hardening, in that
   order.

Never restate a finding as worse than its severity. Never claim a defect you
cannot point at with a file and a line.

## Writing the fix

Headers first, because they cost nothing and break nothing:

```js
// next.config.mjs
const nextConfig = {
  async headers() {
    return [{
      source: "/(.*)",
      headers: [
        { key: "X-Frame-Options", value: "DENY" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
      ],
    }];
  },
};
export default nextConfig;
```

Add a Content-Security-Policy **after** these, and separately — a CSP written
in one pass usually breaks the app in a way that looks like a different bug.

For `DEP001`, do not paste the values into `.env.example`. It is a list of
names, and a value in it is a leak waiting for the first `git push`:

```bash
DATABASE_URL=
STRIPE_SECRET_KEY=
```

For `DEP003`, the fix is a second database, not more care. Ask the user before
changing any connection string — pointing development somewhere new can look
identical to data loss.

## Say what this cannot see

Close every report with the limits, because a clean result is not the same as
being ready, and a user who thinks it is will get hurt:

- **What is actually set in the hosting dashboard**, which is the real
  configuration. This reads files. A project can pass every check here and
  still be missing every variable in production — tell the user to open the
  dashboard and compare.
- Whether the database has backups, or whether anyone has ever restored one.
- Whether the app survives its first hundred concurrent users.
- Whether anything is watching while they sleep.

Say that plainly. Overstating a clean result is the one failure this tool cannot
recover from.
