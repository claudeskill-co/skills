---
name: ship-check
description: Run the whole Ship-Safe suite and grade whether a project is safe to launch - access control, secrets, payments and deploy readiness in one report with one verdict. Use when the user asks whether their app is ready, safe to launch, safe to deploy or safe to go live, wants a security or pre-launch audit, says they are shipping today, or asks for a full check rather than one specific thing.
---

# Ship check

One question, one answer: **is this safe to launch?**

This runs the four Ship-Safe scanners, merges what they find, removes the
duplicates that come from two tools noticing the same line, and grades the
result. It is the front door to the suite — reach for it when the user asks a
whole-project question, and reach for an individual skill when they ask a
specific one.

## Run it first, read second

```bash
python3 scripts/ship_check.py --path .
```

Point `--path` at the project root. It reads files, writes nothing, and never
touches the network.

```bash
python3 scripts/ship_check.py --path . --all       # include review-level findings
python3 scripts/ship_check.py --path . --json      # for piping or storing
python3 scripts/ship_check.py --path . --strict    # exit 1 when BLOCKED or RISKY
python3 scripts/ship_check.py --path . --require-full-coverage   # exit 1 if a scanner is missing
python3 scripts/ship_check.py --path . --scanners ~/plugins   # if siblings are elsewhere
```

## The verdict

| Verdict | Means |
|---|---|
| `BLOCKED` | A **proven** critical finding. Exploitable by someone who has done nothing but open the site |
| `RISKY` | A proven high, or an unproven critical/high. Deployable, with known holes |
| `INCOMPLETE` | Not every scanner ran. Nothing blocking was found in what *was* checked |
| `CLEAR` | Every scanner ran and found nothing proven above medium |

Two rules make the verdict worth trusting, and you should repeat both to the
user rather than paraphrasing them away:

- **A scanner that is not installed did not pass — it did not run.** Missing
  coverage can never be graded `CLEAR`, and the report names exactly what went
  unchecked. `--strict` fails on *findings*; `--require-full-coverage` fails on
  *missing scanners*. They are separate flags because they are separate
  failures — a CI job should not go red for a security reason it did not find.
- **A heuristic never blocks.** Only `fact`-confidence findings can produce
  `BLOCKED`. Pattern matches raise the verdict to `RISKY` and say so. Being
  loudly wrong is how a pre-flight check stops being run at all.

`CLEAR` does not mean safe. It means four scanners found nothing proven. Say
that in those words.

## What runs

| Scanner | Covers |
|---|---|
| `rls-audit` | Access control — RLS gaps, permissive policies, keys the browser can read |
| `secret-sweep` | Secrets — credentials in source, in the bundle, in git history |
| `stripe-check` | Payments — unverified webhooks, customer-controlled amounts, key placement |
| `deploy-check` | Deploy readiness — env drift, shared databases, headers, limits |

**`db-guard` is not run**, and the report says so explicitly. It is a
PreToolUse hook that blocks destructive commands in real time — there is
nothing for it to report about a directory. The report can see whether the
plugin is on disk, but **not** whether it is enabled, so it says *found*, never
*protecting you*. If it is missing, say plainly that nothing is stopping a
destructive command.

Each scanner is an independent plugin. If one is not installed, install it:

```
/plugin install rls-audit@claudeskill
```

## How to report the results

Lead with the verdict and the coverage line, in that order. A user who reads
"CLEAR" without reading "3 of 4 scanners ran" has been actively misled, and
that is this tool's worst failure mode.

Then work the findings in the order printed — they are already sorted by
severity, and by design each place appears once. When a finding says *also
reported by*, that is two scanners agreeing, not two problems.

Then apply the individual skill's guidance for whichever codes came up; each
scanner's SKILL.md has the fix patterns and the ordering advice for its own
rules. Do not invent fixes here that contradict them.

Findings under `tests/`, `fixtures/`, `__mocks__/`, `testdata/`, `cypress/` and
`stories/` are downgraded to `review` by the scanners themselves, because a
deliberately broken sample is not a production defect. The coverage block says
how many were demoted and where — **read that line out to the user**, because a
`CLEAR` verdict that quietly demoted eight findings is the most misleading
output this tool can produce. If that is their real code, re-run the individual
scanner with `--include-tests`.

`demo/` and `examples/` are deliberately **not** downgraded. A directory called
`demo` in a real project is far more likely to be shipped code than a throwaway
fixture.

## Say what this cannot see

Close every report with the limits. A clean result is not the same as being
safe, and a user who believes it is will get hurt:

- It does not mean the app is safe. It means four scanners found nothing proven.
- None of this sees the hosting dashboard, where the real configuration lives.
- None of this knows whether the database has a backup anyone has restored.
- None of this is still true after the next deploy. **This is a snapshot.**

Say that plainly, every time. Overstating a clear result is the one failure
this suite cannot recover from.
