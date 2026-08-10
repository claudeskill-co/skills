---
name: token-screener
description: Analyze Claude Code token usage from local transcripts - total spend, which tasks and tools consumed it, and where it is avoidable. Use when the user asks about token usage, cost, or spend ("how many tokens am I using", "what am I spending", "token report", "why is this so expensive", "how do I use fewer tokens", "am I wasting tokens", "audit my usage"), or invokes /token-screener.
---

# Token Screener

Reads local Claude Code transcripts and reports where tokens went and which of
that spend was avoidable. Read-only, no network, python3 stdlib only.

## Run it

The script lives next to this file. From the user's project directory:

```bash
python3 <skill-dir>/scripts/screen.py
```

Default scope is the current project, last 30 days. Common variants:

| Goal | Command |
|---|---|
| This project, last 30 days | `screen.py` |
| Everything, all time | `screen.py --all-projects --days 3650` |
| One session | `screen.py --session <id-prefix>` |
| Last week only | `screen.py --days 7` |
| Visual dashboard | `screen.py --html report.html` |
| Machine-readable | `screen.py --json` |
| Safe to share (no prompts/paths) | `screen.py --redact` |
| Another project | `screen.py --project ~/code/thing` |

Other flags: `--since YYYY-MM-DD`, `--until`, `--top N` (rows per section,
default 10), `--inr-rate` (default 88), `--root` (transcript dir).

**If the report is going anywhere other than the user's own screen** — an issue,
a screenshot, a shared file — add `--redact`. Without it, task labels are the
user's verbatim prompts and some findings cite absolute file paths.

Report the headline number, the biggest line item, and the top two or three
findings in your own text. Do not paste the whole report back — the user can
see it. If they asked "how do I use fewer tokens", lead with the findings
section and skip the accounting tables.

## Reading the output

**Where it went** splits spend four ways. The one that surprises people is
**cache read**: every turn re-sends the whole conversation, so a long session
pays for its history again and again. It routinely dominates. High cache-read
share is a session-length problem, not a "doing more work" problem.

**Cache write** is new context entering the conversation — file reads, tool
output, your prompts. It is billed at 1.25x (5-minute TTL) or 2x (1-hour TTL)
the input rate, and then re-read on every later turn. That compounding is why
the script prices content by *when* it entered a session: a token added at turn
5 of a 50-turn session costs far more than the same token added at turn 49.

**By task** groups every turn under the user prompt that started it, so cost
maps to work rather than to messages.

**By tool** estimates how much context each tool's results added (bytes / 4,
labelled as an estimate). This answers "what is filling my context".

## When a finding needs explaining

`references/optimizations.md` has the full catalogue: what each detector looks
for, why it costs money, and the concrete fix. Read it only when the user asks
about a specific finding — the report itself already carries a one-line fix.

## Caveats to state honestly

- Costs are **estimates from published API rates**, not an invoice. On a Max or
  Pro subscription nothing is metered per token; the numbers show relative
  weight, not a bill.
- Tool-result token counts are approximated from bytes.
- Savings estimates are directional. They tell you which lever is biggest, not
  what you would have paid.
- Pricing is a static table with an `as_of` date printed in the footer. If it
  looks stale, update `references/pricing.json`.
