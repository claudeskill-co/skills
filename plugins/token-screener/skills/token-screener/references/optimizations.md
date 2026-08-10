# The detector catalogue

Every finding the screener emits comes from one of these. Each entry explains
what it looks for, why it costs money, and what to actually do.

Thresholds live in the `THRESHOLDS` dict at the top of `scripts/screen.py` —
edit there, not in the logic.

---

## The one idea behind all of them

Context is not paid for once. It is paid on write, then again on every
subsequent turn as a cache read.

A token entering the conversation at a point where `N` more turns will follow
costs roughly:

```
(1.25 + N x 0.10) x input_rate
```

So on Opus ($5/MTok input), a token added at turn 5 of a 50-turn session costs
about `(1.25 + 4.5) x $5 = $28.75/MTok` — nearly six times the sticker input
rate. The same token added on the last turn costs $6.25/MTok.

This is why "just read the file" and "just run the whole test suite" are not
free, and why the screener prices content by *when* it entered the session.

---

## 1. Long sessions re-reading their own history

**Looks for** a session past ~25 turns where cache reads are over 70% of its
cost.

**Why it costs** total cost grows with roughly the square of session length —
each turn re-sends everything before it. A 700-turn session can spend more
re-reading itself than on all its actual output combined.

**Fix** `/clear` between unrelated tasks. `/compact` when a single thread of
work genuinely needs to continue. Both reset the quadratic. The instinct to
keep one long session "so Claude remembers" is the single most expensive habit
in Claude Code.

---

## 2. Redundant file re-reads

**Looks for** the same `file_path` read two or more times in one session.

**Why it costs** the first read already put the file in context permanently.
The second read adds a *second copy*, and both copies are re-sent on every
later turn.

**Fix** nothing to configure — this is a behavioural note. If a file changed
and needs re-reading that is legitimate; if it was re-read because it scrolled
out of attention, the cost was avoidable. Frequent re-reads of the same file
are also a signal it belongs in `CLAUDE.md` instead.

---

## 3. Oversized tool results

**Looks for** any single tool result over 50,000 characters.

**Why it costs** one 200k-character file read is ~50k tokens that sit in
context for the rest of the session. At turn 10 of a 60-turn session that one
read costs more than most tasks.

**Fix** bound the output where it is produced:
- `Read` with `limit` / `offset` rather than whole files
- `Bash` piped through `head`, `tail`, `grep`, or `--quiet` flags
- redirect build and test logs to a file, then grep the file
- for anything exploratory, delegate to a subagent so only its conclusion
  lands in the main thread

---

## 4. Prompt-cache churn

**Looks for** a session writing more to cache than it reads back.

**Why it costs** cache writes are 1.25-2x the input rate and only pay off when
re-read. Writing without reading means paying the premium for nothing.

**Fix** usually means many short sessions rather than one flowing one, so no
prefix survives long enough to be reused. It can also mean something near the
front of the prompt changes every turn, invalidating everything after it. If
the work is genuinely a series of one-shot questions, this is fine and the
finding can be ignored.

---

## 5. Research that should have been a subagent

**Looks for** a task that read 6+ files and edited none.

**Why it costs** every file read in the main thread stays in the main thread's
context permanently, at the compounding rate above — even though the answer
you needed was one paragraph.

**Fix** delegate investigation. A subagent reads whatever it needs in its own
context, that context is discarded when it finishes, and only the findings come
back. The saving scales with how long the main session continues afterwards.

---

## 6. Top-tier model or effort on small work

**Looks for** short, few-turn tasks with tiny output running on an expensive
model or at `xhigh`/`max` effort.

**Why it costs** Opus is 5x Sonnet on input and Fable is 10x. Effort drives how
much thinking happens before the answer.

**Fix** drop effort first — it is the bigger lever and does not change model
quality, only depth. Then consider a smaller model for that class of task.
Session boot messages and one-line acknowledgements are excluded from this
detector because their cost is an unavoidable first-turn cache write.

---

## 7. Searching in the main thread

**Looks for** 8+ `Grep`/`Glob`/`Bash` calls in the main thread on one session.

**Why it costs** search output is the highest-volume, lowest-reuse content in a
session. You need it for one turn; you pay for it for every remaining turn.

**Fix** fan the sweep out to a subagent and keep only what it found. This is
the same fix as #5 from a different angle — and together they are usually the
largest single lever available.

---

## Habits that follow from all of this

1. `/clear` between unrelated tasks. Not optional at scale.
2. Delegate noisy reading and searching. Keep conclusions, not transcripts.
3. Bound tool output at the source rather than after the fact.
4. Tune effort before tuning model.
5. Put durable project facts in `CLAUDE.md` so they are cached once rather than
   re-discovered every session.
