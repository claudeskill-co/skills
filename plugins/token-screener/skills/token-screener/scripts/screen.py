#!/usr/bin/env python3
"""
Token Screener - where your Claude Code tokens actually go.

Reads local Claude Code transcripts (~/.claude/projects/**/*.jsonl), attributes
every token to a task, a tool, a model and a session, prices it, and reports
where the spend is avoidable.

Read-only. No network. Python 3 stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------- tunables --

THRESHOLDS = {
    # A session whose cache-read share exceeds this is paying the
    # long-conversation tax: every turn re-reads the whole history.
    "cache_read_share": 0.70,
    # Only flag long sessions above this many assistant turns.
    "long_session_turns": 25,
    # A single tool result bigger than this lands in context forever.
    "big_result_bytes": 50_000,
    # Cache-write to cache-read ratio above this means the prefix keeps
    # getting invalidated - context is churning instead of being reused.
    "churn_ratio": 1.0,
    # A task that reads at least this many files and edits none was research.
    "explore_files": 6,
    # A task with this many search calls in the main thread should have been
    # delegated to a subagent.
    "search_calls": 8,
    # Ignore findings whose estimated saving is below this many USD.
    "min_finding_usd": 0.02,
    # Chars per token for sizing tool results. Rough, and labelled as such.
    "chars_per_token": 4.0,
}

SEARCH_TOOLS = {"Grep", "Glob", "Bash"}
READ_TOOLS = {"Read", "NotebookRead"}
EDIT_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}

# ---------------------------------------------------------------- pricing --


class Pricing:
    def __init__(self, data: dict):
        self.as_of = data.get("as_of", "unknown")
        self.models = data.get("models", {})
        self.families = data.get("family_fallbacks", {})
        self.default = data.get("default_model", "claude-opus-5")
        self.read_mult = data.get("cache_read_multiplier", 0.10)
        self.write5m_mult = data.get("cache_write_5m_multiplier", 1.25)
        self.write1h_mult = data.get("cache_write_1h_multiplier", 2.0)
        self.unknown_models: set[str] = set()

    @classmethod
    def load(cls, path: Path) -> "Pricing":
        with open(path) as fh:
            return cls(json.load(fh))

    def rates(self, model: str) -> tuple[float, float]:
        """Return (input $/MTok, output $/MTok) for a model id."""
        if not model:
            model = self.default
        if model in self.models:
            r = self.models[model]
            return r["input"], r["output"]
        for family, r in self.families.items():
            if family in model:
                return r["input"], r["output"]
        if model != "<synthetic>":
            self.unknown_models.add(model)
        r = self.models.get(self.default, {"input": 5.0, "output": 25.0})
        return r["input"], r["output"]

    def cost(self, model: str, u: "Usage") -> "Cost":
        inp, out = self.rates(model)
        return Cost(
            input=u.input * inp / 1e6,
            output=u.output * out / 1e6,
            cache_write=(
                u.cache_write_5m * inp * self.write5m_mult / 1e6
                + u.cache_write_1h * inp * self.write1h_mult / 1e6
            ),
            cache_read=u.cache_read * inp * self.read_mult / 1e6,
        )

    def carry_rate(self, model: str, turns_remaining: int) -> float:
        """
        USD per token for putting one token into context at a point where
        `turns_remaining` further requests will re-read it.

        This is the number nobody sees: context is not paid once. It is paid
        on write, then again on every subsequent turn as a cache read.
        """
        inp, _ = self.rates(model)
        mult = self.write5m_mult + max(0, turns_remaining) * self.read_mult
        return inp * mult / 1e6


class Usage:
    __slots__ = ("input", "output", "cache_write_5m", "cache_write_1h", "cache_read")

    def __init__(self, input=0, output=0, cw5=0, cw1=0, cr=0):
        self.input = input
        self.output = output
        self.cache_write_5m = cw5
        self.cache_write_1h = cw1
        self.cache_read = cr

    @property
    def cache_write(self) -> int:
        return self.cache_write_5m + self.cache_write_1h

    @property
    def total(self) -> int:
        return self.input + self.output + self.cache_write + self.cache_read

    def add(self, o: "Usage") -> None:
        self.input += o.input
        self.output += o.output
        self.cache_write_5m += o.cache_write_5m
        self.cache_write_1h += o.cache_write_1h
        self.cache_read += o.cache_read

    @classmethod
    def from_raw(cls, u: dict) -> "Usage":
        cc = u.get("cache_creation") or {}
        cw5 = cc.get("ephemeral_5m_input_tokens")
        cw1 = cc.get("ephemeral_1h_input_tokens")
        if cw5 is None and cw1 is None:
            # Older transcripts have no TTL split. Attribute to 5m (the
            # cheaper multiplier) so we never overstate cost.
            cw5, cw1 = u.get("cache_creation_input_tokens", 0) or 0, 0
        return cls(
            input=u.get("input_tokens", 0) or 0,
            output=u.get("output_tokens", 0) or 0,
            cw5=cw5 or 0,
            cw1=cw1 or 0,
            cr=u.get("cache_read_input_tokens", 0) or 0,
        )


class Cost:
    __slots__ = ("input", "output", "cache_write", "cache_read")

    def __init__(self, input=0.0, output=0.0, cache_write=0.0, cache_read=0.0):
        self.input = input
        self.output = output
        self.cache_write = cache_write
        self.cache_read = cache_read

    @property
    def total(self) -> float:
        return self.input + self.output + self.cache_write + self.cache_read

    def add(self, o: "Cost") -> None:
        self.input += o.input
        self.output += o.output
        self.cache_write += o.cache_write
        self.cache_read += o.cache_read


# ------------------------------------------------------------- structures --


def _bucket():
    return {"usage": Usage(), "cost": Cost()}


class Task:
    def __init__(self, key, label, session, when):
        self.key = key
        self.label = label
        self.session = session
        self.when = when
        self.usage = Usage()
        self.cost = Cost()
        self.turns = 0
        self.tools = defaultdict(int)
        self.files_read = set()
        self.files_edited = set()
        self.models = set()
        self.efforts = set()
        self.sidechain_turns = 0


class Session:
    def __init__(self, sid, project, when):
        self.sid = sid
        self.project = project
        self.when = when
        self.usage = Usage()
        self.cost = Cost()
        self.turns = 0
        # Total assistant turns in the transcript, including any outside the
        # reporting window. Set as soon as the session is created so the
        # carrying-cost maths never silently falls back to a partial count.
        self.total_turns = 0
        self.model = ""
        self.tasks = 0
        # file_path -> [turn indices where it was read]
        self.reads = defaultdict(list)
        self.big_results = []  # (tool, bytes, turn_idx, detail)
        self.search_calls = 0
        # Per-session Read sizing. Using a global average here would charge a
        # session that only read small files the corpus-wide rate.
        self.read_bytes = 0
        self.read_calls = 0


class Analysis:
    def __init__(self, pricing: Pricing):
        self.pricing = pricing
        self.usage = Usage()
        self.cost = Cost()
        self.tasks: dict[str, Task] = {}
        self.sessions: dict[str, Session] = {}
        self.by_tool = defaultdict(lambda: {"calls": 0, "bytes": 0})
        self.by_model = defaultdict(_bucket)
        self.by_effort = defaultdict(_bucket)
        self.by_day = defaultdict(_bucket)
        self.main = _bucket()
        self.side = _bucket()
        self.files_scanned = 0
        self.lines_bad = 0
        self.first_ts = None
        self.last_ts = None
        self.findings = []
        self.projects = set()


# ----------------------------------------------------------------- reading --


def project_dir_for(cwd: str) -> str:
    """Claude Code mangles a cwd into a flat directory name."""
    return re.sub(r"[^A-Za-z0-9]", "-", cwd)


def find_project_dirs(root: Path, project: str | None, all_projects: bool) -> list[Path]:
    if not root.is_dir():
        return []
    dirs = sorted(p for p in root.iterdir() if p.is_dir())
    if all_projects:
        return dirs
    if project:
        want = project_dir_for(str(Path(project).expanduser().resolve()))
        exact = [d for d in dirs if d.name == want]
        if exact:
            return exact
        # Fall back to matching on the cwd recorded inside the transcripts,
        # in case the mangling rule differs across Claude Code versions.
        target = str(Path(project).expanduser().resolve())
        matched = [d for d in dirs if _dir_cwd(d) == target]
        return matched
    return []


def _dir_cwd(d: Path) -> str | None:
    """Read the cwd recorded inside a project's first transcript."""
    for f in sorted(d.glob("*.jsonl"))[:1]:
        try:
            with open(f, errors="replace") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if rec.get("cwd"):
                        return rec["cwd"]
        except OSError:
            return None
    return None


def parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def block_text_len(content) -> int:
    """Bytes a tool_result contributes to the context window."""
    if content is None:
        return 0
    if isinstance(content, str):
        return len(content)
    if isinstance(content, list):
        n = 0
        for b in content:
            if isinstance(b, str):
                n += len(b)
            elif isinstance(b, dict):
                if isinstance(b.get("text"), str):
                    n += len(b["text"])
                elif b.get("type") == "image":
                    src = b.get("source") or {}
                    n += len(src.get("data") or "")
        return n
    if isinstance(content, dict):
        return len(json.dumps(content))
    return 0


def first_line(text, limit=72) -> str:
    if not isinstance(text, str):
        return "(non-text prompt)"
    text = re.sub(r"<[^>]+>", " ", text)  # strip command/caveat wrappers
    text = " ".join(text.split())
    if not text:
        return "(empty prompt)"
    return text[:limit] + ("..." if len(text) > limit else "")


def user_prompt_text(content) -> str | None:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        for b in content:
            if isinstance(b, dict) and b.get("type") == "text":
                return b.get("text")
    return None


# ---------------------------------------------------------------- analysis --


def analyze(files, pricing, since=None, until=None, session_filter=None) -> Analysis:
    a = Analysis(pricing)

    for path in files:
        # A transcript is one session; process it in order so we can compute
        # turn positions (needed to price how long content sits in context).
        try:
            records = list(iter_records(path, a))
        except OSError:
            continue
        if not records:
            continue
        a.files_scanned += 1
        process_session(records, a, pricing, since, until, session_filter)

    finalize(a, pricing)
    return a


def iter_records(path: Path, a: Analysis):
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                a.lines_bad += 1
                continue


def process_session(records, a: Analysis, pricing: Pricing, since, until, session_filter):
    # First pass: how many assistant turns in this session, so we know how
    # many times content added at turn i will be re-read afterwards.
    assistant_idx = [i for i, r in enumerate(records) if r.get("type") == "assistant"]
    total_turns = len(assistant_idx)
    if total_turns == 0:
        return

    sid = None
    for r in records:
        sid = r.get("sessionId") or r.get("session_id")
        if sid:
            break
    if session_filter and sid and not sid.startswith(session_filter):
        return

    cwd = next((r.get("cwd") for r in records if r.get("cwd")), "")
    sess = None
    turn = 0
    cur_key = None
    cur_label = None
    pending_tools = {}  # tool_use_id -> (name, input)
    seen_task_keys = set()
    in_window = False

    for rec in records:
        rtype = rec.get("type")
        ts = parse_ts(rec.get("timestamp"))

        if rtype == "user":
            content = (rec.get("message") or {}).get("content")
            is_tool_result = False
            if isinstance(content, list):
                is_tool_result = any(
                    isinstance(b, dict) and b.get("type") == "tool_result" for b in content
                )

            if not is_tool_result and rec.get("promptId"):
                text = user_prompt_text(content)
                cur_key = f"{sid}:{rec['promptId']}"
                cur_label = first_line(text)

            if is_tool_result and sess is not None:
                for b in content:
                    if not (isinstance(b, dict) and b.get("type") == "tool_result"):
                        continue
                    name, tinput = pending_tools.pop(b.get("tool_use_id"), ("unknown", {}))
                    nbytes = block_text_len(b.get("content"))
                    a.by_tool[name]["calls"] += 1
                    a.by_tool[name]["bytes"] += nbytes
                    if name in READ_TOOLS:
                        sess.read_bytes += nbytes
                        sess.read_calls += 1
                    if nbytes >= THRESHOLDS["big_result_bytes"]:
                        sess.big_results.append(
                            (name, nbytes, turn, describe_call(name, tinput))
                        )
            continue

        if rtype != "assistant":
            continue

        msg = rec.get("message") or {}
        raw_usage = msg.get("usage")
        if not raw_usage:
            continue

        # Time window is decided by assistant turns (the billed events).
        if ts:
            if since and ts < since:
                continue
            if until and ts > until:
                continue
        if not in_window:
            in_window = True
            sess = a.sessions.get(sid)
            if sess is None:
                sess = Session(sid or path_stem_fallback(rec), cwd, ts)
                a.sessions[sess.sid] = sess
            # A session id can span transcript files; keep the largest count.
            sess.total_turns = max(sess.total_turns, total_turns)
            if cwd:
                a.projects.add(cwd)

        turn += 1
        u = Usage.from_raw(raw_usage)
        model = msg.get("model") or ""
        c = pricing.cost(model, u)
        effort = rec.get("effort") or "default"
        side = bool(rec.get("isSidechain"))

        a.usage.add(u)
        a.cost.add(c)
        a.by_model[model or "unknown"]["usage"].add(u)
        a.by_model[model or "unknown"]["cost"].add(c)
        a.by_effort[effort]["usage"].add(u)
        a.by_effort[effort]["cost"].add(c)
        tgt = a.side if side else a.main
        tgt["usage"].add(u)
        tgt["cost"].add(c)

        if ts:
            day = ts.date().isoformat()
            a.by_day[day]["usage"].add(u)
            a.by_day[day]["cost"].add(c)
            a.first_ts = ts if a.first_ts is None or ts < a.first_ts else a.first_ts
            a.last_ts = ts if a.last_ts is None or ts > a.last_ts else a.last_ts

        sess.usage.add(u)
        sess.cost.add(c)
        sess.turns += 1
        sess.model = sess.model or model

        key = cur_key or f"{sid}:untracked"
        task = a.tasks.get(key)
        if task is None:
            task = Task(key, cur_label or "(no prompt recorded)", sid, ts)
            a.tasks[key] = task
        if key not in seen_task_keys:
            seen_task_keys.add(key)
            sess.tasks += 1
        task.usage.add(u)
        task.cost.add(c)
        task.turns += 1
        task.models.add(model)
        task.efforts.add(effort)
        if side:
            task.sidechain_turns += 1

        for b in msg.get("content") or []:
            if not (isinstance(b, dict) and b.get("type") == "tool_use"):
                continue
            name = b.get("name") or "unknown"
            tinput = b.get("input") or {}
            pending_tools[b.get("id")] = (name, tinput)
            task.tools[name] += 1
            fp = tinput.get("file_path") or tinput.get("notebook_path")
            if name in READ_TOOLS and fp:
                task.files_read.add(fp)
                sess.reads[fp].append(turn)
            if name in EDIT_TOOLS and fp:
                task.files_edited.add(fp)
            if name in SEARCH_TOOLS and not side:
                sess.search_calls += 1

    if sess is not None:
        sess.total_turns = total_turns


def path_stem_fallback(rec) -> str:
    return rec.get("uuid", "unknown")[:8]


def describe_call(name, tinput) -> str:
    if not isinstance(tinput, dict):
        return name
    for k in ("file_path", "command", "pattern", "path", "url", "query"):
        v = tinput.get(k)
        if isinstance(v, str) and v.strip():
            v = " ".join(v.split())
            return v[:70] + ("..." if len(v) > 70 else "")
    return name


def finalize(a: Analysis, pricing: Pricing):
    # Attribution invariant: every billed token must land in exactly one task.
    task_total = Usage()
    for t in a.tasks.values():
        task_total.add(t.usage)
    if task_total.total != a.usage.total:
        print(
            f"WARNING: attribution drift - tasks sum to {task_total.total:,} tokens "
            f"but total is {a.usage.total:,}. Report may be incomplete.",
            file=sys.stderr,
        )
    a.findings = detect(a, pricing)


# --------------------------------------------------------------- redaction --


def _scrub(s: str) -> str:
    """Strip prompt text, paths, and vendor names out of a generated string."""
    s = re.sub(r'mcp__[\w.\-]+', "mcp tool", s)        # vendor + capability
    s = re.sub(r'"[^"]*"', '"[redacted]"', s)          # quoted prompt excerpts
    s = re.sub(r'\[[^\]]*/[^\]]*\]', "[path]", s)      # bracketed path details
    s = re.sub(r'(/[\w.\- ]+){2,}', "[path]", s)       # bare absolute paths
    # Bare filenames leak too: "SPUR-SETUP.md" names a vendor and
    # "jane-doe.png" names a person. Requires alphabetic extension so
    # numbers like 1.25x and $35.85 are untouched.
    s = re.sub(r'\b[\w\-]+\.[A-Za-z]{1,6}\b', "[file]", s)
    s = re.sub(r'\[[^\]]{40,}\]', "[redacted]", s)     # long free-text details
    return s


def apply_redaction(a: Analysis) -> None:
    """
    Replace every piece of user content in the report with a safe placeholder.

    The report is built from someone's private transcripts. Task labels are
    verbatim prompts and finding evidence carries file paths, so a report
    shared for support, a screenshot, or a bug attachment leaks both. This
    makes the numbers shareable while keeping the content local.
    """
    ranked = sorted(a.tasks.values(), key=lambda t: -t.cost.total)
    for i, t in enumerate(ranked, 1):
        t.label = f"task {i:03d}"
        t.files_read = {f"file-{n:03d}" for n in range(len(t.files_read))}
        t.files_edited = {f"file-{n:03d}" for n in range(len(t.files_edited))}
    for s in a.sessions.values():
        s.project = "[redacted]"
    for f in a.findings:
        f["title"] = _scrub(f["title"])
        f["evidence"] = _scrub(f["evidence"])

    # MCP tool names embed the server and capability - "mcp__acme__crm_lookup"
    # tells a reader which vendors the user integrates with. Built-in tool
    # names (Read, Bash, Edit) are part of Claude Code and reveal nothing.
    renamed, n = {}, 0
    for name, d in a.by_tool.items():
        if name.startswith("mcp__"):
            n += 1
            renamed[f"mcp tool {n:02d}"] = d
        else:
            renamed[name] = d
    a.by_tool.clear()
    a.by_tool.update(renamed)

    for t in a.tasks.values():
        tools = {(k if not k.startswith("mcp__") else "mcp tool"): v
                 for k, v in t.tools.items()}
        t.tools.clear()
        t.tools.update(tools)


# --------------------------------------------------------------- detectors --


def _finding(title, saving, evidence, fix, kind):
    return {
        "title": title,
        "saving_usd": max(0.0, saving),
        "evidence": evidence,
        "fix": fix,
        "kind": kind,
    }


def detect(a: Analysis, p: Pricing) -> list[dict]:
    out = []
    cpt = THRESHOLDS["chars_per_token"]

    # 1. Long sessions paying the re-read tax.
    for s in a.sessions.values():
        if s.turns < THRESHOLDS["long_session_turns"] or s.cost.total <= 0:
            continue
        share = s.cost.cache_read / s.cost.total
        if share < THRESHOLDS["cache_read_share"]:
            continue
        # Splitting a session in half roughly halves the re-read term. Claim a
        # conservative third of the cache-read spend.
        out.append(
            _finding(
                f"Session {s.sid[:8]} spent {share:.0%} of its cost re-reading its own history",
                s.cost.cache_read * 0.33,
                f"{s.turns} turns, {s.usage.cache_read:,} cache-read tokens "
                f"(${s.cost.cache_read:.2f} of ${s.cost.total:.2f} total)",
                "Run /clear between unrelated tasks, or /compact once a session passes "
                f"~{THRESHOLDS['long_session_turns']} turns. Cost of a long session grows "
                "with the square of its length.",
                "long-session",
            )
        )

    # 2. The same file read more than once in one session.
    for s in a.sessions.values():
        worst = [(fp, len(turns)) for fp, turns in s.reads.items() if len(turns) >= 2]
        if not worst:
            continue
        # Size the redundant reads from THIS session's own Read results. Using
        # the corpus-wide average would charge a session that only read small
        # files the rate of one that read huge ones.
        if s.read_calls:
            avg_tokens = (s.read_bytes / s.read_calls) / cpt
        else:
            continue  # no measured Read results in this session; do not guess
        dupes = sum(n - 1 for _, n in worst)
        rate = p.carry_rate(s.model, max(1, s.total_turns // 2))
        dup_usd = dupes * avg_tokens * rate
        if dup_usd < THRESHOLDS["min_finding_usd"]:
            continue
        worst.sort(key=lambda x: -x[1])
        sample = ", ".join(f"{Path(f).name} x{n}" for f, n in worst[:3])
        out.append(
            _finding(
                f"{dupes} redundant file re-reads in session {s.sid[:8]}",
                dup_usd,
                f"{sample} (~{avg_tokens:,.0f} tokens per read, re-read on every "
                "later turn once in context)",
                "The file contents are already in context from the first read. Re-reading "
                "adds a second copy that you then pay for on every subsequent turn.",
                "duplicate-reads",
            )
        )

    # 3. Oversized single tool results.
    big = []
    for s in a.sessions.values():
        remaining_base = s.total_turns
        for name, nbytes, turn, detail in s.big_results:
            tokens = nbytes / cpt
            remaining = max(0, remaining_base - turn)
            usd = tokens * p.carry_rate(s.model, remaining)
            big.append((usd, name, tokens, detail, s.sid, remaining))
    if big:
        big.sort(reverse=True, key=lambda x: x[0])
        total_usd = sum(b[0] for b in big)
        if total_usd >= THRESHOLDS["min_finding_usd"]:
            lines = "; ".join(
                f"{n} ~{tok:,.0f} tok (${usd:.2f}) [{d}]" for usd, n, tok, d, _, _ in big[:3]
            )
            out.append(
                _finding(
                    f"{len(big)} oversized tool results are sitting in context",
                    total_usd * 0.6,
                    f"{lines}"
                    + (f" and {len(big) - 3} more" if len(big) > 3 else ""),
                    "Bound the output at the source: limit/offset on Read, head/tail or a "
                    "grep filter on Bash, or delegate the search to a subagent so only the "
                    "conclusion lands in the main thread.",
                    "big-results",
                )
            )

    # 4. Cache churn - writing far more than reading.
    for s in a.sessions.values():
        if s.usage.cache_read == 0 or s.turns < 5:
            continue
        ratio = s.usage.cache_write / max(1, s.usage.cache_read)
        if ratio < THRESHOLDS["churn_ratio"]:
            continue
        if s.cost.cache_write < THRESHOLDS["min_finding_usd"]:
            continue
        out.append(
            _finding(
                f"Session {s.sid[:8]} keeps invalidating its prompt cache",
                s.cost.cache_write * 0.4,
                f"{s.usage.cache_write:,} tokens written to cache vs only "
                f"{s.usage.cache_read:,} read back (ratio {ratio:.1f}x)",
                "Cache writes cost 1.25-2x input rate and only pay off when re-read. A high "
                "write:read ratio means context is being rebuilt rather than reused - usually "
                "many short sessions, or content changing near the front of the prompt.",
                "cache-churn",
            )
        )

    # 5. Research tasks that should have been subagents.
    for t in a.tasks.values():
        if t.sidechain_turns:
            continue
        if len(t.files_read) < THRESHOLDS["explore_files"] or t.files_edited:
            continue
        if t.cost.total < THRESHOLDS["min_finding_usd"]:
            continue
        out.append(
            _finding(
                f"Read {len(t.files_read)} files, edited none: \"{t.label}\"",
                t.cost.total * 0.5,
                f"${t.cost.total:.2f} across {t.turns} turns; every file read stays in "
                "the main thread's context for the rest of the session",
                "Pure investigation belongs in a subagent - it reads whatever it needs in its "
                "own context and returns only the conclusion, so the main thread never pays "
                "to carry the file contents forward.",
                "explore-discard",
            )
        )

    # 6. Expensive model or effort on cheap work.
    for t in a.tasks.values():
        if t.cost.total < THRESHOLDS["min_finding_usd"] * 4:
            continue
        if t.usage.output > 1200 or t.turns > 4:
            continue
        # Session boot and one-line acknowledgements are not tasks anyone chose,
        # and their cost is an unavoidable first-turn cache write. Skip them.
        if t.usage.output < 200 and not t.tools:
            continue
        model = next(iter(t.models), "")
        inp, _ = p.rates(model)
        if inp < 5.0 and "xhigh" not in t.efforts and "max" not in t.efforts:
            continue
        cheaper = t.cost.total * (1 - 3.0 / max(inp, 3.0)) if inp > 3.0 else t.cost.total * 0.3
        out.append(
            _finding(
                f"Top-tier model on a {t.usage.output:,}-token answer: \"{t.label}\"",
                cheaper,
                f"${t.cost.total:.2f}, model {model or 'unknown'}, effort "
                f"{'/'.join(sorted(t.efforts))}, {t.turns} turn(s), "
                f"{t.usage.output:,} output tokens",
                "Short, well-scoped answers rarely need the top model or xhigh effort. "
                "Drop effort first (it is the bigger lever), then consider Sonnet for this "
                "class of task.",
                "model-mismatch",
            )
        )

    # 7. Searching in the main thread instead of delegating.
    for s in a.sessions.values():
        if s.search_calls < THRESHOLDS["search_calls"]:
            continue
        est = s.cost.total * 0.15
        if est < THRESHOLDS["min_finding_usd"]:
            continue
        out.append(
            _finding(
                f"{s.search_calls} search/shell calls ran in the main thread "
                f"(session {s.sid[:8]})",
                est,
                f"Grep/Glob/Bash output from all {s.search_calls} calls is now permanent "
                f"context for a {s.turns}-turn session",
                "Fan out noisy searching to a subagent and keep only its findings. Search "
                "output is the highest-volume, lowest-reuse content in most sessions.",
                "search-in-main",
            )
        )

    out = [f for f in out if f["saving_usd"] >= THRESHOLDS["min_finding_usd"]]
    out.sort(key=lambda f: -f["saving_usd"])
    # One finding per kind per report keeps this actionable rather than a wall.
    seen, deduped = set(), []
    for f in out:
        if f["kind"] in seen:
            continue
        seen.add(f["kind"])
        deduped.append(f)
    return deduped[:8]


# ---------------------------------------------------------------- renderer --


def fmt_tok(n) -> str:
    n = int(n)
    if n >= 1_000_000_000:
        return f"{n/1e9:.2f}B"
    if n >= 1_000_000:
        return f"{n/1e6:.2f}M"
    if n >= 1_000:
        return f"{n/1e3:.1f}k"
    return str(n)


def table(headers, rows, aligns=None) -> str:
    if not rows:
        return "  (nothing to show)\n"
    cols = len(headers)
    aligns = aligns or ["l"] * cols
    widths = [len(h) for h in headers]
    srows = [[str(c) for c in r] for r in rows]
    for r in srows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))

    def line(cells):
        parts = []
        for i, c in enumerate(cells):
            parts.append(c.rjust(widths[i]) if aligns[i] == "r" else c.ljust(widths[i]))
        return "  " + "  ".join(parts).rstrip()

    out = [line(headers), "  " + "  ".join("-" * w for w in widths)]
    out += [line(r) for r in srows]
    return "\n".join(out) + "\n"


def render_text(a: Analysis, args) -> str:
    p = a.pricing
    inr = args.inr_rate
    o = []
    W = 78

    def money(x):
        return f"${x:,.2f}"

    def both(x):
        return f"${x:,.2f} / Rs {x*inr:,.0f}"

    span = ""
    if a.first_ts and a.last_ts:
        days = max(1, (a.last_ts - a.first_ts).days + 1)
        span = f"{a.first_ts.date()} to {a.last_ts.date()} ({days} days)"
    else:
        days = 1

    o.append("=" * W)
    o.append("  TOKEN SCREENER")
    o.append("=" * W)

    if a.usage.total == 0:
        o.append("")
        o.append("  No transcript data matched. Try --all-projects, or widen --days.")
        o.append("")
        return "\n".join(o)

    if args.redact:
        scope = "[redacted]"
    else:
        scope = "all projects" if args.all_projects else (args.project or os.getcwd())
    o.append("")
    o.append(f"  Scope     {scope}")
    o.append(f"  Window    {span}")
    o.append(f"  Data      {a.files_scanned} transcripts, {len(a.sessions)} sessions, "
             f"{len(a.tasks)} tasks")
    o.append("")

    # -- headline
    biggest = max(
        [
            ("re-reading conversation history", a.cost.cache_read),
            ("generating output", a.cost.output),
            ("writing new context to cache", a.cost.cache_write),
            ("uncached input", a.cost.input),
        ],
        key=lambda x: x[1],
    )
    o.append("-" * W)
    o.append("  HEADLINE")
    o.append("-" * W)
    o.append(f"  {fmt_tok(a.usage.total)} tokens   {both(a.cost.total)}   "
             f"~{both(a.cost.total/days)}/day")
    o.append(f"  Biggest line item: {biggest[0]} - {money(biggest[1])} "
             f"({biggest[1]/a.cost.total:.0%} of spend)")
    o.append("")

    # -- where it went
    o.append("-" * W)
    o.append("  WHERE IT WENT")
    o.append("-" * W)
    rows = []
    for label, tok, cst, note in [
        ("Cache read", a.usage.cache_read, a.cost.cache_read, "history re-sent each turn"),
        ("Cache write", a.usage.cache_write, a.cost.cache_write, "new context stored"),
        ("Output", a.usage.output, a.cost.output, "what Claude wrote"),
        ("Input", a.usage.input, a.cost.input, "uncached prompt"),
    ]:
        rows.append([label, fmt_tok(tok), money(cst),
                     f"{(cst/a.cost.total*100):.0f}%", note])
    o.append(table(["Bucket", "Tokens", "Cost", "Share", ""], rows,
                   ["l", "r", "r", "r", "l"]))
    if a.cost.cache_read / a.cost.total > 0.5:
        o.append("  Note: over half your spend is re-reading context you already paid to")
        o.append("  create. That is the cost of long sessions, not of doing more work.")
        o.append("")

    # -- by task
    o.append("-" * W)
    o.append("  BY TASK  (most expensive first)")
    o.append("-" * W)
    tasks = sorted(a.tasks.values(), key=lambda t: -t.cost.total)[: args.top]
    rows = []
    for t in tasks:
        rows.append([
            money(t.cost.total),
            fmt_tok(t.usage.output),
            fmt_tok(t.usage.cache_read),
            str(t.turns),
            str(sum(t.tools.values())),
            t.label,
        ])
    o.append(table(["Cost", "Output", "Re-read", "Turns", "Tools", "Task"], rows,
                   ["r", "r", "r", "r", "r", "l"]))

    # -- by tool
    o.append("-" * W)
    o.append("  BY TOOL  (context added by tool results, est. from bytes)")
    o.append("-" * W)
    tools = sorted(a.by_tool.items(), key=lambda kv: -kv[1]["bytes"])[: args.top]
    rows = []
    cpt = THRESHOLDS["chars_per_token"]
    for name, d in tools:
        est = d["bytes"] / cpt
        avg = est / max(1, d["calls"])
        rows.append([name, str(d["calls"]), fmt_tok(est), fmt_tok(avg)])
    o.append(table(["Tool", "Calls", "Est. tokens", "Avg/call"], rows,
                   ["l", "r", "r", "r"]))

    # -- by model / effort
    o.append("-" * W)
    o.append("  BY MODEL AND EFFORT")
    o.append("-" * W)
    rows = []
    for m, d in sorted(a.by_model.items(), key=lambda kv: -kv[1]["cost"].total):
        rows.append([m or "unknown", fmt_tok(d["usage"].total), money(d["cost"].total),
                     f"{d['cost'].total/a.cost.total*100:.0f}%"])
    o.append(table(["Model", "Tokens", "Cost", "Share"], rows, ["l", "r", "r", "r"]))
    rows = []
    for e, d in sorted(a.by_effort.items(), key=lambda kv: -kv[1]["cost"].total):
        rows.append([e, fmt_tok(d["usage"].total), money(d["cost"].total),
                     f"{d['cost'].total/a.cost.total*100:.0f}%"])
    o.append(table(["Effort", "Tokens", "Cost", "Share"], rows, ["l", "r", "r", "r"]))

    # -- main vs subagent
    o.append("-" * W)
    o.append("  MAIN THREAD VS SUBAGENTS")
    o.append("-" * W)
    rows = [
        ["Main thread", fmt_tok(a.main["usage"].total), money(a.main["cost"].total),
         f"{a.main['cost'].total/a.cost.total*100:.0f}%"],
        ["Subagents", fmt_tok(a.side["usage"].total), money(a.side["cost"].total),
         f"{a.side['cost'].total/a.cost.total*100:.0f}%"],
    ]
    o.append(table(["Where", "Tokens", "Cost", "Share"], rows, ["l", "r", "r", "r"]))
    if a.side["cost"].total / a.cost.total < 0.05:
        o.append("  Subagents are under 5% of spend. Work they do stays out of your main")
        o.append("  context - the cheapest place to put noisy searching and file reading.")
        o.append("")

    # -- findings
    o.append("=" * W)
    o.append("  WHERE TO OPTIMIZE")
    o.append("=" * W)
    if not a.findings:
        o.append("")
        o.append("  Nothing worth flagging in this window. Spend looks proportionate.")
        o.append("")
    else:
        total_save = sum(f["saving_usd"] for f in a.findings)
        o.append("")
        o.append(f"  {len(a.findings)} findings, ~{both(total_save)} of estimated avoidable "
                 f"spend ({total_save/a.cost.total:.0%})")
        o.append("")
        for i, f in enumerate(a.findings, 1):
            o.append(f"  {i}. {f['title']}")
            o.append(f"     Est. saving  ~{both(f['saving_usd'])}")
            for j, ln in enumerate(wrap(f["evidence"], W - 22)):
                o.append(f"     {'Evidence     ' if j == 0 else '             '}{ln}")
            for j, ln in enumerate(wrap(f["fix"], W - 22)):
                o.append(f"     {'Fix          ' if j == 0 else '             '}{ln}")
            o.append("")

    # -- footer
    o.append("-" * W)
    notes = [f"Pricing as of {p.as_of}. Estimates, not an invoice - "
             "subscription plans are not metered this way."]
    if p.unknown_models:
        notes.append("Unknown model ids priced at Opus rates: "
                     + ", ".join(sorted(p.unknown_models)))
    if a.lines_bad:
        notes.append(f"{a.lines_bad} unparseable transcript lines skipped.")
    notes.append("Tool token counts estimated at "
                 f"{THRESHOLDS['chars_per_token']:.0f} chars/token.")
    for n in notes:
        for ln in wrap(n, W - 4):
            o.append(f"  {ln}")
    o.append("")
    return "\n".join(o)


def wrap(text, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width and cur:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines or [""]


# -------------------------------------------------------------------- html --

HTML_CSS = """
:root{--bg:#fbfaf8;--fg:#1c1a17;--mut:#6b6560;--line:#e2ddd6;--card:#fff;
--a:#b4531f;--b:#2f6f6a;--c:#7a5ea8;--d:#9a7d29;--warn:#8a3a1e}
@media (prefers-color-scheme:dark){:root{--bg:#14130f;--fg:#eae6df;--mut:#9a938a;
--line:#2c2924;--card:#1c1a16;--a:#e08a4e;--b:#5fb3ab;--c:#a98fd8;--d:#d4b455;--warn:#e08a4e}}
:root[data-theme="dark"]{--bg:#14130f;--fg:#eae6df;--mut:#9a938a;--line:#2c2924;
--card:#1c1a16;--a:#e08a4e;--b:#5fb3ab;--c:#a98fd8;--d:#d4b455;--warn:#e08a4e}
:root[data-theme="light"]{--bg:#fbfaf8;--fg:#1c1a17;--mut:#6b6560;--line:#e2ddd6;
--card:#fff;--a:#b4531f;--b:#2f6f6a;--c:#7a5ea8;--d:#9a7d29;--warn:#8a3a1e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 ui-sans-serif,
-apple-system,"Segoe UI",Roboto,sans-serif;overflow-x:hidden}
.wrap{max-width:960px;margin:0 auto;padding:40px 20px 80px}
h1{font-size:1.05rem;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);
font-weight:600;margin:0 0 6px}
h2{font-size:.78rem;letter-spacing:.13em;text-transform:uppercase;color:var(--mut);
font-weight:600;margin:44px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.big{font-size:2.6rem;line-height:1.1;font-weight:650;letter-spacing:-.02em;margin:14px 0 2px}
.sub{color:var(--mut);font-size:.92rem}
.meta{color:var(--mut);font-size:.85rem;margin-bottom:26px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .k{font-size:.72rem;letter-spacing:.1em;text-transform:uppercase;color:var(--mut)}
.card .v{font-size:1.5rem;font-weight:620;margin-top:4px;letter-spacing:-.01em}
.card .n{font-size:.8rem;color:var(--mut);margin-top:2px}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:.88rem;min-width:520px}
th{text-align:left;font-weight:600;font-size:.72rem;letter-spacing:.09em;
text-transform:uppercase;color:var(--mut);padding:8px 12px 8px 0;border-bottom:1px solid var(--line)}
td{padding:9px 12px 9px 0;border-bottom:1px solid var(--line);vertical-align:top}
td.r,th.r{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tr:last-child td{border-bottom:none}
.bar{height:8px;border-radius:4px;background:var(--a);display:block}
.trunc{max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.find{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--warn);
border-radius:8px;padding:14px 16px;margin-bottom:12px}
.find .t{font-weight:620;margin-bottom:6px}
.find .s{color:var(--warn);font-size:.85rem;font-weight:600;margin-bottom:8px}
.find .e{font-size:.86rem;color:var(--mut);margin-bottom:8px}
.find .f{font-size:.9rem}
.callout{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:12px 16px;font-size:.9rem;color:var(--mut);margin-top:12px}
footer{margin-top:52px;padding-top:16px;border-top:1px solid var(--line);
font-size:.8rem;color:var(--mut)}
svg{max-width:100%;height:auto;display:block}
"""


def esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def bar_row(label, value, maxv, color="var(--a)") -> str:
    pct = (value / maxv * 100) if maxv else 0
    return (f'<span class="bar" style="width:{pct:.1f}%;background:{color};'
            f'min-width:2px"></span>')


def render_html(a: Analysis, args) -> str:
    inr = args.inr_rate
    cpt = THRESHOLDS["chars_per_token"]

    def money(x):
        return f"${x:,.2f}"

    days = 1
    span = "-"
    if a.first_ts and a.last_ts:
        days = max(1, (a.last_ts - a.first_ts).days + 1)
        span = f"{a.first_ts.date()} &rarr; {a.last_ts.date()}"

    h = ['<div class="wrap">']
    h.append("<h1>Token Screener</h1>")

    if a.usage.total == 0:
        h.append('<p class="sub">No transcript data matched this window.</p></div>')
        return page(h)

    if args.redact:
        scope = "[redacted]"
    else:
        scope = "All projects" if args.all_projects else (args.project or os.getcwd())
    h.append(f'<div class="big">{money(a.cost.total)}'
             f'<span class="sub" style="font-size:1rem"> &middot; Rs {a.cost.total*inr:,.0f}'
             f'</span></div>')
    h.append(f'<div class="sub">{fmt_tok(a.usage.total)} tokens across '
             f'{len(a.sessions)} sessions &middot; ~{money(a.cost.total/days)}/day</div>')
    h.append(f'<div class="meta">{esc(scope)} &middot; {span} &middot; '
             f'{a.files_scanned} transcripts &middot; {len(a.tasks)} tasks</div>')

    # cards
    buckets = [
        ("Cache read", a.usage.cache_read, a.cost.cache_read, "history re-sent each turn"),
        ("Cache write", a.usage.cache_write, a.cost.cache_write, "new context stored"),
        ("Output", a.usage.output, a.cost.output, "what Claude wrote"),
        ("Input", a.usage.input, a.cost.input, "uncached prompt"),
    ]
    h.append("<h2>Where it went</h2><div class='grid'>")
    for label, tok, cst, note in buckets:
        h.append(f'<div class="card"><div class="k">{label}</div>'
                 f'<div class="v">{money(cst)}</div>'
                 f'<div class="n">{fmt_tok(tok)} tok &middot; '
                 f'{cst/a.cost.total*100:.0f}% &middot; {note}</div></div>')
    h.append("</div>")
    if a.cost.cache_read / a.cost.total > 0.5:
        h.append('<div class="callout">Over half of this spend is re-reading context you '
                 'already paid to create - the cost of long sessions, not of more work.</div>')

    # daily chart
    if len(a.by_day) > 1:
        h.append("<h2>Daily spend</h2>")
        h.append(sparkline(a))

    # by task
    h.append("<h2>By task</h2><div class='scroll'><table>")
    h.append("<tr><th>Task</th><th class='r'>Cost</th><th class='r'>Output</th>"
             "<th class='r'>Re-read</th><th class='r'>Turns</th><th>Share</th></tr>")
    tasks = sorted(a.tasks.values(), key=lambda t: -t.cost.total)[: args.top]
    mx = tasks[0].cost.total if tasks else 1
    for t in tasks:
        h.append(f"<tr><td class='trunc'>{esc(t.label)}</td>"
                 f"<td class='r'>{money(t.cost.total)}</td>"
                 f"<td class='r'>{fmt_tok(t.usage.output)}</td>"
                 f"<td class='r'>{fmt_tok(t.usage.cache_read)}</td>"
                 f"<td class='r'>{t.turns}</td>"
                 f"<td style='min-width:90px'>{bar_row(t.label, t.cost.total, mx)}</td></tr>")
    h.append("</table></div>")

    # by tool
    h.append("<h2>By tool <span class='sub'>(context added by results, estimated)</span></h2>")
    h.append("<div class='scroll'><table>")
    h.append("<tr><th>Tool</th><th class='r'>Calls</th><th class='r'>Est. tokens</th>"
             "<th class='r'>Avg/call</th><th>Share</th></tr>")
    tools = sorted(a.by_tool.items(), key=lambda kv: -kv[1]["bytes"])[: args.top]
    mxb = tools[0][1]["bytes"] if tools else 1
    for name, d in tools:
        est = d["bytes"] / cpt
        h.append(f"<tr><td>{esc(name)}</td><td class='r'>{d['calls']}</td>"
                 f"<td class='r'>{fmt_tok(est)}</td>"
                 f"<td class='r'>{fmt_tok(est/max(1,d['calls']))}</td>"
                 f"<td style='min-width:90px'>"
                 f"{bar_row(name, d['bytes'], mxb, 'var(--b)')}</td></tr>")
    h.append("</table></div>")

    # model / effort / sidechain
    h.append("<h2>Model, effort, and thread</h2><div class='scroll'><table>")
    h.append("<tr><th>Slice</th><th class='r'>Tokens</th><th class='r'>Cost</th>"
             "<th class='r'>Share</th></tr>")
    for m, d in sorted(a.by_model.items(), key=lambda kv: -kv[1]["cost"].total):
        h.append(f"<tr><td>{esc(m or 'unknown')}</td>"
                 f"<td class='r'>{fmt_tok(d['usage'].total)}</td>"
                 f"<td class='r'>{money(d['cost'].total)}</td>"
                 f"<td class='r'>{d['cost'].total/a.cost.total*100:.0f}%</td></tr>")
    for e, d in sorted(a.by_effort.items(), key=lambda kv: -kv[1]["cost"].total):
        h.append(f"<tr><td>effort: {esc(e)}</td>"
                 f"<td class='r'>{fmt_tok(d['usage'].total)}</td>"
                 f"<td class='r'>{money(d['cost'].total)}</td>"
                 f"<td class='r'>{d['cost'].total/a.cost.total*100:.0f}%</td></tr>")
    for label, d in [("main thread", a.main), ("subagents", a.side)]:
        h.append(f"<tr><td>{label}</td>"
                 f"<td class='r'>{fmt_tok(d['usage'].total)}</td>"
                 f"<td class='r'>{money(d['cost'].total)}</td>"
                 f"<td class='r'>{d['cost'].total/a.cost.total*100:.0f}%</td></tr>")
    h.append("</table></div>")

    # findings
    h.append("<h2>Where to optimize</h2>")
    if not a.findings:
        h.append('<div class="callout">Nothing worth flagging. Spend looks '
                 'proportionate to the work.</div>')
    else:
        tot = sum(f["saving_usd"] for f in a.findings)
        h.append(f'<div class="sub" style="margin-bottom:14px">{len(a.findings)} findings '
                 f'&middot; ~{money(tot)} / Rs {tot*inr:,.0f} estimated avoidable '
                 f'({tot/a.cost.total:.0%} of spend)</div>')
        for f in a.findings:
            h.append('<div class="find">'
                     f'<div class="t">{esc(f["title"])}</div>'
                     f'<div class="s">Est. saving ~{money(f["saving_usd"])} / '
                     f'Rs {f["saving_usd"]*inr:,.0f}</div>'
                     f'<div class="e">{esc(f["evidence"])}</div>'
                     f'<div class="f">{esc(f["fix"])}</div></div>')

    notes = [f"Pricing as of {a.pricing.as_of}. Estimates, not an invoice - "
             "subscription plans are not metered per token.",
             f"Tool token counts estimated at {cpt:.0f} chars/token."]
    if a.pricing.unknown_models:
        notes.append("Unknown model ids priced at Opus rates: "
                     + ", ".join(sorted(a.pricing.unknown_models)))
    if a.lines_bad:
        notes.append(f"{a.lines_bad} unparseable transcript lines skipped.")
    h.append("<footer>" + "<br>".join(esc(n) for n in notes) + "</footer>")
    h.append("</div>")
    return page(h)


def sparkline(a: Analysis) -> str:
    days = sorted(a.by_day.items())
    vals = [d["cost"].total for _, d in days]
    mx = max(vals) or 1
    w, hgt, pad = 900, 130, 4
    bw = max(2, (w - pad * (len(vals) - 1)) / len(vals))
    bars = []
    for i, v in enumerate(vals):
        bh = max(1, v / mx * (hgt - 22))
        x = i * (bw + pad)
        bars.append(f'<rect x="{x:.1f}" y="{hgt-18-bh:.1f}" width="{bw:.1f}" '
                    f'height="{bh:.1f}" rx="2" fill="var(--a)"><title>'
                    f'{days[i][0]}: ${v:.2f}</title></rect>')
    labels = ""
    if days:
        labels = (f'<text x="0" y="{hgt-4}" font-size="11" fill="var(--mut)">'
                  f'{days[0][0]}</text>'
                  f'<text x="{w}" y="{hgt-4}" font-size="11" fill="var(--mut)" '
                  f'text-anchor="end">{days[-1][0]}</text>')
    return (f'<svg viewBox="0 0 {w} {hgt}" role="img" '
            f'aria-label="Daily spend">{"".join(bars)}{labels}</svg>'
            f'<div class="sub">Peak day ${mx:.2f}</div>')


def page(body) -> str:
    return (f"<title>Token Screener</title><style>{HTML_CSS}</style>" + "".join(body))


# -------------------------------------------------------------------- main --


def to_json(a: Analysis) -> dict:
    return {
        "totals": {
            "tokens": {
                "input": a.usage.input, "output": a.usage.output,
                "cache_write": a.usage.cache_write, "cache_read": a.usage.cache_read,
                "total": a.usage.total,
            },
            "cost_usd": {
                "input": round(a.cost.input, 4), "output": round(a.cost.output, 4),
                "cache_write": round(a.cost.cache_write, 4),
                "cache_read": round(a.cost.cache_read, 4),
                "total": round(a.cost.total, 4),
            },
        },
        "sessions": len(a.sessions),
        "tasks": [
            {"label": t.label, "cost_usd": round(t.cost.total, 4),
             "tokens": t.usage.total, "turns": t.turns,
             "output": t.usage.output, "cache_read": t.usage.cache_read}
            for t in sorted(a.tasks.values(), key=lambda t: -t.cost.total)
        ],
        "tools": {k: {"calls": v["calls"], "est_tokens":
                      round(v["bytes"] / THRESHOLDS["chars_per_token"])}
                  for k, v in a.by_tool.items()},
        "models": {k: round(v["cost"].total, 4) for k, v in a.by_model.items()},
        "by_day": {k: round(v["cost"].total, 4) for k, v in sorted(a.by_day.items())},
        "findings": a.findings,
        "pricing_as_of": a.pricing.as_of,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="screen.py",
        description="Where your Claude Code tokens actually go.",
    )
    ap.add_argument("--project", help="Project path (default: current directory)")
    ap.add_argument("--all-projects", action="store_true", help="Every project")
    ap.add_argument("--days", type=int, default=30, help="Look back N days (default 30)")
    ap.add_argument("--since", help="Start date YYYY-MM-DD (overrides --days)")
    ap.add_argument("--until", help="End date YYYY-MM-DD")
    ap.add_argument("--session", help="Restrict to one session id (prefix ok)")
    ap.add_argument("--top", type=int, default=10, help="Rows per section (default 10)")
    ap.add_argument("--html", metavar="FILE", help="Also write an HTML dashboard")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a report")
    ap.add_argument("--inr-rate", type=float, default=88.0, help="USD->INR (default 88)")
    ap.add_argument("--redact", action="store_true",
                    help="Replace prompt text and file paths with placeholders, "
                         "so the report is safe to share")
    ap.add_argument("--root", default=str(Path.home() / ".claude" / "projects"),
                    help="Transcript root")
    ap.add_argument("--pricing", help="Path to pricing.json")
    args = ap.parse_args(argv)

    pricing_path = Path(args.pricing) if args.pricing else (
        Path(__file__).resolve().parent.parent / "references" / "pricing.json")
    if not pricing_path.exists():
        print(f"error: pricing file not found: {pricing_path}", file=sys.stderr)
        return 2
    pricing = Pricing.load(pricing_path)

    since = until = None
    if args.since:
        since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc)
    elif args.days and args.days > 0:
        since = datetime.now(timezone.utc) - timedelta(days=args.days)
    if args.until:
        until = datetime.fromisoformat(args.until).replace(
            tzinfo=timezone.utc) + timedelta(days=1)
    if args.session:
        since = until = None  # a named session is always in scope

    root = Path(args.root).expanduser()
    project = args.project or os.getcwd()
    dirs = find_project_dirs(root, None if args.all_projects else project,
                             args.all_projects)
    if not dirs and not args.all_projects:
        print(f"No transcripts found for {project}.\n"
              f"Looked in {root}. Try --all-projects.", file=sys.stderr)
        return 1

    files = []
    for d in dirs:
        files.extend(sorted(d.glob("*.jsonl")))
    if args.session:
        narrowed = [f for f in files if f.stem.startswith(args.session)]
        files = narrowed or files

    a = analyze(files, pricing, since, until, args.session)
    if args.redact:
        apply_redaction(a)

    if args.json:
        print(json.dumps(to_json(a), indent=2))
        return 0

    print(render_text(a, args))

    if args.html:
        out = Path(args.html).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_html(a, args), encoding="utf-8")
        print(f"  HTML dashboard written to {out}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
