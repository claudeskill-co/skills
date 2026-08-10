#!/usr/bin/env python3
"""
Regression tests for the token screener.

Stdlib `unittest` only - no pytest, matching the tool's zero-dependency rule.

    python3 -m unittest discover -s tests -v

The accounting tests are the load-bearing ones. If the screener ever reports a
number that does not match the raw transcripts, it is worse than having no tool
at all, because it creates false confidence. Those invariants are locked here.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "token-screener" / "scripts"))

import screen  # noqa: E402

PRICING = screen.Pricing.load(
    ROOT / "skills" / "token-screener" / "references" / "pricing.json"
)


def usage(inp=0, out=0, cw5=0, cw1=0, cr=0):
    d = {
        "input_tokens": inp,
        "output_tokens": out,
        "cache_read_input_tokens": cr,
        "cache_creation_input_tokens": cw5 + cw1,
        "cache_creation": {
            "ephemeral_5m_input_tokens": cw5,
            "ephemeral_1h_input_tokens": cw1,
        },
    }
    return d


def transcript(records):
    """Write records to a temp project dir and return the root to scan."""
    tmp = tempfile.mkdtemp()
    proj = Path(tmp) / "-test-project"
    proj.mkdir()
    with open(proj / "s.jsonl", "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return Path(tmp)


def session(n_turns, model="claude-opus-5", sid="sess1", prompt="do the thing",
            per_turn=None, tools=None, ts="2026-08-08T10:00:00.000Z"):
    per_turn = per_turn or usage(inp=5, out=100, cw5=1000, cr=5000)
    recs = [{
        "type": "user", "promptId": "p1", "sessionId": sid, "cwd": "/proj",
        "timestamp": ts, "message": {"role": "user", "content": prompt},
    }]
    for _ in range(n_turns):
        content = [{"type": "text", "text": "ok"}]
        if tools:
            content += tools
        recs.append({
            "type": "assistant", "sessionId": sid, "cwd": "/proj", "timestamp": ts,
            "message": {"model": model, "content": content, "usage": per_turn},
        })
    return recs


def run(records, **kw):
    root = transcript(records)
    files = sorted((root / "-test-project").glob("*.jsonl"))
    return screen.analyze(files, PRICING, **kw)


# --------------------------------------------------------------- accounting --


class TestAccounting(unittest.TestCase):
    def test_totals_match_raw_sum(self):
        recs = session(4, per_turn=usage(inp=7, out=250, cw5=3000, cr=9000))
        a = run(recs)
        self.assertEqual(a.usage.input, 4 * 7)
        self.assertEqual(a.usage.output, 4 * 250)
        self.assertEqual(a.usage.cache_write, 4 * 3000)
        self.assertEqual(a.usage.cache_read, 4 * 9000)

    def test_attribution_invariant(self):
        """Every billed token must land in exactly one task."""
        recs = session(3) + session(2, sid="sess2", prompt="second thing")
        a = run(recs)
        per_task = sum(t.usage.total for t in a.tasks.values())
        self.assertEqual(per_task, a.usage.total)

    def test_cache_write_ttl_multipliers_differ(self):
        """1h cache writes cost 2.0x input; 5m cost 1.25x. Must not be blended."""
        a5 = run(session(1, per_turn=usage(cw5=1_000_000)))
        a1 = run(session(1, per_turn=usage(cw1=1_000_000)))
        self.assertAlmostEqual(a5.cost.cache_write, 5.0 * 1.25, places=6)
        self.assertAlmostEqual(a1.cost.cache_write, 5.0 * 2.00, places=6)

    def test_legacy_transcript_without_ttl_split(self):
        """Old transcripts lack cache_creation; must not overstate cost."""
        rec = {
            "type": "assistant", "sessionId": "s", "cwd": "/p",
            "timestamp": "2026-08-08T10:00:00.000Z",
            "message": {"model": "claude-opus-5", "content": [],
                        "usage": {"input_tokens": 0, "output_tokens": 0,
                                  "cache_creation_input_tokens": 1_000_000,
                                  "cache_read_input_tokens": 0}},
        }
        a = run([rec])
        self.assertAlmostEqual(a.cost.cache_write, 5.0 * 1.25, places=6)

    def test_model_rates_applied_per_model(self):
        opus = run(session(1, model="claude-opus-5", per_turn=usage(out=1_000_000)))
        haiku = run(session(1, model="claude-haiku-4-5", per_turn=usage(out=1_000_000)))
        self.assertAlmostEqual(opus.cost.output, 25.0, places=6)
        self.assertAlmostEqual(haiku.cost.output, 5.0, places=6)

    def test_unknown_model_flagged_not_silently_zeroed(self):
        a = run(session(1, model="claude-does-not-exist-9",
                        per_turn=usage(out=1_000_000)))
        self.assertGreater(a.cost.output, 0)
        self.assertIn("claude-does-not-exist-9", PRICING.unknown_models)

    def test_carry_rate_grows_with_remaining_turns(self):
        """The core insight: context added early costs more than added late."""
        early = PRICING.carry_rate("claude-opus-5", 45)
        late = PRICING.carry_rate("claude-opus-5", 0)
        self.assertGreater(early, late * 4)


# -------------------------------------------------------------- robustness --


class TestRobustness(unittest.TestCase):
    def test_malformed_lines_skipped_not_fatal(self):
        root = transcript(session(2))
        p = root / "-test-project" / "s.jsonl"
        with open(p, "a") as fh:
            fh.write('{"type":"assistant","message":{broken\n')
            fh.write("not json at all\n")
        a = screen.analyze(sorted((root / "-test-project").glob("*.jsonl")), PRICING)
        self.assertEqual(a.lines_bad, 2)
        self.assertGreater(a.usage.total, 0)

    def test_empty_corpus_does_not_crash(self):
        a = screen.analyze([], PRICING)
        self.assertEqual(a.usage.total, 0)
        self.assertEqual(a.findings, [])

    def test_assistant_messages_carry_no_promptid(self):
        """
        Guards the subtlest bug in the tool: assistant lines have no promptId,
        so attribution must carry the last-seen user promptId forward. A naive
        group-by silently drops nearly all usage.
        """
        # Two prompts in ONE session. If the carry-forward is broken, every
        # assistant turn falls into a single "untracked" bucket and the split
        # is lost - which a single-task fixture would not reveal.
        recs = session(2, prompt="first thing", per_turn=usage(out=100))
        second = session(3, prompt="second thing", per_turn=usage(out=100))
        second[0]["promptId"] = "p2"
        recs += second

        for r in recs:
            if r["type"] == "assistant":
                self.assertNotIn("promptId", r)

        a = run(recs)
        self.assertEqual(len(a.tasks), 2, "prompts must not collapse into one task")
        by_label = {t.label: t for t in a.tasks.values()}
        self.assertIn("first thing", by_label)
        self.assertIn("second thing", by_label)
        self.assertEqual(by_label["first thing"].turns, 2)
        self.assertEqual(by_label["second thing"].turns, 3)
        self.assertEqual(by_label["first thing"].usage.output, 200)
        self.assertEqual(by_label["second thing"].usage.output, 300)

    def test_total_turns_always_set(self):
        a = run(session(3))
        for s in a.sessions.values():
            self.assertGreater(s.total_turns, 0)


# ---------------------------------------------------------------- privacy --


class TestRedaction(unittest.TestCase):
    SECRET = "migrate the acme-corp billing database"

    def _analysis(self):
        tool = [{"type": "tool_use", "id": "t1", "name": "Read",
                 "input": {"file_path": "/Users/someone/private/secrets.py"}}]
        a = run(session(3, prompt=self.SECRET, tools=tool))
        return a

    def test_prompt_text_present_without_redaction(self):
        a = self._analysis()
        labels = " ".join(t.label for t in a.tasks.values())
        self.assertIn("acme-corp", labels)

    def test_prompt_text_gone_after_redaction(self):
        a = self._analysis()
        screen.apply_redaction(a)
        blob = " ".join(t.label for t in a.tasks.values())
        blob += " ".join(json.dumps(f) for f in a.findings)
        blob += " ".join(s.project for s in a.sessions.values())
        self.assertNotIn("acme-corp", blob)
        self.assertNotIn("billing", blob)

    def test_file_paths_gone_after_redaction(self):
        a = self._analysis()
        screen.apply_redaction(a)
        blob = " ".join(sorted(
            p for t in a.tasks.values() for p in t.files_read))
        self.assertNotIn("secrets.py", blob)
        self.assertNotIn("/Users/", blob)

    def test_json_output_carries_no_prompt_text_when_redacted(self):
        a = self._analysis()
        screen.apply_redaction(a)
        self.assertNotIn("acme-corp", json.dumps(screen.to_json(a)))

    def test_mcp_tool_names_redacted(self):
        """
        MCP tool names embed the vendor - "mcp__spur__whatsapp_upload" reveals
        which third-party services the user integrates with. Regression test:
        this leaked through the by_tool breakdown in the first redaction pass.
        """
        tool = [{"type": "tool_use", "id": "t1",
                 "name": "mcp__acmecorp__crm_lookup", "input": {}}]
        recs = session(1, tools=tool)
        recs.append({
            "type": "user", "sessionId": "sess1", "cwd": "/proj",
            "timestamp": "2026-08-08T10:00:00.000Z",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "x"}]},
        })
        a = run(recs)
        self.assertIn("mcp__acmecorp__crm_lookup", json.dumps(screen.to_json(a)))

        screen.apply_redaction(a)
        blob = json.dumps(screen.to_json(a))
        self.assertNotIn("acmecorp", blob)
        self.assertNotIn("crm_lookup", blob)
        self.assertIn("mcp tool", blob)

    def test_builtin_tool_names_kept_when_redacting(self):
        """Read/Bash/Edit are Claude Code internals - redacting them would
        destroy the report's value for nothing."""
        tool = [{"type": "tool_use", "id": "t1", "name": "Read",
                 "input": {"file_path": "/a/b.py"}}]
        recs = session(1, tools=tool)
        recs.append({
            "type": "user", "sessionId": "sess1", "cwd": "/proj",
            "timestamp": "2026-08-08T10:00:00.000Z",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "x"}]},
        })
        a = run(recs)
        screen.apply_redaction(a)
        self.assertIn("Read", json.dumps(screen.to_json(a)))

    def test_scrub_handles_quoted_and_bare_paths(self):
        s = screen._scrub('Read 3 files: "do the secret thing" [/Users/x/y/z.py]')
        self.assertNotIn("secret", s)
        self.assertNotIn("z.py", s)

    def test_scrub_removes_bare_filenames(self):
        """
        Regression: duplicate-read evidence lists basenames, not full paths.
        A filename can name a vendor (ACME-SETUP.md) or a person (jane-doe.png).
        """
        s = screen._scrub("jane-doe.png x8, ACME-SETUP.md x2, index.html x3")
        for leak in ("jane", "doe", "ACME", "index", ".png", ".md"):
            self.assertNotIn(leak, s)

    def test_scrub_preserves_numbers_and_money(self):
        """Over-scrubbing must not eat the figures the report exists to show."""
        s = screen._scrub("cost $35.85 at 1.25x over 40 turns, 273,593,524 tokens")
        self.assertIn("$35.85", s)
        self.assertIn("1.25x", s)
        self.assertIn("273,593,524", s)


# -------------------------------------------------------------- detectors --


class TestDetectors(unittest.TestCase):
    def _kinds(self, a):
        return {f["kind"] for f in a.findings}

    def test_long_session_detector_fires(self):
        a = run(session(40, per_turn=usage(out=50, cw5=100, cr=500_000)))
        self.assertIn("long-session", self._kinds(a))

    def test_short_session_does_not_fire_long_session(self):
        a = run(session(3, per_turn=usage(out=50, cw5=100, cr=500_000)))
        self.assertNotIn("long-session", self._kinds(a))

    def test_cache_churn_detector_fires(self):
        a = run(session(8, per_turn=usage(out=300, cw5=60_000, cr=3_000)))
        self.assertIn("cache-churn", self._kinds(a))

    def test_big_result_detector_fires(self):
        big = "x" * 200_000
        recs = session(1, tools=[{"type": "tool_use", "id": "t1", "name": "Read",
                                  "input": {"file_path": "/a/b.py"}}])
        recs.append({
            "type": "user", "sessionId": "sess1", "cwd": "/proj",
            "timestamp": "2026-08-08T10:00:00.000Z",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": big}]},
        })
        recs += session(20)[1:]
        a = run(recs)
        self.assertIn("big-results", self._kinds(a))

    def test_duplicate_reads_use_own_session_sizing(self):
        """
        Regression: this estimate previously used a corpus-wide Read average,
        charging a session that read small files the rate of one that read
        huge files. It must be sized from the session's own reads.
        """
        recs = session(1, tools=[
            {"type": "tool_use", "id": "t1", "name": "Read",
             "input": {"file_path": "/a/same.py"}}])
        recs.append({
            "type": "user", "sessionId": "sess1", "cwd": "/proj",
            "timestamp": "2026-08-08T10:00:00.000Z",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "y" * 8000}]},
        })
        recs += session(1)[1:]
        recs[-1]["message"]["content"] = [
            {"type": "tool_use", "id": "t2", "name": "Read",
             "input": {"file_path": "/a/same.py"}}]
        recs.append({
            "type": "user", "sessionId": "sess1", "cwd": "/proj",
            "timestamp": "2026-08-08T10:00:00.000Z",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t2", "content": "y" * 8000}]},
        })
        recs += session(20)[1:]
        a = run(recs)
        s = next(iter(a.sessions.values()))
        self.assertEqual(s.read_calls, 2)
        self.assertEqual(s.read_bytes, 16000)

    def test_no_findings_on_clean_short_session(self):
        a = run(session(2, per_turn=usage(out=100, cw5=500, cr=5000)))
        self.assertEqual(a.findings, [])

    def test_findings_deduped_one_per_kind(self):
        a = run(session(40, per_turn=usage(out=50, cw5=100, cr=500_000))
                + session(40, sid="s2", prompt="another",
                          per_turn=usage(out=50, cw5=100, cr=500_000)))
        kinds = [f["kind"] for f in a.findings]
        self.assertEqual(len(kinds), len(set(kinds)))


# ---------------------------------------------------------------- renderer --


class TestRenderers(unittest.TestCase):
    class Args:
        top = 10
        inr_rate = 88.0
        all_projects = True
        project = None
        redact = False

    def test_text_report_renders(self):
        a = run(session(5))
        out = screen.render_text(a, self.Args())
        self.assertIn("HEADLINE", out)
        self.assertIn("WHERE IT WENT", out)

    def test_html_is_self_contained(self):
        a = run(session(5))
        html = screen.render_html(a, self.Args())
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertIn("prefers-color-scheme", html)
        self.assertIn("data-theme", html)

    def test_html_escapes_user_content(self):
        a = run(session(2, prompt='<script>alert(1)</script>'))
        html = screen.render_html(a, self.Args())
        self.assertNotIn("<script>alert", html)

    def test_empty_analysis_renders_cleanly(self):
        a = screen.analyze([], PRICING)
        self.assertIn("No transcript data", screen.render_text(a, self.Args()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
