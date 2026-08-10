# Changelog

All notable changes to this repository are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/).

Individual skills carry their own versions in `plugins/<slug>/.claude-plugin/plugin.json`.

## [2.1.0] - 2026-08-10

### Added
- **unit-economics** - per-order margin for a D2C brand. Strips GST out of
  revenue, models prepaid and COD orders separately (including what RTO
  actually costs), and returns CM1/CM2/CM3, the most you can pay to acquire an
  order, breakeven ROAS and the discount floor. 36 tests.

  It is the first skill in the catalogue that runs on the upload surfaces, so
  it is also the first real exercise of the zip pipeline - previously the
  Desktop and claude.ai install path was advertised but never executed.

### Changed
- CI runs each plugin's tests as a matrix rather than naming one plugin, so a
  new skill cannot land untested, and smoke-runs both scripts with no input.
- The identity check in `validate-skills.mjs` now scans every text file under a
  plugin, not just its manifests and SKILL.md.
- LICENSE names the catalogue rather than a single tool, and gives the licensor
  a contact address.

## [2.0.0] - 2026-08-10

The repository became a multi-skill catalogue under the ClaudeSkill name.

### Changed
- **Moved to `claudeskill-co/skills`.** The marketplace is now `claudeskill`,
  not `token-screener-marketplace`. Existing users must add it once:

  ```
  /plugin marketplace add claudeskill-co/skills
  /plugin install token-screener@claudeskill
  ```

  The plugin name is unchanged, so nothing else about `token-screener` moves.
  The old repository stays in place and redirects, so an install done before
  this change keeps working until you switch.
- Repository restructured as a monorepo: each skill is a plugin under
  `plugins/<slug>/`, with `metadata.pluginRoot` pointing Claude Code at it.
- Ownership and licence attribution are now ClaudeSkill rather than an
  individual.

### Added
- `registry.json`, the machine-readable catalogue that claudeskill.co renders.
- `scripts/gen-registry.mjs` generates both catalogue files from the plugin
  tree, and CI fails if either is stale.
- `scripts/validate-skills.mjs` enforces Anthropic's skill rules locally —
  reserved words in `name`, length limits, XML tags, a missing "use when"
  clause — instead of letting an upload fail silently.
- `scripts/build-zips.mjs` packages each skill for the Claude Desktop and
  claude.ai uploaders, and CI attaches the zips to tagged releases.

---

Earlier entries describe `token-screener` before it moved into this repository.

## [1.1.0] - 2026-08-10

### Added
- `--redact` flag. Replaces prompt text, file paths, and project paths with
  placeholders so a report can be shared without leaking the user's content.
- Test suite (31 tests, stdlib `unittest`, no dependencies) covering token
  accounting, task attribution, redaction, detectors, and rendering.
- GitHub Actions CI across Python 3.9 / 3.11 / 3.13.

### Fixed
- Duplicate-read savings estimate used a corpus-wide average Read size, which
  charged small-file sessions the rate of large-file ones. Now sized from each
  session's own reads.
- `Session.total_turns` could be unset when a transcript returned early,
  silently degrading the carrying-cost calculation to a partial turn count.
- Removed dead code in the duplicate-read detector.

### Changed
- README example figures are now illustrative rather than real usage data.
- **Licence changed from MIT to Business Source License 1.1.** Source remains
  public and free for personal and internal commercial use; reselling it as a
  product or service requires a licence. Converts to Apache 2.0 on 2030-08-10.

## [1.0.0] - 2026-08-10

### Added
- Initial release: token accounting from local Claude Code transcripts, task
  and tool attribution, seven optimization detectors, terminal report and
  optional self-contained HTML dashboard.
