#!/usr/bin/env node
/**
 * Build one zip per skill for the Claude Desktop and claude.ai uploaders.
 *
 * Those uploaders expect an archive whose root entry is the skill folder itself,
 * i.e. `token-screener/SKILL.md`, not `SKILL.md` and not
 * `plugins/token-screener/skills/token-screener/SKILL.md`. So each archive is
 * created from the skill's parent directory with the folder name as the target.
 *
 *     node scripts/build-zips.mjs        # -> dist/<skill>.zip
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, existsSync, statSync } from "node:fs";
import { dirname, basename, join, relative } from "node:path";
import { ROOT, readPlugins } from "./lib/catalog.mjs";

const DIST = join(ROOT, "dist");

rmSync(DIST, { recursive: true, force: true });
mkdirSync(DIST, { recursive: true });

const built = [];
const skipped = [];

for (const plugin of readPlugins()) {
  const surfaces = plugin.catalog.surfaces ?? ["cli", "desktop", "web"];

  if (!surfaces.some((surface) => surface !== "cli")) {
    // Not silently dropped - reported below, so the catalogue and the release
    // assets always tell the same story.
    skipped.push(`${plugin.slug} (cli-only)`);
    continue;
  }

  for (const skill of plugin.skills) {
    const out = join(DIST, `${skill.name}.zip`);
    execFileSync(
      "zip",
      ["-r", "-q", "-X", out, basename(skill.dir), "-x", "*.pyc", "-x", "*/__pycache__/*", "-x", ".DS_Store"],
      { cwd: dirname(skill.dir), stdio: "inherit" },
    );
    const kb = (statSync(out).size / 1024).toFixed(1);
    built.push(`${relative(ROOT, out)} (${kb} KB)`);
  }
}

for (const line of built) console.log(`zip   ${line}`);
for (const line of skipped) console.log(`skip  ${line} - no upload surface, so no zip is published`);

if (built.length === 0 && skipped.length === 0) {
  console.error("error no plugins found");
  process.exit(1);
}

if (built.length === 0) {
  console.log("ok    nothing to package: every skill in the catalogue is CLI-only");
} else {
  console.log(`ok    ${built.length} zip(s) in dist/`);
}

if (!existsSync(DIST)) process.exit(1);
