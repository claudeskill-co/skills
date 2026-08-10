#!/usr/bin/env node
/**
 * Enforce the rules Anthropic's loaders enforce, before a user ever hits them.
 *
 * A skill that fails validation here would be silently rejected on upload to
 * claude.ai or skipped by Claude Code, which is a much worse way to find out.
 *
 *     node scripts/validate-skills.mjs
 */

import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { readPlugins, ROOT, VALID_SURFACES, VALID_TIERS } from "./lib/catalog.mjs";

const errors = [];
const warnings = [];

const fail = (where, message) => errors.push(`${where}: ${message}`);
const warn = (where, message) => warnings.push(`${where}: ${message}`);

// Anthropic rejects these substrings in a skill name outright.
const RESERVED_SUBSTRINGS = ["claude", "anthropic"];
const KEBAB = /^[a-z0-9]+(-[a-z0-9]+)*$/;

const plugins = readPlugins();

if (plugins.length === 0) {
  fail("plugins/", "no plugins found");
}

for (const entry of plugins) {
  const { slug, dir, plugin, catalog, skills } = entry;
  const where = `plugins/${slug}`;

  // --- plugin manifest ---
  if (plugin.name !== slug) {
    fail(where, `plugin.json name "${plugin.name}" must match the directory name "${slug}"`);
  }
  if (!plugin.version) {
    fail(where, "plugin.json needs a version, otherwise users never get updates");
  }
  if (!plugin.description) {
    fail(where, "plugin.json needs a description");
  }

  // --- identity: nothing personal ships ---
  if (plugin.author?.name && plugin.author.name !== "ClaudeSkill") {
    fail(where, `plugin.json author must be "ClaudeSkill", found "${plugin.author.name}"`);
  }

  // --- catalogue metadata ---
  if (!catalog.displayName) warn(where, "catalog.json has no displayName; the site will show the slug");
  if (!catalog.summary) warn(where, "catalog.json has no summary; the catalogue card will look empty");

  for (const surface of catalog.surfaces ?? []) {
    if (!VALID_SURFACES.includes(surface)) {
      fail(where, `unknown surface "${surface}" (expected ${VALID_SURFACES.join(", ")})`);
    }
  }
  if (catalog.tier && !VALID_TIERS.includes(catalog.tier)) {
    fail(where, `unknown tier "${catalog.tier}" (expected ${VALID_TIERS.join(", ")})`);
  }

  // --- the skills themselves ---
  if (skills.length === 0) {
    fail(where, "no skills/<name>/SKILL.md found");
  }

  for (const skill of skills) {
    const skillWhere = `${where}/skills/${skill.name}`;

    if (!skill.frontmatter) {
      fail(skillWhere, "SKILL.md is missing or has no YAML frontmatter");
      continue;
    }

    const { name, description } = skill.frontmatter;

    if (!name) {
      fail(skillWhere, "frontmatter needs a name");
    } else {
      if (name !== skill.name) {
        fail(skillWhere, `frontmatter name "${name}" must match the folder name "${skill.name}"`);
      }
      if (name.length > 64) {
        fail(skillWhere, `name is ${name.length} chars, the limit is 64`);
      }
      if (!KEBAB.test(name)) {
        fail(skillWhere, `name "${name}" must be lowercase letters, numbers and hyphens only`);
      }
      for (const reserved of RESERVED_SUBSTRINGS) {
        if (name.includes(reserved)) {
          fail(skillWhere, `name contains the reserved word "${reserved}" and will be rejected on upload`);
        }
      }
    }

    if (!description) {
      fail(skillWhere, "frontmatter needs a description - it is the only trigger signal Claude gets");
    } else {
      if (description.length > 1024) {
        fail(skillWhere, `description is ${description.length} chars, the limit is 1024`);
      }
      if (/<[a-zA-Z/]/.test(description)) {
        fail(skillWhere, "description must not contain XML tags");
      }
      // The description has to say *when* to use the skill, not just what it is.
      if (!/\buse (when|this|it)\b/i.test(description)) {
        warn(skillWhere, 'description has no "Use when ..." clause, so Claude may never trigger it');
      }
    }

    if (!existsSync(join(skill.dir, "SKILL.md"))) {
      fail(skillWhere, "SKILL.md not found");
    }
  }

  // --- no personal identifiers anywhere in the shipped files ---
  const shipped = [join(dir, ".claude-plugin", "plugin.json"), join(dir, "catalog.json")];
  for (const skill of skills) shipped.push(join(skill.dir, "SKILL.md"));
  for (const path of shipped) {
    if (!existsSync(path)) continue;
    const text = readFileSync(path, "utf8");
    const hit = /puneet|sharma|puneet-sharma-18/i.exec(text);
    if (hit) {
      fail(relative(ROOT, path), `contains a personal identifier ("${hit[0]}")`);
    }
  }
}

for (const message of warnings) console.warn(`warn  ${message}`);
for (const message of errors) console.error(`error ${message}`);

if (errors.length > 0) {
  console.error(`\n${errors.length} error(s). Nothing was published.`);
  process.exit(1);
}

const skillCount = plugins.reduce((total, plugin) => total + plugin.skills.length, 0);
console.log(`ok    ${plugins.length} plugin(s), ${skillCount} skill(s) valid`);
