/**
 * Shared reader for the plugin tree.
 *
 * One function walks `plugins/` and returns everything the other scripts need,
 * so `validate-skills`, `gen-registry` and `build-zips` can never disagree
 * about what is in the catalogue.
 */

import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const PLUGIN_DIR_NAME = "plugins";
export const PLUGINS_DIR = join(ROOT, PLUGIN_DIR_NAME);

export const MARKETPLACE_NAME = "claudeskill";
export const GITHUB_SLUG = "claudeskill-co/skills";
export const SITE_URL = "https://claudeskill.co";

const VALID_SURFACES = ["cli", "desktop", "web"];
const VALID_TIERS = ["free", "pro"];

/** Minimal YAML frontmatter reader: flat `key: value` pairs only, which is all SKILL.md uses. */
export function parseFrontmatter(markdown) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(markdown);
  if (!match) return null;
  const fields = {};
  let key = null;
  for (const line of match[1].split(/\r?\n/)) {
    const start = /^([A-Za-z0-9_-]+):\s?(.*)$/.exec(line);
    if (start) {
      key = start[1];
      fields[key] = start[2].trim();
    } else if (key && line.trim()) {
      // A folded continuation line belongs to the previous key.
      fields[key] = `${fields[key]} ${line.trim()}`.trim();
    }
  }
  return fields;
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${path}: ${error.message}`);
  }
}

/**
 * @returns {Array<{slug, dir, plugin, catalog, skills: Array<{name, dir, frontmatter}>}>}
 */
export function readPlugins() {
  if (!existsSync(PLUGINS_DIR)) return [];

  return readdirSync(PLUGINS_DIR)
    .filter((entry) => !entry.startsWith(".") && statSync(join(PLUGINS_DIR, entry)).isDirectory())
    .sort()
    .map((slug) => {
      const dir = join(PLUGINS_DIR, slug);
      const plugin = readJson(join(dir, ".claude-plugin", "plugin.json"));
      const catalogPath = join(dir, "catalog.json");
      const catalog = existsSync(catalogPath) ? readJson(catalogPath) : {};

      const skillsRoot = join(dir, "skills");
      const skills = existsSync(skillsRoot)
        ? readdirSync(skillsRoot)
            .filter((entry) => statSync(join(skillsRoot, entry)).isDirectory())
            .sort()
            .map((name) => {
              const skillDir = join(skillsRoot, name);
              const skillMd = join(skillDir, "SKILL.md");
              return {
                name,
                dir: skillDir,
                frontmatter: existsSync(skillMd)
                  ? parseFrontmatter(readFileSync(skillMd, "utf8"))
                  : null,
              };
            })
        : [];

      return { slug, dir, plugin, catalog, skills };
    });
}

/** The registry entry the website renders. Derived, never hand-edited. */
export function toRegistryEntry({ slug, plugin, catalog, skills }) {
  const surfaces = catalog.surfaces ?? ["cli", "desktop", "web"];
  // A zip is only meaningful for the upload surfaces. CLI-only skills get none,
  // rather than a download that would appear to work and then do nothing.
  const uploadable = surfaces.some((surface) => surface !== "cli");
  const zipFor = (skillName) =>
    uploadable ? `https://github.com/${GITHUB_SLUG}/releases/latest/download/${skillName}.zip` : null;

  return {
    slug,
    displayName: catalog.displayName ?? slug,
    summary: catalog.summary ?? plugin.description ?? "",
    // One concrete line about what the skill actually contains. Lives beside
    // the code so the catalogue cannot advertise a count the code lost.
    signature: catalog.signature ?? null,
    description: plugin.description ?? "",
    category: catalog.category ?? "general",
    audience: catalog.audience ?? ["operator"],
    surfaces,
    tier: catalog.tier ?? "free",
    featured: catalog.featured === true,
    version: plugin.version,
    highlights: catalog.highlights ?? [],
    requires: catalog.requires ?? null,
    notes: catalog.notes ?? null,
    skills: skills.map((skill) => ({
      name: skill.name,
      description: skill.frontmatter?.description ?? "",
      zip: zipFor(skill.name),
    })),
    install: {
      marketplace: MARKETPLACE_NAME,
      marketplaceAdd: `/plugin marketplace add ${GITHUB_SLUG}`,
      pluginInstall: `/plugin install ${slug}@${MARKETPLACE_NAME}`,
      // Convenience for the common single-skill plugin. Multi-skill plugins are
      // uploaded one skill at a time, so the site links each skill's own zip.
      zip: skills.length === 1 ? zipFor(skills[0].name) : null,
    },
    source: `https://github.com/${GITHUB_SLUG}/tree/main/plugins/${slug}`,
  };
}

/** The plugin entry Claude Code reads out of `.claude-plugin/marketplace.json`. */
export function toMarketplaceEntry({ slug, plugin, catalog }) {
  return {
    name: slug,
    // Full path from the marketplace root, deliberately not relying on
    // metadata.pluginRoot: `claude plugin validate` accepts a bare slug there,
    // but `claude plugin install` then resolves it against the repository root
    // and fails. Verified by installing, not by reading the schema.
    source: `./${PLUGIN_DIR_NAME}/${slug}`,
    displayName: catalog.displayName ?? slug,
    description: plugin.description,
    version: plugin.version,
    author: plugin.author,
    homepage: plugin.homepage,
    license: plugin.license,
    category: catalog.category ?? "general",
    tags: plugin.keywords ?? [],
  };
}

export { VALID_SURFACES, VALID_TIERS };
