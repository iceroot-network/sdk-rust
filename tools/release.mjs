#!/usr/bin/env node
// Publishes a GitHub release of the Rust SDK for a version tag, with release notes. The crates are
// used as git dependencies on the tag; the release carries no build.
//
//   node tools/release.mjs [--tag vX.Y.Z] [--require-on BRANCH] [--dry-run]
//
// --tag           the release tag (default: $GITHUB_REF_NAME); it must be v<the workspace version
//                 in Cargo.toml> and point at the checked-out commit
// --require-on    refuse unless the commit is on origin/BRANCH (the release workflow passes prod)
// --dry-run       print the notes, publish nothing
//
// The release workflow (.github/workflows/release.yml) runs this for every pushed v* tag, after
// the checks and tests. It needs the GitHub CLI with a token that may write releases (GH_TOKEN).
//
// The notes say how to depend on the release, what it contains, the notes written for the version
// in release-notes/<tag>.md (what an application must know: changed or removed interfaces), and
// the commits since the previous tag.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repository = "iceroot-network/sdk-rust";

const { values: options } = parseArgs({
  options: {
    tag: { type: "string", default: process.env.GITHUB_REF_NAME },
    "require-on": { type: "string" },
    "dry-run": { type: "boolean", default: false },
  },
});

main();

function main() {
  const manifest = readFileSync(join(root, "Cargo.toml"), "utf8");
  const version = /\[workspace\.package\][^[]*?\nversion = "([^"]+)"/.exec(manifest)?.[1];
  if (version === undefined) {
    fail("Cargo.toml has no [workspace.package] version");
  }
  const tag = options.tag;
  if (tag !== `v${version}`) {
    fail(`the tag ${tag ?? "(none)"} is not v${version}, the workspace version in Cargo.toml`);
  }
  const head = git("rev-parse", "HEAD");
  const tagged = gitOrNull("rev-parse", `${tag}^{commit}`);
  if (tagged === null) {
    fail(`the tag ${tag} does not exist here`);
  }
  if (tagged !== head) {
    fail(`the tag ${tag} is ${tagged}, but the checkout is ${head}`);
  }
  if (git("status", "--porcelain", "--untracked-files=no") !== "") {
    fail("the working tree has changes; a release is made from the tagged commit only");
  }
  if (options["require-on"] !== undefined) {
    const branch = `origin/${options["require-on"]}`;
    if (gitOrNull("merge-base", "--is-ancestor", head, branch) === null) {
      fail(`${head} is not on ${branch}`);
    }
  }

  const notes = releaseNotes(tag, version, head);
  if (options["dry-run"]) {
    process.stdout.write(`release: ${tag} (dry run)\n\n${notes}`);
    return;
  }
  const notesFile = join(mkdtempSync(join(tmpdir(), "release-")), "notes.md");
  writeFileSync(notesFile, notes);
  const args = ["release", "create", tag, "--repo", repository, "--title", `IceRoot SDK for Rust ${version}`];
  args.push("--notes-file", notesFile, "--verify-tag");
  if (version.includes("-")) {
    args.push("--prerelease");
  }
  execFileSync("gh", args, { cwd: root, stdio: "inherit" });
  process.stdout.write(`release: published ${tag}\n`);
}

function releaseNotes(tag, version, head) {
  const lock = readFileSync(join(root, "Cargo.lock"), "utf8");
  const crates = [...lock.matchAll(/\[\[package\]\]\nname = "(iceroot-[^"]+)"\nversion = "([^"]+)"\n(?!source)/g)]
    .map(([, name, crateVersion]) => `\`${name}\` ${crateVersion}`)
    .join(", ");
  const previous = gitOrNull("describe", "--tags", "--abbrev=0", "--match", "v*", `${head}^`);
  const changes = git("log", "--no-merges", "--format=- %s", previous ? `${previous}..${head}` : head)
    .split("\n")
    .filter(Boolean);
  const written = versionNotes(tag);

  return `Use this release as a git dependency:

\`\`\`toml
[dependencies]
iceroot-sdk = { git = "https://github.com/${repository}", tag = "${tag}" }
\`\`\`

Building it fetches heartwood-core from the public HTTPS repository without credentials. The TypeScript package built from this release is attached to the release of the same tag in [sdk-typescript](https://github.com/iceroot-network/sdk-typescript/releases).

## Contents

- Crates: ${crates}
- heartwood-crypto: ${heartwoodSource(lock)}
- Rust ${rustVersion()} or later
${written ? `\n## Notes\n\n${written}\n` : ""}
## Changes${previous ? ` since ${previous}` : ""}

${changes.join("\n") || "- No changes."}
`;
}

// The notes written for this version, if any.
function versionNotes(tag) {
  const file = join(root, "release-notes", `${tag}.md`);
  return existsSync(file) ? readFileSync(file, "utf8").trim() : null;
}

// Where heartwood-crypto comes from, as Cargo.lock records it.
function heartwoodSource(lock) {
  const match = /\[\[package\]\]\nname = "heartwood-crypto"\nversion = "([^"]+)"\nsource = "git\+([^"]+)"/.exec(lock);
  if (match === null) {
    fail("Cargo.lock has no git source for heartwood-crypto");
  }
  const [, crateVersion, source] = match;
  const [location, commit] = source.split("#");
  const url = new URL(location.replace(/^ssh:\/\/git@[^/]+\//, "https://github.com/"));
  const pin = url.searchParams.get("tag") ?? url.searchParams.get("rev") ?? url.searchParams.get("branch");
  const repo = `${url.origin}${url.pathname.replace(/\.git$/, "")}`;
  return `${crateVersion} from ${repo}${pin ? ` at ${pin}` : ""} (commit ${commit})`;
}

function rustVersion() {
  const manifest = readFileSync(join(root, "Cargo.toml"), "utf8");
  return /\nrust-version = "([^"]+)"/.exec(manifest)?.[1] ?? "unknown";
}

function git(...args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function gitOrNull(...args) {
  try {
    return git(...args);
  } catch {
    return null;
  }
}

function fail(message) {
  process.stderr.write(`release: ${message}\n`);
  process.exit(1);
}
