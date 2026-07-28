#!/usr/bin/env node
// Merges freshly captured per-platform signature vectors into
// src/cross-platform-test-vectors.json.
//
// "Generate Test Vectors" in the app (src/lib/TestVectors.svelte) produces a JSON
// array for whichever platform it ran on. Previously the only way to get that into
// the committed file was to copy the textarea contents by hand and splice them into
// the right spot — error-prone, and nothing checked the result was well-formed before
// it landed in git. This script takes that JSON (as a file, or piped via stdin),
// replaces the entries for its platform in the canonical file, validates the merged
// result the same way tests/cross_platform_vectors.rs would reject it, and writes it
// back with stable formatting.
//
// Usage:
//   node scripts/merge-test-vectors.mjs path/to/ios-vectors.json
//   pnpm tauri dev ... | node scripts/merge-test-vectors.mjs   (paste JSON, then EOF)

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CANONICAL_PATH = join(
  __dirname,
  "../src/cross-platform-test-vectors.json"
);
const REQUIRED_PLATFORMS = ["ios", "macos", "android", "windows"];
const REQUIRED_FIELDS = [
  "platform",
  "label",
  "publicKey",
  "message",
  "signatureBase64",
  "generatedAt",
];

function readInput() {
  const arg = process.argv[2];
  const raw = arg ? readFileSync(arg, "utf8") : readFileSync(0, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    fail(`input is not valid JSON: ${e.message}`);
  }
  if (!Array.isArray(parsed)) {
    fail(
      "input must be a JSON array of vectors (the shape TestVectors.svelte emits)"
    );
  }
  return parsed;
}

function fail(message) {
  console.error(`merge-test-vectors: ${message}`);
  process.exit(1);
}

function isValidBase64(s) {
  return typeof s === "string" && s.length > 0 && /^[A-Za-z0-9+/]+=*$/.test(s);
}

function validateVector(vector, index) {
  for (const field of REQUIRED_FIELDS) {
    if (typeof vector[field] !== "string" || vector[field].length === 0) {
      fail(`vector[${index}] is missing or has an empty "${field}"`);
    }
  }
  if (!REQUIRED_PLATFORMS.includes(vector.platform)) {
    fail(
      `vector[${index}] has unknown platform "${vector.platform}" (expected one of ${REQUIRED_PLATFORMS.join(", ")})`
    );
  }
  if (!isValidBase64(vector.publicKey)) {
    fail(`vector[${index}] "publicKey" is not valid base64`);
  }
  if (!isValidBase64(vector.signatureBase64)) {
    fail(`vector[${index}] "signatureBase64" is not valid base64`);
  }
}

const incoming = readInput();
if (incoming.length === 0) {
  fail("input has no vectors");
}
incoming.forEach(validateVector);

const platforms = new Set(incoming.map((v) => v.platform));
if (platforms.size !== 1) {
  fail(
    `input mixes vectors from multiple platforms (${[...platforms].join(", ")}) — merge one platform's capture at a time`
  );
}
const [platform] = platforms;

const canonical = JSON.parse(readFileSync(CANONICAL_PATH, "utf8"));
const before = canonical.vectors.filter((v) => v.platform === platform).length;
canonical.vectors = [
  ...canonical.vectors.filter((v) => v.platform !== platform),
  ...incoming,
];

// Same coverage bar tests/cross_platform_vectors.rs enforces: catch a bad capture
// (e.g. every message happened to be ASCII) before it reaches the committed file.
if (!incoming.some((v) => !/^[\x00-\x7F]*$/.test(v.message))) {
  fail(
    `incoming ${platform} vectors have no non-ASCII message — capture is incomplete`
  );
}

writeFileSync(CANONICAL_PATH, JSON.stringify(canonical, null, 2) + "\n");

console.log(
  `merge-test-vectors: replaced ${before} existing ${platform} vector(s) with ${incoming.length} new one(s) in ${CANONICAL_PATH}`
);
console.log(
  `Run "cargo test" in tauri-plugin-secure-element/ to verify the merged vectors.`
);
