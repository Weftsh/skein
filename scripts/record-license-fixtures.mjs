#!/usr/bin/env node
// Records licence keys encoded, validated and verified by sandy's own
// licence code into crates/skein-license/fixtures/sandy-issued.json.
//
// Skein verifies the same `weft_lic_v1` keys Weft Sandboxes does, minted
// by the same `weft-license` tool. What Skein's Rust verifier believes
// about that format — base64url with no padding, the signature over the
// payload segment's ASCII, which fields the issuer insists on — is
// checked here against sandy's actual `packages/license/src/key.ts`, not
// against a description of it:
//
//   SANDY_DIR=../weftsh/sandy node --experimental-strip-types \
//     scripts/record-license-fixtures.mjs
//
// `key.ts` imports only node:crypto, so it runs straight from sandy's
// checkout with no install. `issue.ts` imports the AWS SDK for its KMS
// signer, so the two lines of `localSigner` and `issueLicenseKey` it
// would contribute are repeated below, marked, around sandy's own
// `validatePayload`, `encodePayload` and `encodeLicenseKey`.
//
// The signing key is generated fresh and thrown away; only its public
// half is recorded.

import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const sandy = process.env.SANDY_DIR;
if (!sandy) {
  console.error("set SANDY_DIR to a checkout of weftsh/sandy");
  process.exit(2);
}
const key = await import(resolve(sandy, "packages/license/src/key.ts"));

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const kid = "fixture-1";

// issue.ts's issueLicenseKey(payload, localSigner(privateKey)), verbatim
// but for the signer's KMS import.
function issue(payload) {
  const problem = key.validatePayload(payload);
  if (problem) throw new Error(`invalid license payload: ${problem}`);
  const part = key.encodePayload(payload);
  return key.encodeLicenseKey(part, sign(null, Buffer.from(part, "utf8"), privateKey));
}

const base = {
  v: 1,
  kid,
  lid: "lic_fixture_001",
  entity: "Fixture Corp",
  tier: "team",
  accounts: [],
  maxConcurrent: null,
  mode: "online",
  iat: "2026-10-01T00:00:00.000Z",
  exp: "2027-10-01T00:00:00.000Z",
};

const keys = {
  // What a Skein key minted by `weft-license issue` is: sandy's required
  // fields, and Skein's two.
  skein_team: issue({ ...base, product: "skein", maxSeats: 25 }),
  skein_enterprise_offline_uncapped: issue({
    ...base,
    lid: "lic_fixture_002",
    tier: "enterprise",
    mode: "offline",
    product: "skein",
    maxSeats: null,
    trial: true,
  }),
  // A Weft Sandboxes key: no product. Skein must refuse it.
  sandboxes_team: issue({ ...base, lid: "lic_fixture_003", maxConcurrent: 50 }),
};

const trusted = key.trustedKeysFromPem({ [kid]: publicKeyPem });
// What sandy's verifier says about each: recorded because a Skein key
// verifying in sandy is sandy's to fix (it reads no `product`).
const sandyVerdicts = Object.fromEntries(
  Object.entries(keys).map(([name, k]) => {
    const r = key.verifyLicenseKey(k, trusted);
    return [name, r.ok ? "ok" : r.reason];
  }),
);

let sandyCommit = "unknown";
try {
  sandyCommit = execFileSync("git", ["-C", sandy, "rev-parse", "HEAD"]).toString().trim();
} catch {}

const out = {
  provenance: {
    recorded_by: "scripts/record-license-fixtures.mjs",
    sandy_commit: sandyCommit,
    node: process.version,
    recorded_at: new Date().toISOString(),
  },
  kid,
  public_key_pem: publicKeyPem,
  keys,
  sandy_verdicts: sandyVerdicts,
};

const here = dirname(fileURLToPath(import.meta.url));
const path = join(here, "..", "crates", "skein-license", "fixtures", "sandy-issued.json");
writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${path}`);
console.log(sandyVerdicts);
