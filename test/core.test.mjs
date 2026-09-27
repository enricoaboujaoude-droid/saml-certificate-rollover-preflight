import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { analyzeContract, toHtml, toSarif } from "../src/core.mjs";

async function fixture(name) {
  const base = resolve(`examples/${name}`);
  const contract = JSON.parse(await readFile(resolve(base, "contract.json"), "utf8"));
  for (const key of ["currentMetadataPath", "nextMetadataPath"]) contract[key.replace("Path", "Xml")] = await readFile(resolve(base, contract[key]), "utf8");
  return contract;
}

test("safe rollover passes with complete three-stage trust", async () => {
  const report = await analyzeContract(await fixture("safe"));
  assert.equal(report.status, "PASS");
  assert.equal(report.findings.length, 0);
  assert.equal(report.acceptanceMatrix.length, 2);
});

test("incident rollover blocks unsafe transition", async () => {
  const report = await analyzeContract(await fixture("incident"));
  assert.equal(report.status, "BLOCK");
  for (const id of ["SAML-ENTITY-ID-CHANGED", "SAML-SSO-ENDPOINT-CHANGED", "SAML-WEAK-SIGNATURE-ALGORITHM", "SAML-CURRENT-REJECTS-OLD", "SAML-OVERLAP-INCOMPLETE", "SAML-FINAL-REJECTS-NEW", "SAML-FINAL-RETAINS-OLD"]) assert.ok(report.findings.some((item) => item.ruleId === id), id);
});

test("private key material is rejected", async () => {
  const contract = await fixture("safe");
  contract.nextMetadataXml += "-----BEGIN PRIVATE KEY-----";
  await assert.rejects(() => analyzeContract(contract), /private-key/);
});

test("fingerprints must be SHA-256", async () => {
  const contract = await fixture("safe");
  contract.trust.current = ["AA:BB"];
  await assert.rejects(() => analyzeContract(contract), /non-SHA-256/);
});

test("final old-certificate exception produces review inside bounded window", async () => {
  const contract = await fixture("safe");
  contract.trust.final.push(contract.trust.current[0]);
  contract.policy.allowOldInFinalUntil = "2026-09-28T00:00:00Z";
  const report = await analyzeContract(contract);
  assert.equal(report.status, "REVIEW");
  assert.ok(report.findings.some((item) => item.ruleId === "SAML-FINAL-RETAINS-OLD"));
});

test("expired metadata blocks", async () => {
  const contract = await fixture("safe");
  contract.nextMetadataXml = contract.nextMetadataXml.replace("2028-09-26T09:32:05Z", "2025-01-01T00:00:00Z");
  const report = await analyzeContract(contract);
  assert.ok(report.findings.some((item) => item.ruleId === "SAML-METADATA-EXPIRED"));
});

test("duplicate certificates are reviewed", async () => {
  const contract = await fixture("safe");
  const cert = contract.nextMetadataXml.match(/<X509Certificate>([\s\S]*?)<\/X509Certificate>/)[0];
  contract.nextMetadataXml = contract.nextMetadataXml.replace("</KeyDescriptor>", `</KeyDescriptor><KeyDescriptor use="signing">${cert}</KeyDescriptor>`);
  const report = await analyzeContract(contract);
  assert.ok(report.findings.some((item) => item.ruleId === "SAML-DUPLICATE-CERTIFICATE"));
});

test("report is deterministic for pinned evaluationTime", async () => {
  const contract = await fixture("safe");
  assert.deepEqual(await analyzeContract(contract), await analyzeContract(contract));
});

test("SARIF maps blocks to errors", async () => {
  const sarif = toSarif(await analyzeContract(await fixture("incident")));
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.some((item) => item.level === "error"));
});

test("HTML contains matrix and escaped findings", async () => {
  const html = toHtml(await analyzeContract(await fixture("incident")));
  assert.match(html, /Acceptance matrix/);
  assert.match(html, /SAML-ENTITY-ID-CHANGED/);
});

test("safe CLI exits zero", async () => {
  const { spawnSync } = await import("node:child_process");
  const result = spawnSync(process.execPath, ["src/cli.mjs", "examples/safe/contract.json", "--json"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, "PASS");
});

test("incident CLI exits one", async () => {
  const { spawnSync } = await import("node:child_process");
  const result = spawnSync(process.execPath, ["src/cli.mjs", "examples/incident/contract.json", "--json"], { encoding: "utf8" });
  assert.equal(result.status, 1, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, "BLOCK");
});

test("root Action metadata uses Node 20", async () => {
  const action = await readFile("action.yml", "utf8");
  assert.match(action, /using: node20/);
  assert.match(action, /name: SAML Certificate Rollover Preflight/);
});

test("CLI writes JSON, HTML, and SARIF evidence", async () => {
  const { spawnSync } = await import("node:child_process");
  const { mkdtemp, readFile: read, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "saml-preflight-"));
  const result = spawnSync(process.execPath, ["src/cli.mjs", "examples/safe/contract.json", "--out", join(dir, "report.json"), "--html", join(dir, "report.html"), "--sarif", join(dir, "report.sarif.json")], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(await read(join(dir, "report.json"), "utf8")).status, "PASS");
  assert.match(await read(join(dir, "report.html"), "utf8"), /Acceptance matrix/);
  assert.equal(JSON.parse(await read(join(dir, "report.sarif.json"), "utf8")).version, "2.1.0");
  await rm(dir, { recursive: true });
});
