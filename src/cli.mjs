#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { analyzeContract, toHtml, toSarif } from "./core.mjs";

async function main() {
  const args = process.argv.slice(2);
  const input = args.find((arg) => !arg.startsWith("--"));
  if (!input) throw new Error("Usage: saml-rollover-preflight <contract.json> [--out report.json] [--html report.html] [--sarif report.sarif.json]");
  const inputPath = resolve(input);
  const contract = JSON.parse(await readFile(inputPath, "utf8"));
  for (const key of ["currentMetadataPath", "nextMetadataPath"]) {
    if (contract[key]) contract[key.replace("Path", "Xml")] = await readFile(resolve(dirname(inputPath), contract[key]), "utf8");
  }
  const report = await analyzeContract(contract);
  const outIndex = args.indexOf("--out");
  const htmlIndex = args.indexOf("--html");
  const sarifIndex = args.indexOf("--sarif");
  if (outIndex >= 0) await writeFile(resolve(args[outIndex + 1]), JSON.stringify(report, null, 2) + "\n");
  if (htmlIndex >= 0) await writeFile(resolve(args[htmlIndex + 1]), toHtml(report));
  if (sarifIndex >= 0) await writeFile(resolve(args[sarifIndex + 1]), JSON.stringify(toSarif(report), null, 2) + "\n");
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  process.exitCode = report.status === "BLOCK" ? 1 : 0;
}

main().catch((error) => { console.error(`saml-rollover-preflight: ${error.message}`); process.exitCode = 2; });
