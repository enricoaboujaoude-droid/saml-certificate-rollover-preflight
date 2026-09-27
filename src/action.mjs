import { readFile, writeFile, appendFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { analyzeContract, toSarif } from "./core.mjs";

const inputPath = resolve(process.env.INPUT_CONTRACT || "");
try {
  const contract = JSON.parse(await readFile(inputPath, "utf8"));
  for (const key of ["currentMetadataPath", "nextMetadataPath"]) if (contract[key]) contract[key.replace("Path", "Xml")] = await readFile(resolve(dirname(inputPath), contract[key]), "utf8");
  const report = await analyzeContract(contract);
  await writeFile(resolve(process.env.INPUT_REPORT || "saml-rollover-report.json"), JSON.stringify(report, null, 2) + "\n");
  await writeFile(resolve(process.env.INPUT_SARIF || "saml-rollover-report.sarif.json"), JSON.stringify(toSarif(report), null, 2) + "\n");
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `status=${report.status}\nblock-count=${report.summary.blockCount}\nreview-count=${report.summary.reviewCount}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `## SAML rollover preflight: ${report.status}\n\n- Blocks: ${report.summary.blockCount}\n- Reviews: ${report.summary.reviewCount}\n`);
  if (report.status === "BLOCK") process.exitCode = 1;
} catch (error) { console.error(error.stack || error.message); process.exitCode = 2; }
