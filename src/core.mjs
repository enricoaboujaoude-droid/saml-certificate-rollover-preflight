const SEVERITY = { PASS: 0, REVIEW: 1, BLOCK: 2 };

function cleanFingerprint(value) {
  return String(value || "").replace(/[^a-fA-F0-9]/g, "").toUpperCase();
}

function base64ToBytes(value) {
  const clean = value.replace(/\s+/g, "");
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(clean, "base64"));
  const binary = atob(clean);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function sha256Hex(bytes) {
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  }
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(bytes).digest("hex").toUpperCase();
}

function decodeEntities(value) {
  return String(value || "").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function attribute(xml, tagPattern, name) {
  const match = xml.match(new RegExp(`<${tagPattern}\\b[^>]*\\b${name}\\s*=\\s*["']([^"']+)["']`, "i"));
  return match ? decodeEntities(match[1]) : null;
}

async function parseMetadata(xml, label) {
  if (typeof xml !== "string" || !xml.trim()) throw new Error(`${label} metadata XML is required`);
  if (/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|<ds:KeyValue\b|<KeyValue\b/i.test(xml)) throw new Error(`${label} metadata contains private-key or raw key material; only public X.509 certificates are allowed`);
  const entityId = attribute(xml, "(?:[\\w.-]+:)?EntityDescriptor", "entityID");
  const validUntil = attribute(xml, "(?:[\\w.-]+:)?EntityDescriptor", "validUntil");
  const services = [...xml.matchAll(/<(?:[\w.-]+:)?SingleSignOnService\b([^>]*)\/?\s*>/gi)].map((match) => ({
    binding: decodeEntities((match[1].match(/\bBinding\s*=\s*["']([^"']+)["']/i) || [])[1]),
    location: decodeEntities((match[1].match(/\bLocation\s*=\s*["']([^"']+)["']/i) || [])[1])
  })).filter((item) => item.binding || item.location);
  const certBodies = [...xml.matchAll(/<(?:[\w.-]+:)?X509Certificate\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?X509Certificate>/gi)].map((match) => match[1].replace(/\s+/g, ""));
  const certificates = [];
  for (const body of certBodies) certificates.push({ fingerprint: await sha256Hex(base64ToBytes(body)), certificateBase64: body });
  const algorithms = [...xml.matchAll(/\bAlgorithm\s*=\s*["']([^"']+)["']/gi)].map((match) => decodeEntities(match[1]));
  return { label, entityId, validUntil, services, certificates, algorithms };
}

function finding(ruleId, level, message, evidence = {}) { return { ruleId, level, message, evidence }; }
function unique(items) { return [...new Set(items)]; }

function comparePolicy(current, next, policy, findings) {
  if (!current.entityId || !next.entityId) findings.push(finding("SAML-ENTITY-ID-MISSING", "BLOCK", "Both metadata documents must declare entityID."));
  if (current.entityId && next.entityId && current.entityId !== next.entityId) findings.push(finding("SAML-ENTITY-ID-CHANGED", "BLOCK", "entityID changes during a certificate-only rollover.", { current: current.entityId, next: next.entityId }));
  if (policy.requiredEntityId && (current.entityId !== policy.requiredEntityId || next.entityId !== policy.requiredEntityId)) findings.push(finding("SAML-ENTITY-ID-POLICY", "BLOCK", "Metadata does not match requiredEntityId.", { required: policy.requiredEntityId }));
  const currentEndpoints = current.services.map((s) => `${s.binding}|${s.location}`).sort();
  const nextEndpoints = next.services.map((s) => `${s.binding}|${s.location}`).sort();
  if (JSON.stringify(currentEndpoints) !== JSON.stringify(nextEndpoints)) findings.push(finding("SAML-SSO-ENDPOINT-CHANGED", "BLOCK", "SSO endpoint or binding changes during a certificate-only rollover.", { current: currentEndpoints, next: nextEndpoints }));
  if (policy.requiredSsoLocation && [...current.services, ...next.services].some((s) => s.location !== policy.requiredSsoLocation)) findings.push(finding("SAML-SSO-ENDPOINT-POLICY", "BLOCK", "An SSO endpoint does not match requiredSsoLocation.", { required: policy.requiredSsoLocation }));
  if (policy.requiredBinding && [...current.services, ...next.services].some((s) => s.binding !== policy.requiredBinding)) findings.push(finding("SAML-BINDING-POLICY", "BLOCK", "An SSO binding does not match requiredBinding.", { required: policy.requiredBinding }));
}

function inspectMetadata(metadata, evaluationTime, warningDays, findings) {
  if (!metadata.certificates.length) findings.push(finding("SAML-SIGNING-CERT-MISSING", "BLOCK", `${metadata.label} metadata contains no X509Certificate.`));
  const fingerprints = metadata.certificates.map((cert) => cert.fingerprint);
  if (new Set(fingerprints).size !== fingerprints.length) findings.push(finding("SAML-DUPLICATE-CERTIFICATE", "REVIEW", `${metadata.label} metadata repeats a certificate fingerprint.`));
  const weak = metadata.algorithms.filter((algorithm) => /sha1|md5|dsa-sha1/i.test(algorithm));
  if (weak.length) findings.push(finding("SAML-WEAK-SIGNATURE-ALGORITHM", "BLOCK", `${metadata.label} metadata advertises a weak signature algorithm.`, { algorithms: unique(weak) }));
  if (metadata.validUntil) {
    const expiry = Date.parse(metadata.validUntil);
    if (!Number.isFinite(expiry)) findings.push(finding("SAML-METADATA-VALIDUNTIL-INVALID", "REVIEW", `${metadata.label} metadata validUntil is not parseable.`));
    else if (expiry <= evaluationTime) findings.push(finding("SAML-METADATA-EXPIRED", "BLOCK", `${metadata.label} metadata is expired.`, { validUntil: metadata.validUntil }));
    else if (expiry - evaluationTime <= warningDays * 86400000) findings.push(finding("SAML-METADATA-EXPIRY-WINDOW", "REVIEW", `${metadata.label} metadata expires within ${warningDays} days.`, { validUntil: metadata.validUntil }));
  }
}

function acceptance(stage, signerFingerprint) { return stage.includes(signerFingerprint); }

export async function analyzeContract(contract) {
  if (!contract || typeof contract !== "object") throw new Error("Contract JSON object is required");
  const policy = contract.policy || {};
  const evaluationTime = Date.parse(contract.evaluationTime || new Date().toISOString());
  if (!Number.isFinite(evaluationTime)) throw new Error("evaluationTime must be an ISO-8601 timestamp");
  const current = await parseMetadata(contract.currentMetadataXml, "current");
  const next = await parseMetadata(contract.nextMetadataXml, "next");
  const stages = {};
  for (const name of ["current", "overlap", "final"]) {
    const values = contract.trust?.[name];
    if (!Array.isArray(values)) throw new Error(`trust.${name} must be an array of SHA-256 fingerprints`);
    stages[name] = unique(values.map(cleanFingerprint).filter(Boolean));
    if (stages[name].some((fp) => fp.length !== 64)) throw new Error(`trust.${name} contains a non-SHA-256 fingerprint`);
  }
  const findings = [];
  comparePolicy(current, next, policy, findings);
  inspectMetadata(current, evaluationTime, Number(policy.expiryWarningDays ?? 30), findings);
  inspectMetadata(next, evaluationTime, Number(policy.expiryWarningDays ?? 30), findings);
  const oldSigners = unique(current.certificates.map((cert) => cert.fingerprint));
  const newSigners = unique(next.certificates.map((cert) => cert.fingerprint));
  const matrix = [];
  for (const [signer, fingerprints] of [["old", oldSigners], ["new", newSigners]]) {
    for (const fingerprint of fingerprints) {
      matrix.push({ signer, fingerprint, current: acceptance(stages.current, fingerprint), overlap: acceptance(stages.overlap, fingerprint), final: acceptance(stages.final, fingerprint) });
    }
  }
  if (oldSigners.some((fp) => !acceptance(stages.current, fp))) findings.push(finding("SAML-CURRENT-REJECTS-OLD", "BLOCK", "Current trust does not accept every current signing certificate."));
  if ([...oldSigners, ...newSigners].some((fp) => !acceptance(stages.overlap, fp))) findings.push(finding("SAML-OVERLAP-INCOMPLETE", "BLOCK", "Overlap trust must accept every old and new signing certificate."));
  if (newSigners.some((fp) => !acceptance(stages.final, fp))) findings.push(finding("SAML-FINAL-REJECTS-NEW", "BLOCK", "Final trust does not accept every new signing certificate."));
  const retainedOld = oldSigners.filter((fp) => !newSigners.includes(fp) && acceptance(stages.final, fp));
  if (retainedOld.length) {
    const deadline = Date.parse(policy.allowOldInFinalUntil || "");
    const permitted = Number.isFinite(deadline) && evaluationTime <= deadline;
    findings.push(finding("SAML-FINAL-RETAINS-OLD", permitted ? "REVIEW" : "BLOCK", permitted ? "Final trust temporarily retains an old signer inside the declared exception window." : "Final trust retains an old signer beyond policy.", { fingerprints: retainedOld, allowOldInFinalUntil: policy.allowOldInFinalUntil || null }));
  }
  const level = findings.reduce((max, item) => Math.max(max, SEVERITY[item.level]), 0);
  const status = Object.keys(SEVERITY).find((key) => SEVERITY[key] === level);
  const report = {
    schemaVersion: "1.0.0", tool: { name: "saml-certificate-rollover-preflight", version: "0.1.0" },
    status, evaluatedAt: new Date(evaluationTime).toISOString(),
    summary: { blockCount: findings.filter((f) => f.level === "BLOCK").length, reviewCount: findings.filter((f) => f.level === "REVIEW").length, oldSignerCount: oldSigners.length, newSignerCount: newSigners.length },
    metadata: { current: { entityId: current.entityId, validUntil: current.validUntil, services: current.services, fingerprints: oldSigners }, next: { entityId: next.entityId, validUntil: next.validUntil, services: next.services, fingerprints: newSigners } },
    trust: stages, acceptanceMatrix: matrix, findings
  };
  return report;
}

export function toSarif(report) {
  const rules = unique(report.findings.map((f) => f.ruleId)).map((id) => ({ id, shortDescription: { text: id } }));
  return { version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: { driver: { name: report.tool.name, version: report.tool.version, rules } }, results: report.findings.map((f) => ({ ruleId: f.ruleId, level: f.level === "BLOCK" ? "error" : "warning", message: { text: f.message } })) }] };
}

export function toHtml(report) {
  const escape = (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const rows = report.acceptanceMatrix.map((r) => `<tr><td>${escape(r.signer)}</td><td><code>${escape(r.fingerprint)}</code></td><td>${r.current}</td><td>${r.overlap}</td><td>${r.final}</td></tr>`).join("");
  const findings = report.findings.length ? report.findings.map((f) => `<li><strong>${escape(f.level)} ${escape(f.ruleId)}</strong> — ${escape(f.message)}</li>`).join("") : "<li>No findings.</li>";
  return `<!doctype html><meta charset="utf-8"><title>SAML rollover evidence — ${escape(report.status)}</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#172033}code{font-size:12px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd5e0;padding:8px;text-align:left}.PASS{color:#08783e}.REVIEW{color:#9a6200}.BLOCK{color:#b42318}</style><h1 class="${escape(report.status)}">${escape(report.status)} — SAML certificate rollover</h1><p>Evaluated ${escape(report.evaluatedAt)}. Blocks: ${report.summary.blockCount}; reviews: ${report.summary.reviewCount}.</p><h2>Acceptance matrix</h2><table><thead><tr><th>Signer</th><th>SHA-256</th><th>Current</th><th>Overlap</th><th>Final</th></tr></thead><tbody>${rows}</tbody></table><h2>Findings</h2><ul>${findings}</ul>`;
}
