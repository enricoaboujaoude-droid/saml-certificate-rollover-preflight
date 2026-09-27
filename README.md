# SAML Certificate Rollover Preflight

[![CI](https://github.com/enricoaboujaoude-droid/saml-certificate-rollover-preflight/actions/workflows/test.yml/badge.svg)](https://github.com/enricoaboujaoude-droid/saml-certificate-rollover-preflight/actions/workflows/test.yml) [![Release](https://img.shields.io/github/v/release/enricoaboujaoude-droid/saml-certificate-rollover-preflight)](https://github.com/enricoaboujaoude-droid/saml-certificate-rollover-preflight/releases/latest) [![Downloads](https://img.shields.io/github/downloads/enricoaboujaoude-droid/saml-certificate-rollover-preflight/total)](https://github.com/enricoaboujaoude-droid/saml-certificate-rollover-preflight/releases)

Prove a SAML IdP signing-certificate rollover before it breaks enterprise SSO. This deterministic, browser-local tool compares current and next IdP metadata against **current → overlap → final** SP trust sets and emits an old/new signer acceptance matrix.

It blocks when current trust rejects the old signer, overlap does not accept both signer sets, final rejects the new signer, or final retains an old-only signer beyond policy. It also detects unexpected `entityID`, SSO endpoint, binding, weak-algorithm, duplicate-certificate, metadata-expiry, and private-key changes.

## Use it

Canonical local CLI command:

```bash
npx --yes github:enricoaboujaoude-droid/saml-certificate-rollover-preflight examples/safe/contract.json --json
```

GitHub Action:

```yaml
- uses: enricoaboujaoude-droid/saml-certificate-rollover-preflight@v0.1.0
  with:
    contract: saml-rollover.json
```

The Action writes canonical JSON and SARIF evidence. The static `index.html` performs the same analysis in the browser; inputs never leave the device.

## Download

The [v0.1.0 release](https://github.com/enricoaboujaoude-droid/saml-certificate-rollover-preflight/releases/tag/v0.1.0) contains the npm-compatible TGZ, a complete source ZIP, and SHA-256 checksums. After downloading the TGZ:

```bash
npx ./saml-certificate-rollover-preflight-0.1.0.tgz examples/safe/contract.json --json
```

## Contract

Start with [`examples/safe/contract.json`](examples/safe/contract.json). CLI and Action contracts may reference metadata with `currentMetadataPath` and `nextMetadataPath`. Browser contracts embed the same XML as `currentMetadataXml` and `nextMetadataXml`.

Trust values are SHA-256 certificate fingerprints. `evaluationTime` should be pinned in CI for reproducible evidence. A bounded `policy.allowOldInFinalUntil` exception creates REVIEW before its deadline and BLOCK afterward.

## Evidence and status

- `PASS`: no finding.
- `REVIEW`: a bounded exception or warning requires human confirmation.
- `BLOCK`: the staged trust contract cannot safely complete.
- Exit codes: `0` PASS/REVIEW, `1` BLOCK, `2` invalid input.
- Outputs: canonical JSON, standalone HTML, and SARIF 2.1.0.

Safe and incident fixtures contain public test certificates only. Never paste private keys; the parser rejects PEM private-key markers and raw XML key values.

## Troubleshooting

See [SAML signature validation failed after certificate rotation](docs/saml-signature-validation-failed-after-certificate-rotation.md), including the ADFS rollover path.

## Scope

Version 0.1.0 does one job: offline staged signing-certificate rollover proof. It has no SAML response validator, live IdP fetch, secrets, auth, backend, database, monitoring, billing, or AI.

MIT licensed. Runtime and hosting cost: $0.
