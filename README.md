# SAML Certificate Rollover Preflight

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
