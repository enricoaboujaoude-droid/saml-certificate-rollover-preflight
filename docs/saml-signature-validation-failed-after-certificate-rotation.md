# SAML signature validation failed after certificate rotation

If SAML login fails immediately after an IdP or ADFS signing-certificate rollover, check the transition as three explicit trust states—not as one certificate replacement.

1. **Current** must accept every signer in the current IdP metadata.
2. **Overlap** must accept every old and new signer while both sides converge.
3. **Final** must accept every new signer and reject old-only signers after the exception window.

Also prove that `entityID`, the SSO endpoint, and the required binding did not change. A signing-certificate rollover should not silently become an endpoint migration.

Run the included safe example:

```bash
npx --yes github:enricoaboujaoude-droid/saml-certificate-rollover-preflight examples/safe/contract.json --json
```

Exit code `0` means PASS or REVIEW; exit code `1` means BLOCK; exit code `2` means invalid input or execution failure. The tool runs locally and rejects private-key material.
