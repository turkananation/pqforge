# Document Signing

Use `signDocument` and `verifyDocument` for document-like payloads. The helper
signs a canonical message containing a domain label, document ID, document hash,
and document length.

The same helpers accept an optional `slhDsa:` parameter for FIPS 205 hash-based
signatures. `keygen` emits a profile-matched SHAKE-f SLH-DSA key next to the
ML-DSA bundle; pass that secret to CLI `sign` / `verify` (`--kind document`,
`text`, `media`, or `artifact`). Envelope headers and `hybrid-sign` stay
ML-DSA-only.

You supply document canonicalization, legal/e-signature policy, signer identity
vetting, and signature container UX.