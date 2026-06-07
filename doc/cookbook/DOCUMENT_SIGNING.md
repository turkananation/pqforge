# Document Signing

Use `signDocument` and `verifyDocument` for document-like payloads. The helper
signs a canonical message containing a domain label, document ID, document hash,
and document length.

You supply document canonicalization, legal/e-signature policy, signer identity
vetting, and signature container UX.
