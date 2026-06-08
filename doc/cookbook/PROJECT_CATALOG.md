# pqforge Project Catalog

This catalog maps product ideas to the tested `pqforge` recipe surface. Each
entry names what the package gives you and what the application still owns.

## Local And Server File Vaults

Use for developer secrets, operator laptops, scheduled backup jobs, and server
batch exports.

- Use: `keygen`, `encrypt`, `decrypt`, `encryptFileBytes`, `decryptFileBytes`.
- Use maximum profile when the confidentiality lifetime is long.
- Store secret keys as wrapped JSON, not raw exported keys.
- You supply storage policy, backup policy, and recovery.

## Folder Archives

Use for case folders, document bundles, release directories, evidence packages,
and internal archive exports.

- Use: `encrypt-folder`, `decrypt-folder`, `encryptFolderEntry`,
  `decryptFolderEntry`.
- Each file is encrypted independently and keeps its relative path in AAD.
- You supply inclusion/exclusion rules, streaming for large files, and archive
  lifecycle.

## Text Snippets And Notes

Use for short secrets, prompts, memos, policy snippets, and admin notes.

- Use: `encrypt-text`, `decrypt-text`, `sealText`, `openText`, `signText`,
  `verifyText`.
- Text is UTF-8 and bound to a stable text id.
- You supply classification and storage.

## Media And PDFs

Use for images, audio, video, PDFs, campaign media, identity images, and
inspection artifacts.

- Use: `encrypt-media`, `decrypt-media`, `sealMedia`, `openMedia`, `signMedia`,
  `verifyMedia`.
- Media id and MIME type are bound into recipe messages.
- You supply MIME classification and storage policy.

## Document Approval And E-Signature Workflows

Use for contracts, forms, reports, approvals, certificates, policy documents,
and public notices.

- Use: `sign --kind document`, `verify`, `signDocument`, `verifyDocument`.
- Document id, hash, and length are signed.
- You supply legal policy, signer identity vetting, document canonicalization,
  and user experience.

## Signed Webhooks

Use for payment callbacks, server-to-server notifications, audit delivery, and
integration events.

- Use: `signWebhook`, `verifyWebhook`.
- Event type, timestamp, and payload hash are signed.
- You supply replay protection, timestamp windows, and verification-key
  distribution.

## Signed Tokens

Use for API capability tokens, short-lived grants, admin commands, and service
handoffs.

- Use: `issueToken`, `verifyToken`.
- Claims are canonicalized before signing.
- You supply authorization policy, revocation, and key rotation.

## Private Email Payloads

Use for secure notification bodies, encrypted mail archives, and private
outbound message payloads.

- Use: `sealEmail`, `openEmail`.
- Message id is bound into AAD.
- You supply transport handling and metadata minimization.

## Government And Medical Records

Use for registries, health records, incident records, case files, and long-lived
public-sector archives.

- Use: `encryptRecord`, `appendSignedLogEntry`, `verifySignedLogEntry`.
- Prefer maximum profile for long confidentiality lifetimes.
- You supply access control, retention policy, audit policy, and legal process.

## Signed Software Artifacts

Use for release bundles, firmware, packages, configuration pushes, and internal
deployment manifests.

- Use: `sign --kind artifact`, `signArtifact`, `verifyArtifact`.
- Sign version and artifact hash to reduce rollback risk.
- You supply target metadata, release channel, and signing-key custody.

## Hybrid Server Sessions

Use for Serverpod backends, API services, local agents, or server-to-server
session bootstrapping.

- Use: `PqForgeHybridKeyAgreement`, `PqForgeCombiner`,
  `PqForgeSecureSession`.
- X25519 and ML-KEM are combined before traffic keys are used.
- You supply authenticated public-key bundles, replay stores, session storage,
  authorization, and transport policy.
