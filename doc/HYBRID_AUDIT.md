# pqforge Hybrid Coverage Audit

Last updated: 2026-06-07

This audit reconciles `pqforge` against the local
`/home/turkananation/Projects/PQC/pqcrypto` repository, especially:

- `doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md`
- `doc/cookbook/BUILDING_BLOCKS.md`
- `doc/cookbook/PROJECT_CATALOG.md`
- `doc/cookbook/FUTURE_RELEASES.md`

## Evidence Summary

`pqcrypto` 0.3.1 is pure post-quantum cryptography: ML-KEM, ML-DSA, SHA-2,
SHA-3/SHAKE building blocks, and zero runtime dependencies. Its local source
does not expose classical KEX/signatures, AES, ChaCha20-Poly1305, or RC4.

`pqforge` supplies the composition layer around that boundary:

| Dimension | Current pqforge coverage |
| --- | --- |
| ML-KEM | 512, 768, 1024 through `PqKemAlgorithm` |
| ML-DSA | 44, 65, 87 through `PqSignatureAlgorithm` |
| KEM-DEM encryption | `encrypt`, `decrypt`, `sealToKemPublicKey`, file/record/email/text/media/folder helpers |
| Signatures | raw signatures, documents, text, media, webhooks, artifacts, logs, tokens |
| Hybrid KDF | `PqForgeCombiner`, `deriveHybridSessionKey` |
| Built-in hybrid KEX | X25519 + ML-KEM through `PqForgeHybridKeyAgreement` |
| Built-in hybrid signatures | ML-DSA + Ed25519 through `PqForgeHybridSigner` |
| App-supplied hybrid signatures | `dualSign` / `dualVerify` for ECDSA or any other verifier |
| AEAD | AES-256-GCM and ChaCha20-Poly1305 |
| CLI | `dart run pqforge keygen/encrypt/decrypt/encrypt-folder/decrypt-folder/encrypt-text/decrypt-text/encrypt-media/decrypt-media/sign/verify` |

## Rejections And Boundaries

### RC4

RC4 is rejected. It is not post-quantum, not authenticated encryption, not in
`pqcrypto`, and not safe for new systems. Adding it would contradict the
package's security claim. Users who need encryption choices get AES-256-GCM and
ChaCha20-Poly1305.

### `signWithAES`

AES is not a signature algorithm. Helpers are named by operation:

- Sign/authenticate: `signDocument`, `signText`, `signMedia`, `signWebhook`,
  `signArtifact`, `issueToken`, `PqForgeHybridSigner`.
- Encrypt/confidentiality: `encryptFileBytes`, `sealText`, `sealMedia`,
  `sealEmail`, `encryptRecord`, `encryptFolderEntry`, `PqForgeSecureSession`.

### ECDSA P-256

`cryptography 2.9.0` exposes `Ecdsa.p256`, but on the Dart VM its key generation
path throws `UnimplementedError`. Since `pqforge` targets local CLI and servers,
ECDSA is not advertised as a built-in path. Projects that already have an ECDSA
stack can still use `dualSign` / `dualVerify` by supplying the classical
signature and verifier.

### SLH-DSA

The local `pqcrypto` roadmap lists SLH-DSA (FIPS 205) for future releases. It is
not shipped in `pqcrypto` 0.3.1, so `pqforge` cannot expose it yet. When
`pqcrypto` ships it, add it as a new signature family with explicit docs and
tests; do not overclaim ahead of the dependency.

## Building Blocks Mapping

| pqcrypto block | pqforge surface |
| --- | --- |
| BB1 detached signatures | `sign`, `verify`, `signDocument`, `signText`, `signMedia`, `signWebhook`, `issueToken` |
| BB2 encrypt to public key | `encrypt`, `decrypt`, `sealToKemPublicKey`, `PqEnvelope` |
| BB3 hybrid authenticated handshake | `PqForgeHybridKeyAgreement`, `PqForgeCombiner` |
| BB4 identity enrollment | `createIdentityBinding`, `verifyIdentityBinding` |
| BB5 deterministic keys | `generateSignatureKeyPairFromSeed`, key export/wrapping |
| BB6 signed log | `appendSignedLogEntry`, `verifySignedLogEntry` |
| BB7 signed artifacts | `signArtifact`, `verifyArtifact` |
| BB8 encrypted data at rest | `encryptFileBytes`, `encryptRecord`, `sealEmail`, `sealText`, `sealMedia`, `encryptFolderEntry`, CLI file/folder/text/media encryption |
| BB9 hybrid/dual signatures | `PqForgeHybridSigner`, `dualSign`, `dualVerify` |
| BB10 offloading | `PqOffloadRequest`, `PqOffloadResponse` |

## Verification Expectations

Run:

```bash
dart analyze
dart test
dart run example/hybrid_key_agreement_example.dart
dart run example/catalog_recipes_example.dart
export PQFORGE_PASSPHRASE='use-a-real-secret-manager-value'
dart run pqforge keygen --profile compact --key-id smoke --out-dir /tmp/pqforge-keys --passphrase-env PQFORGE_PASSPHRASE
dart run pqforge encrypt-folder --recipient-public /tmp/pqforge-keys/smoke.kem.public.json --in-dir ./example --out-dir /tmp/pqforge-example.pqf
```

Do not commit generated `doc/api/` HTML; it is ignored build output.
