# pqforge Hybrid Coverage Audit

Last updated: 2026-09-17

This audit reconciles `pqforge` against the
[`pqcrypto`](https://pub.dev/packages/pqcrypto) primitives package
([repository](https://github.com/turkananation/pqcrypto)) — what `pqforge`
composes on top of it, and the boundaries it deliberately keeps. For the
plain-language version, see the
[pqforge vs pqcrypto](https://github.com/turkananation/pqforge/wiki/pqforge-vs-pqcrypto)
wiki page.

## Evidence Summary

`pqcrypto` 0.4.1 is pure post-quantum cryptography: ML-KEM (FIPS 203), ML-DSA
(FIPS 204), SLH-DSA (FIPS 205, all 12 parameter sets), SHA-2, SHA-3/SHAKE
building blocks, and zero runtime dependencies. It does not expose classical
KEX/signatures, AES, ChaCha20-Poly1305, or RC4.

`pqforge` supplies the composition layer around that boundary. It **re-exports**
the full `pqcrypto` API (`export 'package:pqcrypto/pqcrypto.dart'`), including
`SlhDsa` / `SlhDsaParams` / `SlhDsaPreHash`. It **composes** ML-KEM and ML-DSA
into envelopes, recipes, `keygen`, and hybrid signatures. It does **not**
compose SLH-DSA into those workflows.

| Dimension | Current pqforge coverage |
| --- | --- |
| ML-KEM | 512, 768, 1024 through `PqKemAlgorithm` |
| ML-DSA | 44, 65, 87 through `PqSignatureAlgorithm` |
| SLH-DSA | Re-exported from `pqcrypto` (`SlhDsa`). **Not** in `PqSignatureAlgorithm`, `keygen`, envelopes, recipes, or `hybrid-sign` |
| KEM-DEM encryption | `encrypt`, `decrypt`, `sealToKemPublicKey`, file/record/email/text/media/folder helpers |
| Signatures | raw ML-DSA signatures, documents, text, media, webhooks, artifacts, logs, tokens |
| Hybrid KDF | `PqForgeCombiner` (`combine` = classical\|\|PQ then HKDF); `concatenateSharedSecrets` (concat only, for RFC 10024) |
| Built-in hybrid KEX | X25519 + ML-KEM through `PqForgeHybridKeyAgreement`; P-256/P-384 ECDH through `PqNistEcdh` (TLS hybrid groups, not the X25519 handshake) |
| Built-in hybrid signatures | ML-DSA + Ed25519 **or ECDSA-P256** through `PqForgeHybridSigner` |
| Built-in classical signatures | ECDSA-P256 (`PqEcdsaP256`, pure-Dart PointyCastle, RFC 6979, low-S) — `ecdsa-sign`/`ecdsa-verify` |
| App-supplied hybrid signatures | `dualSign` / `dualVerify` for any other classical verifier callback |
| AEAD | AES-256-GCM and ChaCha20-Poly1305 on a pure-Dart or native (`package:cryptography`) engine; sync caller-nonce helpers (`PqSymmetricPrimitives.chacha20Poly1305Encrypt`) distinct from `PqForgeSecureSession` |
| KDF / digests | HKDF-SHA-256/384 Extract+Expand (RFC 5869); SHA-256/384/512 and HMAC-SHA-256/384/512 facades |
| KEM check | `PqKemPrimitives.checkEncapsulationKey` — FIPS 203 §7.2 via pqcrypto, no lattice reimplementation |
| Large files | Bounded-memory `.pqfs` streaming (auto ≥ 8 MiB) and `pack`/`unpack` whole-folder archives |
| Multi-recipient | One sealed payload, DEM key wrapped per recipient (`PqMultiRecipient`), no wire-format change |
| CLI | `dart run pqforge keygen/encrypt/decrypt/encrypt-folder/decrypt-folder/encrypt-text/decrypt-text/encrypt-media/decrypt-media/pack/unpack/inspect/sign/verify/hybrid-sign/hybrid-verify/ecdsa-sign/ecdsa-verify`. `encrypt-folder`/`decrypt-folder` report live progress; `--quiet`/`-q` mutes per-file lines; non-regular files are skipped. |

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

ECDSA-P256 **is** a built-in path: `PqEcdsaP256` (pure-Dart PointyCastle, RFC
6979 deterministic nonces, canonical low-S), CLI `ecdsa-sign`/`ecdsa-verify`,
and `PqForgeHybridSigner` with `classicalAlgorithm: ecdsaP256`. `keygen` emits
an ECDSA-P256 keypair in the default hybrid set.

`package:cryptography` `Ecdsa.p256` is **not** used for this path — its Dart VM
key generation throws `UnimplementedError`. pqforge's implementation is the
PointyCastle one. `dualSign` / `dualVerify` remain for other app-supplied
classical schemes.

ECDH over P-256/P-384 is a separate type, `PqNistEcdh`. It does not overload
`PqEcdsaP256`.

### SLH-DSA

`pqcrypto` 0.4.1 ships all 12 FIPS 205 parameter sets. Because pqforge re-exports
`package:pqcrypto/pqcrypto.dart`, this works:

```dart
import 'package:pqforge/pqforge.dart';

final keys = SlhDsa.generateKeyPair(SlhDsaParams.sha2128s);
```

What pqforge does **not** do in 0.4.4:

- `PqSignatureAlgorithm` has only `mlDsa44` / `mlDsa65` / `mlDsa87`.
- `PqPureDartLatticeProvider` signs with `MlDsa` only.
- `keygen` emits ML-KEM + ML-DSA (+ classical), never SLH-DSA.
- Envelopes, recipes, `sign`/`verify`, and `hybrid-sign` are ML-DSA-only.

Do not document SLH-DSA as a composed pqforge workflow. When composition lands,
add it as a new signature family with explicit docs and tests.

## Building Blocks Mapping

| pqcrypto block | pqforge surface |
| --- | --- |
| BB1 detached signatures | `sign`, `verify`, `signDocument`, `signText`, `signMedia`, `signWebhook`, `issueToken` (ML-DSA). `SlhDsa` is available as a re-export. |
| BB2 encrypt to public key | `encrypt`, `decrypt`, `sealToKemPublicKey`, `PqEnvelope` |
| BB3 hybrid authenticated handshake | `PqForgeHybridKeyAgreement`, `PqForgeCombiner`, `PqNistEcdh` |
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
