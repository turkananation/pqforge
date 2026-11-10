# Changelog

## 0.4.14

Classical key generation reads `PqRandom`. Background isolates re-enable
`PqFipsMode` and refuse a custom generator. HPKE seal and open refuse an
AEAD other than AES-256-GCM while the flag is on. Sync AES-GCM uses the
same pure-Dart engine as the fast path on little-endian hosts. The CLI
takes `--fips` and `keygen --pbkdf2-iterations`. No `.pqf` / `.pqfs`
wire-format change.

X-Wing, draft-connolly-cfrg-xwing-kem-11, beside the custom hybrid.
No `.pqf` / `.pqfs` wire-format change. 0.4.13 stays the RSA SHA-224
release.

- **`PqXWing`** — 32-byte seed, 1216-byte encapsulation key, 1120-byte
  ciphertext, 32-byte shared secret. The combiner is
  `SHA3-256(ss_M || ss_X || ct_X || pk_X || 5c2e2f2f5e5c)`, label last.
  Known answers are the three draft-11 Appendix C records. A flipped
  ciphertext returns 32 bytes. An ML-KEM encapsulation key that fails
  the coefficient check throws before a ciphertext is returned. An
  all-zero X25519 public key still encapsulates. The expanded ML-KEM
  private key is not returned.
- **`HpkeKem.xWing`** is id `0x647A`. Base and PSK seal and open. Auth
  and authPSK throw before encapsulation. `DeriveKeyPair` is
  `SHAKE256(ikm, 32)` and then the seed. `ephemeralIkm` for this KEM is
  the 64-byte encapsulation seed. The five DHKEMs still take the RFC
  9180 ikm. The suite KDF stays HKDF.
- **`PqHybridAgreementMode.xWing`** is opt-in.
  `encapsulateXWing` and `decapsulateXWing` throw on the default mode.
  `initiate` and `accept` throw on the X-Wing mode. The default
  handshake bytes are unchanged.
- **`pqforge hpke keygen|seal|open`** writes magic `XW01`. `--kem`
  accepts only `xwing`. It is not `encrypt` and not `keygen --kem`.
- **`PqFipsMode`** rejects X-Wing at `PqHpke` and at
  `PqForgeHybridKeyAgreement`. `PqXWing` does not read the flag. X-Wing
  is not a FIPS construction. There is no BoringSSL or OpenSSL
  comparison for `0x647A`.

- **Signature policy is caller-pinned.** `dualVerify`,
  `PqForgeHybridSigner.verify`, and `PqForgeSignatureComposer.verify` default
  to require-both / require-all and return false unless the stored policy is
  exactly that. `hybrid-verify --policy` and `compose-verify --policy` throw
  when the file disagrees. The file cannot widen the check.
- **`PqForgeProfile.resolve`** rejects a built-in name whose KEM or signature
  does not match that profile, so the DEM label cannot diverge from the
  wire KEM.
- **X.509.** Anchor selection uses the first subject match whose key verifies
  the top certificate. A same-DN certificate with a different public key is
  not treated as self-signed, so the anchor's name constraints still apply.
  Permitted `directoryName` values match if any one matches. `validate` takes
  an optional `extendedKeyUsage` list; omitting it still does not check
  purpose.
- **`PqForgeSecureSession`** nonces are a 4-byte per-session salt plus a
  64-bit counter (SP 800-38D §8.2.1). The packet is still
  `nonce || ciphertext || tag`. One session throws after 2^32 messages.
- **`PqForgeHybridKeyAgreement.x25519SharedSecret`** rejects an all-zero
  X25519 share. `initiate` and `accept` use that check. `PqXWing` does not.
- **`aesGcmDecrypt` and `aes128GcmDecrypt`** throw `PqForgeAuthTagException`
  and wipe the output buffer when the tag fails.
- **FIPS mode** makes `PqRsa.signPkcs1` / `signPss` throw for SHA-1 or a
  modulus under 2048 bits. Verify returns false for those inputs and does
  not throw. Outside FIPS mode, SHA-1 and a 1024-bit verify stay legal.
  The mode is not a validated module.
- **Folder unpack** refuses to follow a symlink under the output directory.

## 0.4.13

RSA verification accepts a 1024-bit modulus. No `.pqf` / `.pqfs`
wire-format change. 0.4.12 stays the brainpool and FFDHE release.

- **`PqRsa.verifyPkcs1` and `verifyPss`** accept a 1024, 2048, 3072, or
  4096 bit modulus. RFC 5702 requires a validator to check 1024-bit
  RSASHA256 keys. A 1024-bit modulus used to return false before the
  signature was read. `generateKeyPair` still refuses 1024, 512, and
  8192.
- **`PqRsaHash.sha224`** is PKCS#1 v1.5 and RSASSA-PSS (RFC 8017). The
  DigestInfo is OID `2.16.840.1.101.3.4.2.4`. The default PSS salt is 28
  bytes, so a 1024-bit modulus can hold it. SHA-512 with that default
  salt cannot: the block needs 130 bytes and the modulus has 128.
- A private exponent reduced modulo λ(n), which is what OpenSSL writes,
  still signs. The old check required the φ(n) representative and
  rejected a valid key.
- **`PqEd448`** is RFC 8032 Ed448. 57-byte seed, 57-byte public key,
  114-byte signature. Pure Ed448 uses the empty context, which is what
  DNSSEC algorithm 16 signs. A context of at most 255 bytes is accepted.
  `preHash: true` is Ed448ph (SHAKE256 to 64 bytes). The field is
  twenty-eight 16-bit limbs. The expanded seed is wiped. Not X.509, and
  not a TLS signature scheme.

## 0.4.12

Brainpool and RFC 7919 finite-field agreement. No `.pqf` / `.pqfs`
wire-format change. 0.4.11 stays the SHA-1 release.

- **`PqBrainpool`** — ECDH for brainpoolP256r1, brainpoolP384r1, and
  brainpoolP512r1 (RFC 5639). These are the three brainpool groups
  OpenSSL offers in TLS 1.3, code points 31, 32, and 33 (RFC 8734).
  There is no NIST P-512. The smaller and twisted brainpool curves are
  not TLS groups and are not implemented. Public keys are uncompressed
  SEC1. The shared secret is the x-coordinate. Not constant-time, and
  not a TLS stack.
- **`PqFfdhe`** — RFC 7919 ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144,
  and ffdhe8192. Code points 256 through 260. Public values and shared
  secrets are left-padded to the prime. A public value outside the
  subgroup of order `(p - 1) / 2` is rejected. The random draw is wiped
  with `secureZero`. The exponent is a `BigInt` and is not wiped.
- CI runs the pqcrypto OpenSSL suite against pinned OpenSSL 4.1.0:
  ML-KEM-512/768/1024, ML-DSA-44/65/87, and all 12 SLH-DSA sets. The
  named-group agreement also uses that binary. BoringSSL on this pin
  does not export ML-KEM-512 or ten SLH-DSA sets. `boringssl_pqc`
  covers ML-KEM-768, ML-KEM-1024, ML-DSA-44/65/87, and SLH-DSA
  SHA2-128s and SHAKE-256f.

## 0.4.11

SHA-1 as a digest. No `.pqf` / `.pqfs` wire-format change. 0.4.10 stays
the HPKE release.

- **`PqBytes.sha1`** and **`sha1OfStream`** — RFC 3174, 20 bytes. Collision
  resistance is broken. The function exists because some standards still
  name SHA-1: DNSSEC NSEC3 (RFC 5155) and DS digest type 1 (RFC 4034).
  It is not a signature and not a hash for a new protocol. SHA-256,
  SHA-384, and SHA-512 remain the digests for new work. `PqForgeBytes.sha1`
  is the same function.

## 0.4.10

RFC 9180 HPKE as a public API. No `.pqf` / `.pqfs` wire-format change.
0.4.9 stays the X.509 release. 0.4.8 stays the ChaCha20 keystream release.

- **`PqHpke`** — base, PSK, auth, and authPSK. KEMs: DHKEM(X25519,
  HKDF-SHA256), DHKEM(X448, HKDF-SHA512), DHKEM(P-256, HKDF-SHA256),
  DHKEM(P-384, HKDF-SHA384), and DHKEM(P-521, HKDF-SHA512).
  Key-schedule KDFs: HKDF-SHA256, HKDF-SHA384, and HKDF-SHA512. The KEM
  hash stays the one named by the KEM id. AEADs: AES-128-GCM, AES-256-GCM,
  ChaCha20-Poly1305, and export-only. A sender context seals. A recipient
  context opens. A failed open does not advance the sequence. `export`
  does not use the sequence. P-521 `Nsk` is 66 bytes and `Nsecret` is 64.
  X448 keys are 56 bytes and `Nsecret` is 64. `PqX448` is the RFC 7748
  ladder those X448 calls use. It is not a constant-time implementation.
- Known answers are the RFC 9180 vectors for X25519, X448, P-256, and
  P-521, every mode, HKDF-SHA256 and HKDF-SHA512, and every AEAD including
  export-only. One base vector on each of X25519, X448, and P-521 is
  checked through sequence 256. P-384 is a round trip in every mode; that
  KEM is not in the vector file this release pins. RFC 7748 §6.2 is the
  X448 Diffie-Hellman vector.
- BoringSSL 0.20261020.0 `EVP_HPKE` interop, both directions, base and
  auth, X25519 and P-256, HKDF-SHA256 and HKDF-SHA384, AES-128-GCM,
  AES-256-GCM, and ChaCha20-Poly1305, including `Export`. That public API
  has no PSK setup, no X448, no P-384, no P-521, and no HKDF-SHA512.
- OpenSSL 3.5.9 `OSSL_HPKE` interop, both directions, base, PSK, auth, and
  authPSK, X448 and P-521, HKDF-SHA256 and HKDF-SHA512, and the three
  AEADs, including `Export`. `OSSL_HPKE_keygen` agrees with `DeriveKeyPair`
  on the public key. The peer is `tool/interop/openssl_hpke_peer.c`. CI
  links it to the OpenSSL pin in `pins.env`. That pin's `hpke.h` (OpenSSL
  4.1.0) exports the same calls. This is not an OpenSSL claim for X25519,
  P-256, or P-384, and not a BoringSSL claim for X448 or P-521.
- `dispose` on an `HpkeContext` is best-effort zeroization. It is not a
  claim that the key has left process memory.
- Detached recipes that still serialized only `PqSignatureAlgorithm` now
  accept SLH-DSA the same way artifacts do. `issueToken` / `verifyToken`,
  `appendSignedLogEntry` / `verifySignedLogEntry`, and
  `createIdentityBinding` / `verifyIdentityBinding` take an optional
  `slhDsa:`. Pass exactly one of `algorithm` (ML-DSA) or `slhDsa`. Token
  JSON stays version 1; `signatureAlgorithm` holds either id. An ML-DSA
  token, log, or identity binding is still signed with `preHash: false`,
  so a 0.4.9 token still verifies. SLH-DSA recipe calls use the same
  pre-hash path as `signDocument`. `sign --kind webhook` writes that
  recipe from the CLI (`--event-type`, `--timestamp-ms`). Envelope
  headers, `.pqfs` signatures, and `hybrid-sign` stay ML-DSA-only.
- Signature algorithms are opt-in legs. `compose-sign` / `compose-verify`
  take 2 legs (dual) or 3 (triple): any mix of one ML-DSA, one SLH-DSA,
  and classical Ed25519 / ECDSA-P256 / ECDSA-P384 / ECDSA-P521.
  `--policy require-all` is the default; `accept-any` lets one leg pass.
  `keygen --classical ecdsa-p384` and `--classical ecdsa-p521` emit those
  keys. They are not in the default classical set. `ecdsa-sign` follows
  the key. `hybrid-sign` is still exactly ML-DSA plus one of those
  classical algorithms, now including P-384 and P-521. P-384 and P-521
  ECDSA are not provider methods, so a custom `PqClassicalProvider` does
  not have to implement them. P-521 ECDSA is not a TLS group and not HPKE.
  Not constant-time. No `.pqf` / `.pqfs` change.

## 0.4.9

X.509 certificates and the classical signatures those certificates use.
No `.pqf` / `.pqfs` wire-format change. 0.4.8 stays the ChaCha20 keystream
release.

- **`PqX509`** — DER parse, self-signed or issued mint, one signature check,
  and a path check against caller-supplied anchors. No sockets, no system
  trust store, no AIA, OCSP, or CT. `now` is an argument.
- **`PqEcdsaP384`** — ECDSA P-384 / SHA-384, raw `r || s`, low-S. This is not
  `p384SharedSecret`. That function remains the SecP384r1MLKEM1024 key share.
- **`PqRsa`** — PKCS#1 v1.5 and RSASSA-PSS, SHA-256/384/512. The modulus and
  exponent stay bytes. A `BigInt` is built only after the modulus is 2048,
  3072, or 4096 bits.
- **`PqEd25519`** — synchronous RFC 8032 sign and verify. The field is 16-bit
  limbs so the multiply fits a dart2js-safe integer.
- Depend on `pqcrypto` 0.4.4. That release publishes
  `SlhDsa.generateKeyPairSeeded`. No wire-format change.
- CI builds pinned OpenSSL 4.1.0 and BoringSSL 0.20261020.0 from
  `tool/interop/pins.env` and checks a chain for every signature algorithm
  against both: ECDSA P-256 and P-384, Ed25519, RSA PKCS#1 SHA-256/384/512,
  RSASSA-PSS (hash-length salt, salt 20, and an `id-RSASSA-PSS` public key),
  and ML-DSA-44/65/87. The same job parses a certificate OpenSSL minted for
  each of those. OpenSSL is the conformance oracle. BoringSSL is a second
  verifier, not a second certificate branch: it rejects a PSS salt other
  than the hash length and an `id-RSASSA-PSS` SubjectPublicKeyInfo, so those
  two chains are checked with OpenSSL only. Hash-length PSS with an
  `rsaEncryption` public key is checked against both. The AEAD
  interop harness links that OpenSSL, not the Ubuntu package. The BoringSSL
  install also builds the `bssl` tool, which `cmake --install` requires.
  The chain checker is linked with the C++ driver because `libcrypto.a` is
  C++. `install_ssldirs` puts `openssl.cnf` in `OPENSSLDIR`; `req` will not
  start without it.
- `cert req`, `cert issue`, and `cert sign` match `openssl req` and
  `openssl x509 -req`: `--subj`, repeatable `--addext`, and a PEM private key
  or a keygen secret. A request is a PKCS#10 `CERTIFICATE REQUEST`. Signing a
  request copies its extensions. `cert inspect` prints a certificate, a
  PKCS#10 request, or a private-key PEM (the secret itself is not printed).
  `cert verify` reads PEM or DER.
- Verify accepts the high-S ECDSA encoding OpenSSL and BoringSSL put in a
  certificate. `sign` still emits low-S. Compressed SEC1 points are accepted.
  `id-RSASSA-PSS` public keys and a PSS salt other than the hash length are
  accepted. An omitted salt is the RFC 4055 default, 20. SHA-1 is not.
  `issuerUniqueID` and `subjectUniqueID` parse. Name constraints cover DNS,
  IP, email, URI, and directory names. A name form that cannot be evaluated
  fails closed. `id-pe-tlsfeature` status_request is must-staple: the path
  fails until the caller says an OCSP response was present. Explicit EC
  parameters stay rejected, which is what a browser does.

## 0.4.8

Additive ChaCha20 keystream for QUIC header protection (RFC 9001 §5.4.4).
No `.pqf` / `.pqfs` / `PqForgeSecureSession` wire-format changes.

- **`PqSymmetricPrimitives.chacha20`** — RFC 8439 ChaCha20 keystream.
  32-byte key, 12-byte nonce, caller-supplied 32-bit block counter,
  1..4096 keystream bytes. RFC 8439 §2.3.2 (block count 1) is pinned.
  QUIC takes the first 5 bytes as the header-protection mask: the
  sample's little-endian counter and its last 12 bytes are the nonce.
  Same Dart engine as `chacha20Poly1305Encrypt`, so this runs on
  dart2js. The AEAD is not this function: it forces counter 1 and
  appends a Poly1305 tag.

## 0.4.7

### Fixed

**Argon2id cost parameters are now range-checked before the KDF runs.**
`PqSymmetricPrimitives.argon2id` passed `iterations`, `memoryPowerOf2` and
`lanes` straight into `pc.Argon2Parameters` and `generator.process()` with no
validation, while the adjacent `pbkdf2Sha256` already validated its own
`iterations`. Because a `PqWrappedKey` round-trips through JSON, those
parameters are part of the untrusted input to
`PqForge.unwrapKeyWithPassphrase`: a stored record claiming
`memoryPowerOf2: 30` requested 1 GiB of allocation, and `40` a terabyte, before
any authentication had happened. Anyone able to write one file into a key store
could trigger it.

- `Argon2Limits` — public, authoritative bounds: iterations `1..10`,
  `memoryPowerOf2` `10..20` (1 MiB - 1 GiB), lanes `1..16`, salt at least 8
  bytes. Exposed so a caller holding untrusted parameters can reject them with
  its own typed error before calling the KDF.
- `PqSymmetricPrimitives.argon2id` enforces the bounds and throws `RangeError`.
- `PqForge.unwrapKeyWithPassphrase` additionally validates the stored cost and
  throws `PqForgeException` naming the field, the observed value and the
  permitted range - so callers can tell a malformed record from a wrong
  passphrase, and no `RangeError` leaks out of the service.

No wire-format change. Legal parameters, including the range endpoints, still
derive keys as before.

### Dependencies

- `pqcrypto` `^0.4.2` -> `^0.4.3`. 0.4.3 exports the ML-KEM parameter tables
  (`KyberParams`, `KyberLevel`) from `package:pqcrypto/pqcrypto.dart`, so
  ML-KEM derived sizes become reachable through the same barrel import
  `pqforge` already uses, matching how ML-DSA and SLH-DSA were already exposed.
  No behaviour change; `KyberParams` and `KyberLevel` existed before and were
  only used internally.
- **New dependency: `zeroize` `^0.2.0`.** A leaf package whose only runtime
  dependency is `package:meta`, so this adds no transitive weight.

### Security

**Zeroization now goes through `package:zeroize` instead of hand-rolled wipes.**

Every secret-buffer wipe in `lib/` used `Uint8List.fillRange(0, n, 0)`. That
call is exactly the pattern Dead Store Elimination removes: the buffer is not
read afterwards, so the AOT compiler can prove the writes are dead and elide
them. The wipe silently became a no-op.

- `PqForgeCombiner.wipe` — the library's own zeroization primitive, used by
  roughly ten call sites across the hybrid, multi-recipient, and async
  services — now delegates to `secureZero`. One change covers all of them.
- `PqForgeSecureSession.dispose`, and the unauthenticated-plaintext wipe in the
  PointyCastle AEAD engine's error path, now call `secureZero` directly.
- `PqBytes.constantTimeEquals` now delegates to `zeroize`'s `ctEquals`. The two
  implementations were functionally equivalent (both fold a length XOR and byte
  XORs into an accumulator); `ctEquals` additionally carries the
  `@constantTime` annotation. No behavioural change to any of the eight call
  sites.

`pqcrypto` also exports a `secureZero`, but it is pqcrypto's own hand-rolled
zeroizer rather than the DSE-resistant one. The import in
`lib/src/primitives/pq_primitives.dart` hides pqcrypto's, so the name always
binds to `package:zeroize`'s implementation.

**`checkEncapsulationKey` no longer wipes the ML-KEM ciphertext.** Ciphertext is
public output, not a secret, and is already dead at that point. Wiping it cost
time and implied a sensitivity that does not exist. The shared secret, which is
live key material, is still scrubbed.

`doc/security/CLAIM_BOUNDARY.md` gains a section stating what a wipe does *not*
achieve: it is not erasure, it cannot reach registers, and a value still needed
after the wipe call can be spilled to a second copy the wipe does not cover.


## 0.4.6

Additive AES helpers for QUIC (RFC 9000 header protection, RFC 9001
Initial). No `.pqf` / `.pqfs` / `PqForgeSecureSession` wire-format
changes.

- **`PqSymmetricPrimitives.aesEncryptBlock`** — AES-ECB one 16-byte
  block. Key is 16 (AES-128) or 32 (AES-256) bytes. FIPS 197 C.1 / C.3
  pins. Used by QUIC header protection, not as an AEAD.
- **`PqSymmetricPrimitives.aes128GcmEncrypt` / `Decrypt`** — AES-128-GCM
  (16-byte key, 12-byte nonce, `ciphertext || tag`). QUIC Initial packets
  use this AEAD regardless of the 1-RTT suite. NIST empty-plaintext tag
  pin. Existing AES-256-GCM helpers are unchanged.

## 0.4.5

Sync ChaCha20-Poly1305 is dart2js-safe. No `.pqf` / `.pqfs` /
`PqForgeSecureSession` wire-format changes.

- **`PqSymmetricPrimitives.chacha20Poly1305Encrypt` / `Decrypt`** now use
  `package:cryptography`'s Dart engine (`DartChacha20.poly1305Aead`, 32-bit
  Poly1305) instead of PointyCastle `Poly1305()`. Wire layout is unchanged:
  32-byte key, caller-supplied 12-byte nonce, `ciphertext || tag`. RFC 8439
  §2.8.2 still holds. dart2js can run the helper; PointyCastle cannot
  (IEEE-754 mantissa, `2^53 + 1 == 2^53`).
- **`PqSymmetricPrimitives.supportsChaCha20Poly1305`** — always `true`.
  Callers must not copy PointyCastle's full-width-integer check. The
  PointyCastle **session** engine (`PqForgePointyCastleAeadEngine` ChaCha)
  still needs 64-bit integers; use this helper or
  `PqForgeEngineProvider.nativeCryptography` on dart2js.
- Chrome CI runs the sync ChaCha group under dart2js (RFC vector, round-trip,
  bit-flip, capability). Tests are not skipped.
- **pub.dev score** — `pubspec.yaml` description is 60–180 characters.
  `LICENSE` is SPDX MIT (`TORT`, not `TITLE`; no duplicated "to persons").
  `NOTICE` matches MIT (stale AGPL dual-license text removed).
- **`pqcrypto: ^0.4.2`.** That version ships `doc/cookbook/README.md` in
  the pub.dev archive, so `dart doc` no longer crashes while initializing
  pqcrypto's Cookbook category. Required for pqforge's own documentation
  points.

## 0.4.4

Additive library surface, CLI progress across file operations, and first-class
SLH-DSA keygen/sign/verify. No `.pqf` / `.pqfs` / `PqForgeSecureSession`
wire-format changes.

### Library (pqtransport uplink)

- **`PqBytes.sha512`**, **`PqBytes.sha512OfStream`**, and **`PqBytes.hmacSha512`** — SHA-512 helpers for protocols (e.g. FROST-Ed25519) that need a 512-bit digest facade alongside the existing SHA-256 APIs. Additive only; no wire-format changes.
- **NIST-curve ECDH** — `PqNistEcdh` plus `PqClassicalProvider.p256*` / `p384*` and `PqForgeHybridKeyAgreement.p256SharedSecret` / `p384SharedSecret`. Uncompressed SEC1 (`0x04 || X || Y`); shared secret is the x-coordinate (RFC 8446 / SP 800-56A). Full public-key validation: rejects infinity, all-zero x, missing `0x04`, off-curve points, and out-of-range scalars. Does **not** overload `PqEcdsaP256` (signatures only). Unlocks TLS hybrid groups SecP256r1MLKEM768 / SecP384r1MLKEM1024 for `pqtransport`. Additive; no `.pqf`/`.pqfs` changes. Custom `PqClassicalProvider` implementors must add the four ECDH methods.
- **RFC 5869 HKDF-Extract / Expand** — `PqSymmetricPrimitives.hkdfExtractSha256` / `hkdfExpandSha256` / `hkdfExtractSha384` / `hkdfExpandSha384`, plus `PqBytes.sha384` / `hmacSha384` / `sha384OfStream` and combined `hkdfSha384`. Existing `hkdfSha256` is unchanged. Expand-Label stays in the protocol layer.
- **Sync ChaCha20-Poly1305** — `PqSymmetricPrimitives.chacha20Poly1305Encrypt` / `Decrypt` matching the AES-GCM helper shape (32-byte key, caller-supplied 12-byte nonce, `ciphertext || tag`). Distinct from `PqForgeSecureSession.encrypt` (async, self-nonce, nonce-prepended packet).
- **Concat-only hybrid join** — `PqForgeCombiner.concatenateSharedSecrets` with `PqHybridConcatOrder`. Does not HKDF. `combine()` still always does `classical || PQ` then HKDF. RFC 10024 X25519MLKEM768 must use `pqThenClassical` and must **not** call `combine()`.
- **`PqKemPrimitives.checkEncapsulationKey`** — FIPS 203 §7.2 modulus check as a `bool` before encapsulate (length + pqcrypto validation). Does not reimplement ML-KEM.

### SLH-DSA (FIPS 205) — keygen, custody, and detached sign/verify

`pqforge` composes all 12 FIPS 205 parameter sets from `pqcrypto` into
application key material:

- **`PqSlhDsaAlgorithm`** — SHA-2 and SHAKE × 128s/128f/192s/192f/256s/256f,
  with sizes matching `SlhDsaParams`.
- **`PqSlhDsaPrimitives`** and **`PqForge.generateSlhDsaKeyPair`** /
  **`signSlhDsa`** / **`verifySlhDsa`**. Recipe helpers (`signDocument`,
  `signText`, `signMedia`, `signWebhook`, `signArtifact` and their verify
  twins) accept an optional `slhDsa:` parameter. Slow `s` sets still require
  `allowSlowSigning` at the primitive layer, matching `pqcrypto`.
  `issueToken`, signed logs, and identity bindings stay ML-DSA because they
  serialize `PqSignatureAlgorithm`.
- **`keygen`** emits a profile-matched SHAKE-f key by default (`compact` →
  SLH-DSA-SHAKE-128f, `balanced` → 192f, `maximum` → 256f) as
  `<key-id>.slh-dsa-shake-<n>f.{public,secret}.json`, next to the ML-KEM/ML-DSA
  bundle and classical keys. `--slh-dsa` selects specific sets, `--no-slh-dsa`
  skips them, `--slh-dsa-only` emits only SLH-DSA. Secrets wrap through the
  same Argon2id + AES-256-GCM path as ML-DSA.
- **`sign` / `verify`** accept SLH-DSA keys (same `signature-public` /
  `signature-secret` kinds, distinguished by `algorithmId`).

**Still ML-DSA-only:** envelope headers, `.pqfs` streaming signatures, and
`hybrid-sign` / `hybrid-verify`. SLH-DSA signatures are 8–50 KiB and the `s`
sets are slow; those workflows stay compact ML-DSA. Passing an SLH-DSA key as
`--signer-secret` on encrypt/hybrid-sign is rejected with a clear error.

`SlhDsa` / `SlhDsaParams` / `SlhDsaPreHash` remain re-exported from `pqcrypto`.

### CLI

- **Progress** — `encrypt`, `decrypt`, `encrypt-text`, `decrypt-text` (when `--out` is set), `encrypt-media`, `decrypt-media`, `encrypt-folder`, `decrypt-folder`, `pack`, `unpack`, `sign`, `verify`, `hybrid-sign`, `hybrid-verify`, `ecdsa-sign`, and `ecdsa-verify` print a live, throttled progress line. Folder jobs forward streaming byte progress from background isolates over a `SendPort` (callbacks are not isolate-sendable); concurrent files keep separate live totals and the CR line aggregates them. Pack/unpack report per-entry and in-entry bytes. `--digest` hybrid/ECDSA signing reports hashing progress. `keygen` reports per-key wrapping progress when a passphrase is used. A folder job that fails any file exits non-zero. Pack/unpack failures before the first entry report a job-level failure instead of a success summary. Throughput is measured from finished bytes, not started ones.
- **`--quiet` / `-q`** — mutes line-by-line file summaries and skip warnings. Honored on the progress commands and on `keygen`. The completion summary still prints. `keygen --quiet` still prints the raw-secret warning. `decrypt-text` without `--out` never attaches a progress line, so piped plaintext stays clean.
- **Skippable entries** — folder listing skips sockets, FIFOs, broken
  symlinks, and unreadable files (warns unless `--quiet`) instead of failing
  the whole tree.

### What 0.4.4 enables

- `pqtransport` TLS 1.3 hybrid groups (SecP256r1MLKEM768, SecP384r1MLKEM1024, RFC 10024 X25519MLKEM768) without reimplementing ECDH, HKDF-Extract/Expand, sync ChaCha20-Poly1305, concat combiners, or ML-KEM encapsulation-key checks.
- Protocol facades (SHA-384/SHA-512, HMAC-SHA-384/512) for TLS, QUIC, and FROST-style constructions.
- SLH-DSA key generation, custody, and detached signatures through the same CLI and facade as ML-DSA.
- Live progress on encrypt/decrypt/text/media/folder/pack/unpack/sign/verify/hybrid-sign/ecdsa-sign, including isolate-forwarded byte progress on folder jobs and wrapping progress on `keygen`.

### CI

- **pub.dev** — `.github/workflows/publish.yml` publishes the package on `vX.Y.Z` tags using GitHub Actions OIDC (no long-lived pub token). Enable it once on the [package admin page](https://pub.dev/packages/pqforge/admin): repository `turkananation/pqforge`, tag pattern `v{{version}}`, GitHub Actions environment name `pub.dev` (not the workflow filename). The job uses `environment: pub.dev`. The existing `release.yml` still attaches AOT CLI binaries on the same tags.

## 0.4.3

Update pqcrypto to `^0.4.1`. That version ships FIPS 205 SLH-DSA (all 12 parameter sets). pqforge re-exports them through `package:pqcrypto/pqcrypto.dart` but does not compose them into `keygen`, envelopes, recipes, or `hybrid-sign`. No cryptographic or wire-format changes; existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

## 0.4.2

Minor fixes and documentation: Exported more files from the library for external use. No cryptographic or wire-format changes; existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

## 0.4.1

Minor fixes and documentation. No cryptographic or wire-format changes; existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

## 0.4.0

Prepare to land SLH-DSA from pqcrypto into pqforge. No cryptographic or wire-format changes; existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

## 0.3.0

Swappable **classical** backend — the hardware-acceleration seam for the hybrid
stack. Additive and backward-compatible: the default stays pure-Dart and all
`.pqf`/`.pqfs` containers and wire formats are unchanged.

- New `PqClassicalProvider` seam (the classical counterpart to
  `PqLatticeProvider`): X25519 key agreement, Ed25519 and ECDSA-P256 signatures.
  Register a native backend once at startup via `PqClassical.provider = ...`; the
  default is `PqPureDartClassicalProvider` (`package:cryptography` + PointyCastle).
- The **entire** classical half of the hybrid stack now delegates to
  `PqClassical.provider`: `PqForgeHybridSigner`, the static
  `PqForgeHybridKeyAgreement.x25519SharedSecret`, **and** the live-keypair
  `PqForgeHybridKeyAgreement.generateClassicalKeyPair`/`initiate`/`accept`
  handshake (X25519 keygen + both ECDH sides). A host (e.g. an FFI binding to
  AWS-LC) can therefore hardware-accelerate the full hybrid handshake — matching
  the existing lattice seam. Behaviour is unchanged on the default provider
  (same `package:cryptography` under the seam), and because X25519 ECDH is
  deterministic a native backend agrees byte-for-byte.
- New conformance/agreement harness `test/support/classical_conformance.dart`:
  X25519 ECDH and Ed25519 (RFC 8032) must be byte-identical across backends;
  ECDSA-P256 is cross-verified, since its signatures are implementation-dependent
  (pqforge uses RFC-6979; a native backend may be randomized).

## 0.2.2

CLI lifecycle and developer tooling. No cryptographic or wire-format changes;
existing `.pqf`/`.pqfs` containers and library APIs are unchanged.

- The CLI version is single-sourced from `pubspec.yaml`. `bin/src/version.g.dart`
  is generated by `tool/version/generate_version.dart` and powers `pqforge
  --version`, the new `pqforge version` subcommand, and the banner. A `--check`
  mode and a unit test fail if it drifts. The visibility/site version is read
  from `pubspec.yaml` too, so the manifest no longer carries a version.
- New `pqforge uninstall` command removes pqforge however it was installed: it
  runs `dart pub global deactivate pqforge` for a global pub install (with
  `--dry-run` and `--yes`), or prints the executable path to delete for a
  standalone binary. It never blocks for input in non-interactive shells.
- Added a repeatable local/CI verification runner, `tool/agent/verify.dart`
  (`quick`/`docs`/`full`/`release`), with package-boundary, Markdown-link, and
  pub.dev archive checks. `.pubignore` now limits the published archive to the
  runtime package (`lib/`, `bin/`, `example/`, and metadata).
- Docs: README and the CLI guide cover pub.dev install, `pqforge uninstall`, and
  `pqforge version`.

## 0.2.1

Documentation, discovery, and site release. No library or CLI behavior changes
— only the version string moves (`pubspec.yaml`, `pqforgeCliVersion`).

- Docs realigned to the as-shipped v0.2.0 surface: the CLI guide now covers
  auto-streaming (`.pqfs` at ≥ 8 MiB), `pack`/`unpack`, multi-recipient and
  hybrid encryption, `--cipher`/`--engine`, digest signing, and `inspect`, and a
  stale "no multi-GB streaming" note was removed. `doc/INDEX.md` now maps every
  document, and the hybrid audit lists the full v0.2.0 command set.
- Fixed published links that pointed at a feature branch: generated discovery
  files and the site now build repository links from `main`, driven by
  `repository_branch` in the visibility manifest. Also repaired two dead
  doc links and removed a non-portable local path from the audit notes.
- Surfaced the `pqcrypto` relationship and differentiation: a new README section
  and `pqforge-vs-pqcrypto` wiki page, a "Relationship to pqcrypto" block in
  `llms.txt`/`llms-full.txt`, and `isBasedOn` structured data in `identity.json`.
- Expanded the LLM/AI discovery surface: `faq-ai.txt` grew from 5 to 21 Q&As,
  with richer capabilities, recipes, and keywords.
- Expanded the wiki (new Streaming, Multi-Recipient, Performance, and
  pqforge-vs-pqcrypto pages; refreshed Home, CLI, sidebar, and recipe catalog).
- GitHub Pages site: prominent pub.dev / Wiki / GitHub / pqcrypto links, inline
  SVG icons, hero badges, and SEO/discovery metadata (Open Graph, Twitter card,
  keywords, canonical, and a `FAQPage` JSON-LD block).
- Added `CLAUDE.md` and a `pqforge-docs` skill that keep documentation aligned
  to the code (verify-against-source, generated-vs-hand-maintained split, claim
  boundary, and the `main`-branch link rule).

## 0.2.0

Post-quantum + classical hybrid encryption, bounded-memory gigabyte-scale
streaming, multi-recipient envelopes, selectable AEAD suites, and a ~10×
faster default engine — all on the pure-Dart, web-safe core.

### Hybrid (ML-KEM + X25519) encryption

- End-to-end hybrid KEM-DEM: the DEM key is the IETF concatenate-then-KDF
  combination of the ML-KEM shared secret and an ephemeral X25519 exchange
  (`PqHybridKemDem`), so confidentiality holds while *either* Module-LWE or
  Curve25519 stands. The self-describing `hybridKex` metadata marker is
  KDF-bound (tampering flips the derived key, so the first AEAD tag check
  fails even on unsigned envelopes), needs no container-format change, and is
  shared verbatim by the one-shot and `.pqfs` streaming paths.
- `PqForge.encryptAsync`/`decryptAsync` — one-shot envelope encryption over any
  `PqForgeAeadEngine`, with optional hybrid keys; hybrid is auto-detected on
  decrypt. Output stays byte-compatible with the sync paths.
- CLI: `--hybrid` (or `--recipient-x25519-public`) on every encrypt command;
  decrypt auto-detects and finds the conventional
  `<key-id>.x25519.secret[.wrapped].json` next to `--recipient-secret`
  (override `--recipient-x25519-secret`).

### Multi-recipient envelopes

- Encrypt to N recipients with one ciphertext and **no wire-format change**:
  the payload is sealed exactly once and the DEM key is wrapped to each
  additional recipient as a `recipients[]` metadata entry (`PqMultiRecipient`,
  `PqRecipientSpec`; ~1.6 KB + ~2 ms per extra recipient instead of a full
  re-encryption). Entries may individually be hybrid (own ephemeral X25519),
  `recipientKeyId` routes openers straight to their entry, and the scheme works
  identically for one-shot envelopes and `.pqfs` streams. CLI:
  `--recipient-public` is repeatable on `encrypt`, `encrypt-folder`,
  `encrypt-text`, `encrypt-media`, and `pack` (first = primary).

### Selectable AEAD suite

- `--cipher chacha20-poly1305` on the encrypt commands. A non-default suite is
  recorded as a tamper-evident `aeadSuite` marker and every open path rebuilds
  its engine to match — no decrypt flag needed. Pure-Dart ChaCha measures
  ~30.4 MiB/s vs ~11.5 MiB/s AES-256-GCM (2.6×), the bulk recommendation
  wherever hardware AES is not dispatched; AES output stays marker-free and
  byte-compatible with prior releases. FIPS mode still rejects ChaCha.

### Performance & memory

- Bounded-memory streaming envelope (`.pqfs`) for gigabyte-scale files: a
  signed master header followed by independently authenticated frames (per-frame
  `seq`/`isFinal` AAD binding prevents truncation, reordering, duplication, and
  splicing). Peak memory is a small, file-size-independent working set.
- `package:cryptography` is the default AEAD engine for all bulk paths (~10×
  the PointyCastle throughput even in pure Dart; hardware-backed on Flutter via
  `FlutterCryptography.enable()`). `--engine cryptography|pure-dart` on every
  bulk command; wire formats are engine-independent. `encryptAsync`/
  `decryptAsync` extend the speedup to sub-8 MiB one-shot files, which
  previously ignored `--engine`.
- Streaming I/O is pipelined: `encryptFile` double-buffers (the next frame's
  read overlaps the current frame's seal+write) and `decryptStream` prefetches
  one frame; failure-cleanup semantics are unchanged.
- Envelope signatures are computed over `SHA-256(header ‖ SHA-256(payload))`
  with `preHash:true`, so signing cost and memory no longer scale with payload
  size.
- `keygen` wraps secret keys on a bounded isolate pool (`--wrap-concurrency`,
  default 2); folder commands process files concurrently via a bounded per-file
  isolate pool (`--concurrency`).
- `pqforge pack` / `pqforge unpack`: collapse a whole folder into one encrypted
  streaming archive (a single KEM encapsulation and signature for the tree) and
  restore it path-traversal-safe. Both stream end to end — no plaintext temp
  spool, no extra disk need — and a failed unpack removes everything it created.

### Signing

- Digest-mode signing: `hybrid-sign --digest` / `ecdsa-sign --digest` sign the
  streamed SHA-256 of the input (`PqBytes.sha256OfStream`, O(1) memory for
  gigabyte artifacts) under a domain-separation label, recorded in the
  signature JSON so the verify commands re-hash automatically.
- Independent `--kem` / `--sig` overrides so a strong KEM can pair with a
  lighter signature (the custom profile round-trips through both formats).

### Keys & CLI

- `keygen` generates the full hybrid keyset by default — ML-KEM + ML-DSA plus
  X25519, Ed25519, and ECDSA-P256 — so hybrid workflows work out of the box.
  `--classical` narrows the set; `--no-classical` keeps PQC-only.
- Every encrypt/decrypt prints the combination in effect (e.g.
  `suite ML-KEM-1024 + X25519 → HKDF-SHA-512 → ChaCha20-Poly1305`, plus
  `engine`/`signature`/`recipients` lines). New `pqforge inspect` describes any
  `.pqf`/`.pqfs`/key/signature file without decrypting it.

### Hardening & FIPS

- Caller metadata can no longer spoof any reserved container marker
  (`hybridKex`, `aeadSuite`, `recipients`, `recipientKeyId`) on any encrypt
  path.
- Streaming reader hardened against hostile containers (header/signature length
  caps enforced before allocation); NIST SP 800-38D 2³² frames-per-key bound
  enforced in nonce derivation.
- FIPS deployment layer: `PqFipsMode` (AES-256-GCM-only suites, PBKDF2-only
  wrapping when enabled), PBKDF2-HMAC-SHA256 key wrapping (SP 800-132), and a
  swappable `PqRandom.generator` for validated-module DRBGs.

### Web & portability

- The `.pqfs` codec is dart2js-safe: frame counters encode as two uint32 halves
  (`PqBytes.uint64`/`readUint64`, byte-identical wire format), and
  `PqStreamingEnvelope` ships in the core web-safe umbrella. Only the `dart:io`
  file plumbing (`PqForgeStreamCipher`) remains VM/native-only.
- Swappable lattice backend (`PqLatticeProvider`, `PqLattice.provider`) with the
  pure-Dart implementation as default and a reusable conformance / KAT harness.

### Tooling & CI

- `.github/workflows/release.yml`: `dart compile exe` binaries for
  linux-x64/macos-arm64/windows-x64 with SHA-256 checksums on `v*` tags.
- `tool/openssl_interop` (its own `publish_to: none` package, excluded from the
  published archive): proves both AEAD suites on both engines byte-identical
  with the system OpenSSL (cross-seal/open + tamper, enforced in CI) and
  measures the hardware ceiling. The published package contains no `dart:ffi`.
- CI enforces a streaming peak-RSS regression gate (1.5× amplification at
  64 MiB), repo-wide `dart format`/`analyze`, and a full CLI smoke.

### Documentation

- As-built performance/hybrid record and recommendation tracker:
  `doc/technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md`.

## 0.1.0

- Added algorithms, primitives, codecs,keys, recipes and service layers.
- Added binary and JSON envelope v1 formats.
- Added combined key bundles, portable key-store interfaces passphrase key wrapping, document signing, encrypted records/files, signed logs, identity bindings, artifact signing, dual-signature combiners, and isolate DTOs.
- Added the `/doc` documentation system, CI workflow, and expanded tests.
- Added typed ML-KEM, ML-DSA and SLH-DSA profiles for compact, balanced, and maximum parameter choices.
- Added ML-DSA detached signatures, ML-KEM KEM-DEM sealing/opening, signed encrypted envelopes, HKDF-SHA256 hybrid session derivation, AES-GCM helpers,transcript framing utilities, and strict byte-length checks.
- Added segmented examples and focused composition tests.
