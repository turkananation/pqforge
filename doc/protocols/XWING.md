# X-Wing

Status: not implemented. No `PqXWing` symbol exists in `lib/`. Target
release: 0.4.14. This page is the contract for that change. It is not a
call that works today.

Specification: [draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).
The construction paper is [ePrint 2024/039](https://eprint.iacr.org/2024/039).

X-Wing is one hybrid KEM. One ML-KEM-768 encapsulation, one X25519, one
shared secret. It is not PQXDH, not the Double Ratchet, and not the
pqforge custom hybrid.

## Lengths

| Field | Length |
| --- | --- |
| Seed and decapsulation key | 32 bytes |
| Encapsulation key | 1216 bytes. ML-KEM-768 public key, then the X25519 public key |
| Ciphertext | 1120 bytes. ML-KEM-768 ciphertext, then the X25519 ephemeral public key |
| Shared secret | 32 bytes |
| Derandomized encapsulation seed (`eseed`) | 64 bytes |

The public-key and ciphertext lengths match the RFC 10024
`X25519MLKEM768` shares. The shared secret does not. X-Wing's secret is
32 bytes from SHA3-256. The TLS hybrid's secret is the 64-byte
concatenation, and the TLS transcript does the rest. Length must not
select the combiner. Decapsulating one ciphertext with the other
algorithm returns a value and it is the wrong value.

## Combiner

```text
SHA3-256(ss_M || ss_X || ct_X || pk_X || 5c2e2f2f5e5c)
```

The six label bytes are last. They are the ASCII bytes of `\./` and `/^\`.
`ct_M` is not an input. `pk_X` is recomputed from the seed on
decapsulation. It is not an argument.

Key generation expands the 32-byte seed with SHAKE256 to 96 bytes: ML-KEM
`d`, ML-KEM `z`, then the X25519 scalar. `pqcrypto` treats a 32-byte ML-KEM
seed as `d` and fills `z` at random, so the implementation passes the
64-byte `d || z`. The X25519 scalar is clamped by X25519, not before it is
stored. The stored secret remains the 32-byte seed.

`eseed` splits as ML-KEM encapsulation coins, then the X25519 ephemeral
scalar. The first 32 bytes are not the scalar.

## What the tests have to match

Appendix C of draft-11 has three records: `seed`, `pk`, `eseed`, `ct`,
`ss`. The appendix heading still says those vectors are to be replaced, so
the test name pins draft-11. The first record is:

```text
seed  7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
ss    d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384
```

For each record, `GenerateKeyPairDerand(seed)` equals `pk`,
`EncapsulateDerand(pk, eseed)` equals `(ss, ct)`, and `Decapsulate(ct,
seed)` equals `ss`. A local round trip is not the acceptance test. Both
sides can share a wrong label order and still agree.

Also required, once the vectors pass:

- A length that is one byte off throws. No slicing.
- A 64-byte ML-KEM seed passed as an X-Wing secret throws.
- A flipped bit in `ct_M` returns 32 bytes, different from the honest
  shared secret, and does not throw. That is ML-KEM implicit rejection.
- A flipped bit in `ct_X` returns a different 32-byte secret.
- A valid ML-KEM public key with an all-zero X25519 public key still
  encapsulates. X-Wing does not abort on a zero Diffie-Hellman output.
- An ML-KEM public key that fails the FIPS 203 §7.2 check throws before a
  ciphertext is returned.
- Decapsulation takes the ciphertext and the seed. It does not take a
  public key.
- The expanded ML-KEM private key is not returned, cached, or wrapped.
- Exception text and `toString` do not contain seed or secret bytes.

FIPS mode rejects the KEM at `PqHpke` and at `PqForgeHybridKeyAgreement`.
The vector test calls the math type directly so it does not depend on
that flag. X-Wing is not a FIPS construction.

## HPKE

The draft requests HPKE KEM identifier `0x647A` (decimal 25722):
`Nsecret` 32, `Nenc` 1120, `Npk` 1216, `Nsk` 32, `Auth` no. Auth and
authPSK fail before encapsulation and return no `enc`.

`DeriveKeyPair(ikm)` is `SHAKE256(ikm, 32)` and then
`GenerateKeyPairDerand`. A 32-byte `ikm` is still hashed. It is not the
seed. `GenerateKeyPair` is 32 raw random bytes and is not shaken.

The HPKE sender's ephemeral input for this KEM is the 64-byte `eseed`.
A 32-byte value is an error. It does not go through `DeriveKeyPair`. The
suite KDF stays HKDF. The KEM secret is not hashed a second time with
SHA3-256 inside the key schedule.

Base mode can seal and open only after the three KEM vectors match. There
is no BoringSSL or OpenSSL comparison until the pinned build exports
`0x647A`.

## Proposed API

These symbols are not exported.

```dart
enum PqHybridAgreementMode { pqforge, xWing }

final kp = PqXWing.generateKeyPair(); // secret is 32 bytes, public is 1216
final enc = PqXWing.encapsulate(kp.publicKey);
final ss = PqXWing.decapsulate(enc.ciphertext, kp.secretKey);

// Opt-in. The default mode stays pqforge.
final agreement = PqForgeHybridKeyAgreement(
  mode: PqHybridAgreementMode.xWing,
);
```

`PqXWingPublicKey`, `PqXWingCiphertext`, and `SharedSecret32` check their
lengths in the constructor. `initiate` and `accept` on the `xWing` mode
throw before the deployment-salt check. Encapsulate on the `pqforge` mode
throws. The X-Wing mode has no salt, transcript, or info parameter.

`keygen --kem xwing` is opt-in. A default keygen emits the same files it
emits in 0.4.13.

## Out of scope for 0.4.14

HPKE KEM ids `0x0050` and `0x0051` without their own known-answer tests.
Certificates and the `id-XWing` OID. An expanded-key cache. A `.pqf`
branch. Replacing `PqForgeHybridKeyAgreement`.
