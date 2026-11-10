# X-Wing

Status: shipped. `PqXWing`, `HpkeKem.xWing`, and `PqXWingMessage` are
exported from `package:pqforge/pqforge.dart`. The custom hybrid stays
the default. `.pqf` and `.pqfs` are unchanged. This is not PQXDH, not
the Double Ratchet, and not the Sparse Post-Quantum Ratchet.

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

## What the tests match

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

Also required:

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
SHA3-256 inside the key schedule. PSK uses that schedule. Auth does not
run.

`pqforge hpke seal` writes magic `XW01`. It does not write `PQF1`.
There is no BoringSSL or OpenSSL comparison until a pin exports
`0x647A`.

## API

```dart
final pair = await PqXWing.generateKeyPair();
final enc = await PqXWing.encapsulate(pair.publicKey);
final ss = await PqXWing.decapsulate(enc.ciphertext, pair.secretKey);

final known = await PqXWing.generateKeyPairDerand(seed);
final derand = await PqXWing.encapsulateDerand(known.publicKey, eseed);

final derived = await PqHpke.deriveKeyPair(kem: HpkeKem.xWing, ikm: ikm);

final agreement = PqForgeHybridKeyAgreement(
  mode: PqHybridAgreementMode.xWing,
);
final out = await agreement.encapsulateXWing(known.publicKey, eseed: eseed);
final opened = await agreement.decapsulateXWing(out.ciphertext, seed);
```

`pair.secretKey` is 32 bytes. `pair.publicKey` is 1216. Lengths that
are off by one byte throw. There is no `PqXWingPublicKey` type.

`PqForgeHybridKeyAgreement()` stays `PqHybridAgreementMode.pqforge`.
`initiate` and `accept` on that mode are unchanged.
`encapsulateXWing` on that mode throws. `initiate` and `accept` on
`PqHybridAgreementMode.xWing` throw `X-Wing does not use the pqforge
handshake` before the deployment salt is read. That mode has no salt,
transcript, or info parameter.

`PqFipsMode.enable()` makes `PqHpke` and `PqForgeHybridKeyAgreement`
throw `FIPS mode forbids X-Wing`. `PqXWing` itself does not read the
flag, so the known answers still run.

The 32-byte seed can be passed to `wrapKeyWithPassphrase`. The expanded
ML-KEM private key is not returned and is not wrapped.

## CLI

`keygen` and `encrypt` do not grow an X-Wing flag. The command is
`hpke`. `--kem` accepts only `xwing`.

```bash
pqforge hpke keygen --key-id demo --out-dir .
pqforge hpke seal \
  --recipient-public demo.xwing.public.json \
  --in plain.txt --out out.xwing
pqforge hpke open \
  --recipient-secret demo.xwing.secret.json \
  --in out.xwing --out opened.txt
```

`keygen` writes `demo.xwing.public.json` (`kind` `xwing-public`) and
`demo.xwing.secret.json` (`kind` `xwing-secret`). `algorithmId` is
`xwing`. `seal` refuses any other kind. `--cipher` is `aes-256-gcm`
(the default), `aes-128-gcm`, or `chacha20-poly1305`. The KEM stays
X-Wing.

PQXDH, the Double Ratchet, and the Sparse Post-Quantum Ratchet are not
flags on this command.

## Out of scope

HPKE KEM ids `0x0040`, `0x0041`, `0x0042`, `0x0050`, and `0x0051`.
Certificates and the `id-XWing` OID. An expanded-key cache. A `.pqf`
branch. Replacing `PqForgeHybridKeyAgreement`.
