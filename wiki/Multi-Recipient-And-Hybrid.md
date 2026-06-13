# Multi-Recipient And Hybrid Encryption

Two encrypt-side features that need **no decrypt-side flags** — every choice is
recorded in the self-describing container and auto-detected on read.

## Multi-recipient: one ciphertext, many readers

Repeat `--recipient-public` to encrypt **once** for several recipients. The
payload is sealed a single time and the DEM key is wrapped to each additional
recipient as a `recipients[]` metadata entry — about **1.6 KB and 2 ms per extra
recipient**, not a full re-encryption. There is **no wire-format change**, it
works for both one-shot `.pqf` and streaming `.pqfs`, and each entry may
individually be hybrid.

```bash
dart run pqforge encrypt \
  --recipient-public keys/alice.kem.public.json \
  --recipient-public keys/bob.kem.public.json \
  --in report.pdf --out report.pqf
```

The first `--recipient-public` is the primary. Every recipient opens the same
file with their own `--recipient-secret` and no extra flags:

```bash
dart run pqforge decrypt --recipient-secret keys/bob.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE --in report.pqf --out report.bob.pdf
```

`--recipient-public` is repeatable on `encrypt`, `encrypt-folder`,
`encrypt-text`, `encrypt-media`, and `pack`.

Library: `PqForge.encryptAsync(...)` with `PqMultiRecipient` / `PqRecipientSpec`.

## Hybrid encryption: PQC + X25519

Add `--hybrid` to combine the ML-KEM shared secret with an ephemeral X25519
exchange. Confidentiality holds **while either Module-LWE or Curve25519 stands**.
The DEM key is the IETF concatenate-then-KDF combination of both secrets, the
ephemeral public key rides in self-describing `hybridKex` metadata (KDF-bound, so
tampering flips the derived key and the first AEAD tag check fails), and decrypt
auto-detects it.

```bash
dart run pqforge encrypt --hybrid \
  --recipient-public keys/vault.kem.public.json \
  --in secret.bin --out secret.pqf
```

`--hybrid` finds the conventional `<key-id>.x25519.public.json` next to
`--recipient-public` (override with `--recipient-x25519-public`). On decrypt,
pqforge finds `<key-id>.x25519.secret[.wrapped].json` next to
`--recipient-secret` (override with `--recipient-x25519-secret`). `keygen` emits
the X25519 keypair by default, so hybrid works out of the box.

Hybrid and multi-recipient compose — one ciphertext can be hybrid **and** target
several recipients at once.

## Cipher and engine

| Flag | Effect |
| --- | --- |
| `--cipher chacha20-poly1305` | ChaCha20-Poly1305 instead of AES-256-GCM (~2.6× faster in pure Dart). Recorded as a tamper-evident `aeadSuite` marker. |
| `--engine cryptography\|pure-dart` | AEAD backend: `cryptography` (fast default, hardware-backed on Flutter) or `pure-dart` (PointyCastle reference). Wire formats are engine-independent. |

See [Performance](Performance) for measured throughput.

## See also

- [CLI Guide](CLI-Guide)
- [Hybrid Sessions](Hybrid-Sessions)
- [Streaming And Large Files](Streaming-And-Large-Files)
