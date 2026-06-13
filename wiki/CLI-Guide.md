# CLI Guide

The `pqforge` CLI has 18 commands for reusable keys, wrapped secret keys, file /
folder / text / media encryption, gigabyte streaming, whole-folder packing,
multi-recipient and hybrid encryption, recipe-specific and hybrid signatures,
and artifact inspection. The full reference is in
[doc/CLI.md](https://github.com/turkananation/pqforge/blob/main/doc/CLI.md).

`pqforge <command> --help` prints worked examples for any command.

## Wrapped keys

```bash
export PQFORGE_PASSPHRASE='load-this-from-a-secret-manager'
dart run pqforge keygen --profile maximum --key-id vault --out-dir keys --passphrase-env PQFORGE_PASSPHRASE
```

By default `keygen` emits the **full hybrid keyset** — ML-KEM + ML-DSA plus
X25519, Ed25519, and ECDSA-P256 — so hybrid encryption and signing work out of
the box. `--classical <algo>` narrows the classical set, `--no-classical` keeps
the post-quantum bundle only, and `--classical-only` emits classical keys alone.

Public keys: `vault.kem.public.json`, `vault.sign.public.json`,
`vault.x25519.public.json`, `vault.ed25519.public.json`,
`vault.ecdsa-p256.public.json`.

Wrapped secret keys: the same names with `.secret.wrapped.json`. Wrapping uses
Argon2id + AES-256-GCM.

## Files, folders, text, media

```bash
dart run pqforge encrypt --recipient-public keys/vault.kem.public.json --in report.pdf --out report.pdf.pqf
dart run pqforge decrypt --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in report.pdf.pqf --out report.open.pdf

dart run pqforge encrypt-folder --recipient-public keys/vault.kem.public.json --in-dir ./records --out-dir ./records.pqf
dart run pqforge decrypt-folder --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in-dir ./records.pqf --out-dir ./records.open

dart run pqforge encrypt-text --recipient-public keys/vault.kem.public.json --text 'private memo' --text-id memo-1 --out memo.pqf
dart run pqforge encrypt-media --recipient-public keys/vault.kem.public.json --in cover.png --mime-type image/png --out cover.png.pqf
```

The decrypt commands need no format flags — every choice is recorded in the
self-describing container and auto-detected on read.

## Large files and packing

Inputs ≥ 8 MiB **auto-stream** through the bounded-memory `.pqfs` container
(working set ≈ two frames). `pack`/`unpack` collapse a whole folder into one
encrypted streaming archive (one KEM + one signature for the tree). Details:
[Streaming And Large Files](Streaming-And-Large-Files).

```bash
dart run pqforge pack --recipient-public keys/vault.kem.public.json --in-dir ./site --out ./site.pqfs
dart run pqforge unpack --recipient-secret keys/vault.kem.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in ./site.pqfs --out-dir ./site.open
```

## Multi-recipient, hybrid, cipher, engine

Repeatable `--recipient-public` (one ciphertext, many readers), `--hybrid`
(PQC + X25519), `--cipher chacha20-poly1305`, and `--engine cryptography|pure-dart`
work on the encrypt commands; decrypt auto-detects all of them. See
[Multi-Recipient And Hybrid](Multi-Recipient-And-Hybrid).

```bash
dart run pqforge encrypt --hybrid --cipher chacha20-poly1305 \
  --recipient-public keys/alice.kem.public.json \
  --recipient-public keys/bob.kem.public.json \
  --in report.pdf --out report.pqf
```

## Inspect

Describe any `.pqf`, `.pqfs`, key, or signature file **without decrypting it**:

```bash
dart run pqforge inspect --in report.pqf
```

## Signatures

```bash
# Recipe-bound signature (document / text / media / artifact)
dart run pqforge sign --signer-secret keys/vault.sign.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --kind media --in cover.png --mime-type image/png --out cover.sig.json
dart run pqforge verify --signer-public keys/vault.sign.public.json --in cover.png --signature cover.sig.json

# Hybrid ML-DSA + Ed25519/ECDSA-P256 (--digest for gigabyte inputs)
dart run pqforge hybrid-sign --signer-secret keys/vault.sign.secret.wrapped.json --classical-secret keys/vault.ecdsa-p256.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in release.tar.gz --out release.hybrid.json
dart run pqforge hybrid-verify --signer-public keys/vault.sign.public.json --classical-public keys/vault.ecdsa-p256.public.json --in release.tar.gz --signature release.hybrid.json

# Standalone ECDSA-P256 (RFC 6979, low-S)
dart run pqforge ecdsa-sign --secret keys/vault.ecdsa-p256.secret.wrapped.json --passphrase-env PQFORGE_PASSPHRASE --in firmware.bin --out firmware.ecdsa.json
dart run pqforge ecdsa-verify --public keys/vault.ecdsa-p256.public.json --in firmware.bin --signature firmware.ecdsa.json
```

`verify`, `hybrid-verify`, and `ecdsa-verify` exit `0` on a valid signature and
`1` on a failed one, so they slot into shell `&&` chains and CI gates.
