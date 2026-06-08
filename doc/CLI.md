# pqforge CLI Guide

The `pqforge` executable is for local machines, server jobs, release pipelines,
and admin workflows that need post-quantum encryption or signatures without
writing an app first.

Install from this package with:

```bash
dart pub global activate --source path .
```

Or run directly inside the repository:

```bash
dart run pqforge --help
```

## Key Storage

`keygen` writes reusable keys into the directory passed to `--out-dir`.

Public keys are not secret:

- `<key-id>.kem.public.json`
- `<key-id>.sign.public.json`

Secret keys should be wrapped:

- `<key-id>.kem.secret.wrapped.json`
- `<key-id>.sign.secret.wrapped.json`

Wrapped secret keys use `PqWrappedKey`: Argon2id derives a wrapping key from the
passphrase, and AES-256-GCM encrypts the secret key bytes with authenticated
metadata.

```bash
export PQFORGE_PASSPHRASE='load-this-from-a-secret-manager'
dart run pqforge keygen \
  --profile maximum \
  --key-id vault \
  --out-dir keys \
  --passphrase-env PQFORGE_PASSPHRASE
```

Passphrase sources:

| Option | Use |
| --- | --- |
| `--passphrase-env NAME` | CI/server jobs where `NAME` is populated by a secret manager |
| `--passphrase-file path` | Local scripts that read from protected files |
| `--passphrase value` | Short-lived testing only; it can leak through shell history |

If no passphrase source is supplied, `keygen` writes raw secret-key JSON and
prints a warning. Use raw secret files only for disposable tests.

## File Encryption

```bash
dart run pqforge encrypt \
  --recipient-public keys/vault.kem.public.json \
  --profile maximum \
  --in report.pdf \
  --out report.pdf.pqf

dart run pqforge decrypt \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in report.pdf.pqf \
  --out report.open.pdf
```

The file name is bound into structured `pqforge/file/v1` AAD. If you pass
`--aad`, that value is also bound into the envelope and must be supplied again
for decryption.

## Folder Encryption

Folder encryption writes one `.pqf` envelope per file and preserves relative
paths.

```bash
dart run pqforge encrypt-folder \
  --recipient-public keys/vault.kem.public.json \
  --profile maximum \
  --in-dir ./records \
  --out-dir ./records.pqf \
  --aad tenant:county-a

dart run pqforge decrypt-folder \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in-dir ./records.pqf \
  --out-dir ./records.open \
  --aad tenant:county-a
```

Each relative path is bound into `pqforge/folder-entry/v1` AAD, so a folder entry
cannot be moved to another path and still authenticate.

## Text Encryption

Use text commands for short UTF-8 strings, prompts, notes, and secrets.

```bash
dart run pqforge encrypt-text \
  --recipient-public keys/vault.kem.public.json \
  --text 'private memo' \
  --text-id memo-2026-001 \
  --out memo.pqf

dart run pqforge decrypt-text \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in memo.pqf
```

For larger text files:

```bash
dart run pqforge encrypt-text \
  --recipient-public keys/vault.kem.public.json \
  --in memo.txt \
  --text-id memo-2026-001 \
  --out memo.txt.pqf
```

## Media Encryption

Use media commands for images, audio, video, PDFs, and other content where MIME
type matters.

```bash
dart run pqforge encrypt-media \
  --recipient-public keys/vault.kem.public.json \
  --in cover.png \
  --media-id cover-2026-001 \
  --mime-type image/png \
  --out cover.png.pqf

dart run pqforge decrypt-media \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in cover.png.pqf \
  --out cover.open.png
```

If `--mime-type` is omitted, the CLI infers common extensions and otherwise
uses `application/octet-stream`.

## Signatures

The `sign` command supports recipe-specific signature containers.

```bash
dart run pqforge sign \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --kind document \
  --in contract.pdf \
  --document-id contract-2026-001 \
  --out contract.sig.json

dart run pqforge verify \
  --signer-public keys/vault.sign.public.json \
  --in contract.pdf \
  --signature contract.sig.json
```

Supported `--kind` values:

| Kind | Bound fields |
| --- | --- |
| `document` | document id, payload hash, payload length |
| `text` | text id, UTF-8 encoding, payload hash, payload length |
| `media` | media id, MIME type, payload hash, payload length |
| `artifact` | artifact id, version, artifact hash |

Media signing example:

```bash
dart run pqforge sign \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --kind media \
  --in cover.png \
  --media-id cover-2026-001 \
  --mime-type image/png \
  --out cover.sig.json

dart run pqforge verify \
  --signer-public keys/vault.sign.public.json \
  --in cover.png \
  --signature cover.sig.json
```

Artifact signing example:

```bash
dart run pqforge sign \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --kind artifact \
  --in release.tar.gz \
  --artifact-id pqforge-release \
  --version 7 \
  --out release.sig.json
```

## Signed Envelopes

Encryption commands accept `--signer-secret` to sign the encrypted envelope:

```bash
dart run pqforge encrypt \
  --recipient-public keys/vault.kem.public.json \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --signer-key-id vault-signer \
  --in report.pdf \
  --out report.signed.pqf
```

Decrypt signed envelopes with the signer public key:

```bash
dart run pqforge decrypt \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --signer-public keys/vault.sign.public.json \
  --in report.signed.pqf \
  --out report.open.pdf
```

## Classical Keys

`keygen --classical` adds classical keypairs next to the ML-KEM/ML-DSA bundle.
The option is repeatable and accepts `x25519` (hybrid key agreement), `ed25519`,
and `ecdsa-p256` (hybrid/standalone signers). Pass `--classical-only` to skip
the post-quantum bundle entirely.

```bash
dart run pqforge keygen \
  --key-id vault \
  --out-dir keys \
  --classical ed25519 \
  --classical ecdsa-p256 \
  --passphrase-env PQFORGE_PASSPHRASE
```

Classical keys follow the `<key-id>.<algo>.public.json` /
`<key-id>.<algo>.secret[.wrapped].json` naming, and secret keys are wrapped with
Argon2id + AES-256-GCM when a passphrase source is supplied — the same custody
path as ML-KEM/ML-DSA secrets. Only the secret key is stored; the public key is
recomputed from it when signing.

## Hybrid Signatures

`hybrid-sign` produces one ML-DSA signature **and** one classical signature
(Ed25519 or ECDSA-P256, chosen by the classical key) bound over the same
message. The post-quantum profile is inferred from the ML-DSA key.

```bash
dart run pqforge hybrid-sign \
  --signer-secret keys/vault.sign.secret.wrapped.json \
  --classical-secret keys/vault.ecdsa-p256.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in release.tar.gz \
  --out release.hybrid.json \
  --context release:v7

dart run pqforge hybrid-verify \
  --signer-public keys/vault.sign.public.json \
  --classical-public keys/vault.ecdsa-p256.public.json \
  --in release.tar.gz \
  --signature release.hybrid.json
```

`--context` is an optional domain-separation string; when supplied to
`hybrid-sign` it is stored in the signature JSON and reused automatically by
`hybrid-verify` (override it with `--context` if needed). The default `--policy
require-both` fails unless **both** signatures verify; `--policy accept-either`
records an either-or policy instead.

## Standalone ECDSA-P256

`ecdsa-sign` / `ecdsa-verify` use the pure classical ECDSA-P256 path (RFC 6979
deterministic nonces, canonical low-S) over the raw file bytes — no
post-quantum key involved.

```bash
dart run pqforge ecdsa-sign \
  --secret keys/vault.ecdsa-p256.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in firmware.bin \
  --out firmware.ecdsa.json

dart run pqforge ecdsa-verify \
  --public keys/vault.ecdsa-p256.public.json \
  --in firmware.bin \
  --signature firmware.ecdsa.json
```

`verify`, `hybrid-verify`, and `ecdsa-verify` exit `0` on a valid signature and
`1` on a failed one, so they slot directly into shell `&&` chains and CI gates.

## Color And Help

Run `pqforge` with no arguments (or `pqforge --help`) for a grouped command
overview, and `pqforge <command> --help` for per-command options and examples.
Colors auto-disable when output is piped or `NO_COLOR` is set; force them off
with `--no-color`. `pqforge --version` prints the version.

## Operational Notes

- Keep wrapped secret-key JSON in a protected store.
- Prefer `--passphrase-env` for automation.
- Rotate keys according to the app's retention and risk policy.
- Keep public-key trust explicit; a self-provided public key is not an identity.
- Do not use this CLI as a streaming encryptor for multi-GB files yet; add
  application-level chunking for very large payloads.
