# pqforge Roadmap

## V0.1 foundation

- Strict separation of algorithms, primitives, codecs, keys, recipes, services.
- Binary and JSON envelope v1.
- Easy key, sign, encrypt, decrypt, file, record, document, wrapping APIs.
- Portable key-custody hooks.
- Expanded tests and CI.

## V0.3 integration examples

- Serverpod DTO examples for JSON envelopes.
- Flutter isolate examples for signing/encryption work.
- CLI examples for file encryption and artifact signing.

## V0.4 custody adapters

- Optional packages for Flutter secure storage, local encrypted keyring, and
  cloud KMS/Vault integrations.
- Keep adapters out of the core package.

## V0.5 interoperability

- Cross-language envelope test vectors.
- Golden binary and JSON fixtures.
- Public verification examples for signed artifacts and webhooks.

## V1.0 stability

- Freeze envelope v1 compatibility.
- Publish migration policy.
- Maintain green CI, dry-run publish, and evidence-scoped docs.
