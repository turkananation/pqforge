# Key Custody

Secret-key theft turns encryption and signatures into reusable attacker
capabilities. Use wrapped keys for CLI and server jobs.

`pqforge` wraps keys with:

- Argon2id for passphrase-to-key derivation;
- AES-256-GCM for authenticated encryption of key bytes;
- AAD that binds key kind, algorithm, and key id.

CLI passphrase sources:

| Option | Use |
| --- | --- |
| `--passphrase-env NAME` | CI/server jobs with secret-manager injection |
| `--passphrase-file path` | local scripts with protected files |
| `--passphrase value` | disposable tests only |

Applications can use `PqPassphraseKeyCustody` and `PqCallbackKeyCustodyStore` to
store wrapped key JSON in databases, secure storage, KMS metadata tables, Vault
metadata, or Serverpod endpoints.
