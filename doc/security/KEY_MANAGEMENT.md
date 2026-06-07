# Key Management

Use fresh generated keys for normal operation. Use deterministic seeds only for
backup, recovery, or interop workflows where the seed is protected as a secret.

Recommended custody pattern:

1. Generate or import key material.
2. Wrap secret key bytes with `wrapKeyWithPassphrase` or store them in an
   app-provided `PqKeyStore`.
3. Publish public keys through an authenticated directory or pinned channel.
4. Rotate and revoke keys in the application domain.

Never log secret keys, seeds, passphrases, or unwrapped key bytes.
