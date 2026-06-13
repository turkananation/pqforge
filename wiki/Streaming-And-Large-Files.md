# Streaming And Large Files

`pqforge` encrypts gigabyte-scale files in **bounded memory**. No application
chunking is required.

## Automatic streaming

Inputs at or above **8 MiB** automatically switch from the one-shot `.pqf`
envelope to the `.pqfs` streaming container. The container is a signed master
header followed by independently authenticated frames; the working set is
roughly **two frames regardless of total file size**.

Per-frame `seq` and `isFinal` binding in the AAD prevents truncation,
reordering, duplication, and splicing of frames.

```bash
# Auto-streams because the input is > 8 MiB; memory stays bounded.
dart run pqforge encrypt \
  --recipient-public keys/vault.kem.public.json \
  --in movie.mp4 --out movie.mp4.pqf

dart run pqforge decrypt \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in movie.mp4.pqf --out movie.open.mp4
```

`encrypt-media` streams the same way. The decrypt side detects `.pqf` vs
`.pqfs` from the container itself — no flag needed.

## Library API

The streaming file API lives behind the `dart:io` entrypoint
`package:pqforge/pqforge_io.dart` (the core
`package:pqforge/pqforge.dart` stays web-safe):

```dart
import 'package:pqforge/pqforge_io.dart';

final cipher = PqForgeStreamCipher(); // fast cryptography engine by default
await cipher.encryptFile(
  recipientPublicKey: recipientKemPublicKey,
  recipientKexPublicKey: recipientX25519PublicKey, // optional: hybrid
  input: File('movie.mp4'),
  output: File('movie.mp4.pqf'),
  profile: PqForgeProfile.maximum,
);

// Off the UI isolate on Flutter:
await PqForgeStreamCipher.encryptFileInBackground(
  recipientPublicKey: recipientKemPublicKey,
  inputPath: 'movie.mp4',
  outputPath: 'movie.mp4.pqf',
  profile: PqForgeProfile.maximum,
);
```

The streaming codec itself (`PqStreamingEnvelope`) is dart2js-safe and ships in
the core web-safe umbrella; only the `dart:io` file plumbing is VM/native-only.

## Pack archives

When a whole folder of (often small) files moves together, `pack` collapses the
tree into **one** encrypted streaming archive — a single KEM encapsulation and
signature for the entire tree — and `unpack` restores it path-traversal-safe.
Both stream end to end with no plaintext temp spool, and a failed `unpack`
removes everything it created.

```bash
dart run pqforge pack \
  --recipient-public keys/vault.kem.public.json \
  --in-dir ./site --out ./site.pqfs

dart run pqforge unpack \
  --recipient-secret keys/vault.kem.secret.wrapped.json \
  --passphrase-env PQFORGE_PASSPHRASE \
  --in ./site.pqfs --out-dir ./site.open
```

Use [`encrypt-folder`](CLI-Guide) (one `.pqf` per file) when recipients fetch
individual files; use `pack` when the whole tree is one unit.

## See also

- [CLI Guide](CLI-Guide)
- [Performance](Performance)
- [Multi-Recipient And Hybrid](Multi-Recipient-And-Hybrid)
