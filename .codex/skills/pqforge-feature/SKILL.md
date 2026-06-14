---
name: pqforge-feature
description: >-
  Implement pqforge features and fixes across the library, CLI, codecs,
  recipes, streaming, hybrid cryptography, key custody, tests, and examples.
  Use for any behavior change under lib/**, bin/**, example/**, or test/**,
  including new APIs, commands, flags, formats, cipher/provider behavior,
  performance changes, and cross-cutting refactors.
---

# pqforge Feature Workflow

## Establish Scope

1. Read `AGENTS.md`, `pubspec.yaml`, and the affected public entrypoint:
   `lib/pqforge.dart` for web-safe work or `lib/pqforge_io.dart` for I/O.
2. Trace the existing implementation and its tests before editing. Prefer the
   current facade, codec, engine, and recipe patterns over parallel APIs.
3. Decide whether the change affects wire format, public exports, CLI, docs,
   generated files, or the pub.dev surface.

## Preserve Boundaries

- Keep `dart:io` confined to `pqforge_io.dart`, I/O services, the CLI, examples,
  tests, and tools. Never import `dart:ffi` from the published package.
- Use `pqcrypto` through `PqLatticeProvider`; do not copy lattice primitives.
- Bind algorithm choices and metadata into AAD/signing contexts.
- Reject malformed lengths, reserved metadata spoofing, path traversal, and
  authentication failures before returning plaintext.
- Preserve `.pqf` and `.pqfs` compatibility unless a versioned migration is
  explicitly required.
- Add public exports only through the two package entrypoints.

## Implement Vertically

Complete the relevant slice: implementation, public export, CLI wiring, tests,
example, documentation, and generated visibility. Do not leave a feature
advertised in one surface but absent from another.

When CLI behavior changes, verify registration in `bin/pqforge.dart`, parser
definitions in `bin/src/`, help output, exit behavior, and the CLI docs. When
`pubspec.yaml` version changes, regenerate `bin/src/version.g.dart`.

## Focused Tests

Run the narrowest relevant set while iterating:

| Area | Focused tests |
| --- | --- |
| Core facade, recipes, custody | `dart test test/pqforge_test.dart` |
| Hybrid KDF/agreement/signatures | `dart test test/pq_hybrid_combiner_test.dart test/pq_classical_hybrid_test.dart test/pq_hybrid_encryption_test.dart` |
| ECDSA-P256 | `dart test test/pq_ecdsa_p256_test.dart` |
| AEAD engines/sessions/FIPS | `dart test test/pq_secure_session_test.dart test/pq_cipher_suite_selection_test.dart test/pq_fips_mode_test.dart` |
| Envelopes/streaming | `dart test test/pq_envelope_signature_test.dart test/pq_streaming_envelope_test.dart test/pq_streaming_engine_test.dart` |
| Multi-recipient/pack | `dart test test/pq_multi_recipient_test.dart test/pq_folder_pack_test.dart` |
| CLI helpers | `dart test test/cli_semaphore_test.dart` plus command smoke tests |

For streaming memory changes, run the benchmark gate documented in
`dart_test.yaml`. For AEAD interoperability changes, run the nested
`tool/openssl_interop/` harness.

## Finish

Run:

```bash
dart run tool/agent/verify.dart full
```

Use `$pqforge-docs` for any documentation or visibility updates caused by the
feature.
