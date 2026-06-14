# pqforge Project Tracker

## V0.1 foundation

- [x] Split implementation layers.
- [x] Add binary and JSON envelopes.
- [x] Add portable key wrapping and storage interfaces.
- [x] Add document, record, file, folder, text, media, email, webhook, token, log, artifact, identity, and dual-signature helpers.
- [x] Add built-in X25519 + ML-KEM and ML-DSA + Ed25519 hybrid tier.
- [x] Add built-in ECDSA-P256 classical signatures (pure-Dart PointyCastle).
- [x] Add universal CLI with wrapped key reuse.
- [x] Add generated GitHub Pages and AI discovery surfaces.
- [x] Add GitHub Wiki sync source.
- [x] Expand tests across layers and recipes.
- [x] Add CI workflow.
- [x] Add durable `/doc` tree.

## Next verification gates

- [ ] Add golden envelope fixtures.
- [ ] Add benchmark snapshots for common operations.
- [ ] Add Serverpod JSON DTO example.
- [ ] Add Flutter isolate example.
- [x] Add CLI file-vault example.
- [ ] Add streaming/chunked file encryption for multi-GB payloads.
- [ ] Add Serverpod DTO example for envelopes and signed tokens.
- [ ] Add Flutter UX sample for wrapped-key import/export.

## Release gates

- [ ] `dart format --output=none --set-exit-if-changed .`
- [ ] `dart analyze`
- [ ] `dart test`
- [ ] `dart run example/pqforge_example.dart`
- [ ] `dart run example/catalog_recipes_example.dart`
- [ ] wrapped-key CLI smoke
- [ ] `dart run tool/visibility/generate_visibility.dart --check`
- [ ] `dart run tool/agent/check_publish_surface.dart --strict`
