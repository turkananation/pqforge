# pqforge Project Tracker

## V0.1 foundation

- [x] Split implementation layers.
- [x] Add binary and JSON envelopes.
- [x] Add portable key wrapping and storage interfaces.
- [x] Add document, record, file, log, artifact, identity, and dual-signature helpers.
- [x] Expand tests across layers and recipes.
- [x] Add CI workflow.
- [x] Add durable `/doc` tree.

## Next verification gates

- [ ] Add golden envelope fixtures.
- [ ] Add benchmark snapshots for common operations.
- [ ] Add Serverpod JSON DTO example.
- [ ] Add Flutter isolate example.
- [ ] Add CLI file-vault example.

## Release gates

- [ ] `dart format --output=none --set-exit-if-changed .`
- [ ] `dart analyze`
- [ ] `dart test`
- [ ] `dart run example/pqforge_example.dart`
- [ ] `dart pub publish --dry-run`
