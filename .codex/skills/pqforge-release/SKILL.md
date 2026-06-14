---
name: pqforge-release
description: >-
  Prepare, verify, and audit pqforge releases. Use when changing the package
  version, updating release notes, preparing a release branch or tag, checking
  the pub.dev archive, validating generated version/visibility files, building
  release binaries, or publishing to pub.dev/GitHub.
---

# pqforge Release Workflow

## Prepare

1. Confirm the intended release version and branch. Inspect `git status`,
   `pubspec.yaml`, the top of `CHANGELOG.md`, and existing tags.
2. Update `pubspec.yaml` and `CHANGELOG.md` together. Do not infer the version
   from a manifest or generated file.
3. Regenerate:

```bash
dart run tool/version/generate_version.dart
dart run tool/visibility/generate_visibility.dart
```

4. Check README, CLI/API docs, wiki, and visibility claims against source. Use
   `$pqforge-docs`.
5. Confirm `.pubignore` still limits the archive to the runtime package.

## Verify

Run the full release gate from a clean checkout:

```bash
dart pub get
dart pub get --directory tool/openssl_interop
dart run tool/agent/verify.dart release
```

Run the OpenSSL interop and streaming memory gates when affected. Compile and
smoke-test the CLI if release-binary behavior changed.

The strict archive check must have zero warnings. Never hide warnings with
`--ignore-warnings` for an actual release.

## Publish

- Do not publish or tag unless the user explicitly requested it.
- Publish from a clean, reviewed commit.
- Create the `v<version>` tag only for the exact published commit.
- Verify the GitHub release binary workflow and checksums after pushing the tag.
- Report the exact pub.dev version, tag, and commit.

Read `doc/ci/RELEASE_CHECKLIST.md` for the repository checklist.
