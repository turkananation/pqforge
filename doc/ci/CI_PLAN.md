# CI Plan

The core CI workflow runs:

```bash
dart pub get
dart run tool/version/generate_version.dart --check
dart run tool/visibility/generate_visibility.dart --check
dart run tool/agent/check_package_boundaries.dart
dart format --output=none --set-exit-if-changed .
dart analyze
dart run tool/agent/check_links.dart
dart test
dart run example/pqforge_example.dart
dart run example/file_encryption_example.dart
dart run example/hybrid_combiner_example.dart
dart run example/secure_session_example.dart
dart run example/hybrid_key_agreement_example.dart
dart run example/catalog_recipes_example.dart
dart run tool/agent/check_publish_surface.dart --strict
```

The same checks are available locally through
`dart run tool/agent/verify.dart quick|docs|full|release`.

The workflow lives in `.github/workflows/ci.yml`. Additional automation:

- `.github/workflows/visibility.yml` checks generated site and AI files.
- `.github/workflows/pages.yml` deploys `site/` to GitHub Pages.
- `.github/workflows/sync-wiki.yml` syncs `wiki/` to the GitHub Wiki.
- `.github/workflows/codeql.yml` scans GitHub Actions workflow code.
- `.pubignore` and `tool/agent/check_publish_surface.dart` keep repository-only
  agent, test, documentation-source, generated-site, and tooling files out of
  the pub.dev archive.
