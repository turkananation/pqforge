# CI Plan

The core CI workflow runs:

```bash
dart pub get
dart run tool/visibility/generate_visibility.dart --check
dart format --output=none --set-exit-if-changed .
dart analyze
dart test
dart run example/pqforge_example.dart
dart run example/file_encryption_example.dart
dart run example/hybrid_combiner_example.dart
dart run example/secure_session_example.dart
dart run example/hybrid_key_agreement_example.dart
dart run example/catalog_recipes_example.dart
dart pub publish --dry-run
```

The workflow lives in `.github/workflows/ci.yml`. Additional automation:

- `.github/workflows/visibility.yml` checks generated site and AI files.
- `.github/workflows/pages.yml` deploys `site/` to GitHub Pages.
- `.github/workflows/sync-wiki.yml` syncs `wiki/` to the GitHub Wiki.
- `.github/workflows/codeql.yml` scans GitHub Actions workflow code.
