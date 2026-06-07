# CI Plan

The core CI workflow runs:

```bash
dart pub get
dart format --output=none --set-exit-if-changed .
dart analyze
dart test
dart run example/pqforge_example.dart
dart pub publish --dry-run
```

The workflow lives in `.github/workflows/ci.yml`.
