# Visibility Generation

`tool/visibility/visibility_manifest.json` is the source of truth for generated
project visibility surfaces:

- root AI discovery files: `llms.txt`, `llms-full.txt`, `identity.json`,
  `developer-ai.txt`, `faq-ai.txt`, `ai.txt`, `robots-ai.txt`, and `robots.txt`;
- GitHub Pages static mirror under `site/` (`index.html`, `styles.css`,
  `llms.txt`, and the other generated files);
- the Jaspr documentation app, also under `site/` (`content/`, `lib/`,
  `pubspec.yaml`). Pages builds that app and deploys `site/build/jaspr`.
  The generated HTML mirror stays in the repository so `--check` can see it.
  Do not hand-edit either the mirror or the Jaspr output.
- GitHub Copilot instructions;
- Cursor and Windsurf project rules.

Do not edit generated files directly. Update the manifest, then run:

```bash
dart run tool/visibility/generate_visibility.dart
dart run tool/visibility/generate_visibility.dart --check
```

The generated files intentionally repeat the same claim boundary: `pqforge`
composes `pqcrypto` ML-KEM/ML-DSA with AEAD, KDF, key custody, hybrid helpers,
recipes, and CLI workflows. It is not a CMVP/FIPS 140 validated module.
