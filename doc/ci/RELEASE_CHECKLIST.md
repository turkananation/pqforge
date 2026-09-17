# Release Checklist

- [ ] Update version in `pubspec.yaml`.
- [ ] Update `CHANGELOG.md`.
- [ ] Regenerate `bin/src/version.g.dart` and visibility outputs.
- [ ] Run `dart run tool/agent/verify.dart release` from a clean checkout.
- [ ] Confirm the pub.dev archive contains only runtime package files and has
      zero warnings.
- [ ] Check README and `/doc` claim wording.
- [ ] Confirm the release commit is the exact commit intended for publication.
- [ ] Publish to pub.dev with `dart pub publish` from that commit (manual today).
      `.github/workflows/release.yml` attaches AOT CLI binaries on `v*` tags; it
      does **not** run `dart pub publish`. GitHub Pages and wiki sync only from
      `main`/`develop`, so site/wiki updates go live after those merges.
- [ ] Tag the release after publish approval (`v<version>` on the published commit).
