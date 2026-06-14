# Release Checklist

- [ ] Update version in `pubspec.yaml`.
- [ ] Update `CHANGELOG.md`.
- [ ] Regenerate `bin/src/version.g.dart` and visibility outputs.
- [ ] Run `dart run tool/agent/verify.dart release` from a clean checkout.
- [ ] Confirm the pub.dev archive contains only runtime package files and has
      zero warnings.
- [ ] Check README and `/doc` claim wording.
- [ ] Confirm the release commit is the exact commit intended for publication.
- [ ] Tag the release after publish approval.
