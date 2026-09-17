# Release Checklist

- [ ] Update version in `pubspec.yaml`.
- [ ] Update `CHANGELOG.md`.
- [ ] Regenerate `bin/src/version.g.dart` and visibility outputs.
- [ ] Run `dart run tool/agent/verify.dart release` from a clean checkout.
- [ ] Confirm the pub.dev archive contains only runtime package files and has
      zero warnings.
- [ ] Check README and `/doc` claim wording.
- [ ] Confirm the release commit is the exact commit intended for publication.
- [ ] Confirm automated publishing is enabled on
      [pub.dev/packages/pqforge/admin](https://pub.dev/packages/pqforge/admin):
      GitHub repository `turkananation/pqforge`, tag pattern `v{{version}}`,
      workflow `publish.yml`.
- [ ] Tag the release commit `v<version>` and push the tag. That single tag
      drives both:
      - `.github/workflows/publish.yml` — `dart pub publish` via GitHub Actions
        OIDC (no long-lived pub token).
      - `.github/workflows/release.yml` — AOT CLI binaries attached to the
        GitHub release.
- [ ] Confirm the publish and binary workflow runs succeeded, then verify the
      pub.dev version, GitHub release assets, and checksums.
      GitHub Pages and wiki sync only from `main`/`develop`, so site/wiki
      updates go live after those merges.

Do not also run `dart pub publish` by hand for a tagged release: the workflow
is the publisher. Manual publish remains a fallback if OIDC is not yet enabled
on pub.dev.
