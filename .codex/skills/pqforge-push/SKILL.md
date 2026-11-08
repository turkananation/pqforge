---
name: pqforge-push
description: >-
  Gate every git push. Use before pushing any pqforge branch, including a
  docs-only change. Run the same local checks CI runs, and do not push a
  tree that has not passed them.
---

# pqforge Push

One push. The checks below are the push. A red tree does not get a commit
whose message is "fix CI".

## Never

- Push `main` or `develop`. The maintainer merges.
- Push to see whether CI fails.
- Push a formatter, analyzer, or test fix that was not re-run locally.
- Add a second commit because the first push was not checked.

## Before the commit

The commit that will be pushed already contains the fix. Do not plan a
follow-up.

```bash
dart run tool/agent/verify.dart full
```

That is the default CI job: generators, package boundaries, format,
`dart analyze`, links, `dart test`, and the examples.

Also, when the diff touches them:

| Diff | Extra check |
| --- | --- |
| `site/**` | `dart analyze` inside `site/` |
| `tool/openssl_pqc_interop/**` or `tool/pqc_interop_common/**` | `dart analyze` in that package |
| `tool/interop/*.cc` or `tool/interop/*.c` | compile the file against the pinned headers, `-Wall -Werror` |
| `test/pq_openssl_groups_test.dart` | that file, including ffdhe8192, finished inside its own timeout |

`verify.dart full` does not build pinned OpenSSL or BoringSSL. Say so. Do
not describe a local analyze as the pinned job.

## Push

Only after every command above exited 0:

```bash
git status -sb
git push origin <feature-branch>
```

If a check fails, fix it in the same unpushed commit, or amend only when
the commit is still unpushed and you made it. Then run the failed check
again, then `verify.dart full` again. Then push once.
