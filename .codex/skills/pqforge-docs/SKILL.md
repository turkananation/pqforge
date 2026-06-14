---
name: pqforge-docs
description: >-
  Maintain pqforge documentation from live code evidence. Use when editing
  README.md, CHANGELOG.md, CLAUDE.md, AGENTS.md, doc/**, wiki/**, the visibility
  manifest or generator, generated AI-discovery/editor files, or site/**. Also
  use when verifying API names, CLI commands, flags, performance numbers,
  package claims, links, or generated-document consistency.
---

# pqforge Documentation

Follow the canonical repository documentation procedure in
`.claude/skills/pqforge-docs/SKILL.md`. Read that file completely before making
documentation changes; it is shared with Claude Code and contains the detailed
claim boundary and manifest field map.

## Workflow

1. Read `pubspec.yaml`, the latest `CHANGELOG.md` section, `AGENTS.md`, and the
   source/tests for every fact being documented.
2. Determine whether the target is hand-maintained or generated. Edit
   `tool/visibility/visibility_manifest.json` or its generator for generated
   visibility files.
3. Verify public symbols through `lib/pqforge.dart` or `lib/pqforge_io.dart`.
   Verify CLI commands and flags from `bin/pqforge.dart` and `bin/src/`.
4. Keep wording inside `doc/security/CLAIM_BOUNDARY.md`; do not upgrade
   `pqcrypto` algorithm evidence into module-validation claims.
5. Regenerate affected outputs.
6. Run:

```bash
dart run tool/agent/verify.dart docs
```

Run `dart run tool/agent/verify.dart full` when examples, public APIs, CLI
behavior, or code-adjacent claims changed.
