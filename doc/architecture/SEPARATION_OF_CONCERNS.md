# Separation of Concerns

`pqforge` is divided by responsibility:

- `algorithms`: names, profile defaults, byte sizes, and validation.
- `primitives`: direct calls to `pqcrypto` and Pointy Castle.
- `codecs`: envelope serialization and parsing.
- `keys`: key bundles, export/wrap containers, custody interfaces.
- `recipes`: cookbook message formats and helper containers.
- `services`: app-facing orchestration through `PqForge`.

No layer should import a higher layer. The service facade may compose every
lower layer; primitives must remain thin and testable.
