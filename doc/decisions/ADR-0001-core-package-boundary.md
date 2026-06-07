# ADR-0001: Core Package Boundary

## Status

Accepted.

## Decision

`pqforge` core provides pure-Dart composition helpers and portable interfaces.
It does not depend on Flutter secure storage, cloud KMS SDKs, Vault, or a
filesystem keyring.

## Rationale

The package must work across Flutter, Dart CLI, Serverpod, and backends without
forcing unrelated platform dependencies. Storage and custody adapters can live
in optional packages or applications.
