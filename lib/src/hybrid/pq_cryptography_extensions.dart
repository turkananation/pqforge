/// Ergonomic `package:cryptography` layer over the hybrid combiner (Option B).
///
/// This wrapper is kept in its own entrypoint
/// (`package:pqforge/pqforge.dart`) so that the zero-dependency
/// core ([PqForgeCombiner], reachable from `package:pqforge/pqforge.dart`) never
/// drags `package:cryptography` into an application's import graph unless the
/// developer opts in.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;

import 'pq_hybrid_combiner.dart';

/// Hybrid combining for the modern `package:cryptography` [crypto.SecretKey] type.
///
/// The receiver is treated as the **classical** shared secret (placed first in
/// the IETF ordering); [postQuantumSecret] is the **post-quantum** share placed
/// second. Both keys are read asynchronously, handed to the pure
/// [PqForgeCombiner] core, and the result is returned as a fresh
/// [crypto.SecretKeyData] ready to drive an `AesGcm` (or any other) cipher.
extension PqForgeCryptographyExtensions on crypto.SecretKey {
  /// Derives a hybrid session key from this classical secret and a
  /// post-quantum secret.
  ///
  /// ```dart
  /// final session = await classicalSecret.deriveHybridSecretKey(
  ///   postQuantumSecret: mlKemSecret,
  ///   info: utf8.encode('myapp/session/v1') as Uint8List,
  ///   profile: PqHybridProfile.heavy,
  /// );
  /// final cipher = AesGcm.with256bits();
  /// final box = await cipher.encrypt(message, secretKey: session);
  /// ```
  ///
  /// See [PqForgeCombiner.combine] for the meaning of [info], [salt], and
  /// [length]. [info] is mandatory for domain separation.
  ///
  /// Memory hygiene: the secret bytes extracted from both keys are copied into
  /// private buffers and zeroized in a `finally` once derivation completes. The
  /// two input [crypto.SecretKey]s are owned by the caller and are left intact.
  Future<crypto.SecretKeyData> deriveHybridSecretKey({
    required crypto.SecretKey postQuantumSecret,
    required Uint8List info,
    Uint8List? salt,
    PqHybridProfile profile = PqHybridProfile.balanced,
    int length = PqForgeCombiner.defaultLength,
  }) async {
    // `extractBytes()` may hand back a key's internal storage, so copy into
    // owned buffers before any in-place wiping.
    final classicalSharedSecret = Uint8List.fromList(await extractBytes());
    final postQuantumSharedSecret = Uint8List.fromList(
      await postQuantumSecret.extractBytes(),
    );

    try {
      final sessionKey = PqForgeCombiner(profile: profile).combine(
        classicalSharedSecret: classicalSharedSecret,
        postQuantumSharedSecret: postQuantumSharedSecret,
        info: info,
        salt: salt,
        length: length,
      );
      return crypto.SecretKeyData(sessionKey);
    } finally {
      PqForgeCombiner.wipe(classicalSharedSecret);
      PqForgeCombiner.wipe(postQuantumSharedSecret);
    }
  }
}
