/// Multi-recipient key wrapping for one-shot envelopes and `.pqfs` containers.
///
/// The payload is sealed exactly once under a single DEM key; each
/// *additional* recipient gets a `recipients[]` metadata entry that wraps that
/// DEM key to them:
///
/// ```text
/// (ct_i, ss_i) = ML-KEM.Encaps(recipient_i.kemPk)
/// kek_i        = HKDF(ss_i)                        # salt = ct_i [‖ ephPk_i]
/// entry_i      = AES-256-GCM(kek_i, nonce_i, demKey)
/// ```
///
/// The *primary* recipient is unchanged: their decapsulation derives the DEM
/// key directly (KEM-DEM or hybrid), so single-recipient output is
/// byte-identical with or without this module. Entries ride in envelope/header
/// metadata, so **no wire-format change** is needed and the same construction
/// works for both container formats. Per extra recipient the cost is one
/// encapsulation (~2 ms) and ~1.6 KB of metadata (ML-KEM-1024) instead of a
/// full re-encryption of the payload.
///
/// Tamper posture: each wrap entry is itself AEAD-authenticated under a KEK
/// only that recipient can derive (the KEM ciphertext — and the ephemeral
/// X25519 key for hybrid entries — feed the KDF salt), so a corrupted entry
/// can only deny service, never redirect plaintext. Signed envelopes and
/// `.pqfs` headers additionally bind the whole metadata map.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../hybrid/pq_classical_hybrid.dart';
import '../hybrid/pq_hybrid_combiner.dart';
import '../primitives/pq_primitives.dart';

/// One additional recipient of a multi-recipient encryption: their ML-KEM
/// public key, an optional X25519 public key (making *their* key wrap hybrid),
/// and an optional key id recorded in the entry for fast unwrap routing.
class PqRecipientSpec {
  PqRecipientSpec({
    required Uint8List kemPublicKey,
    Uint8List? kexPublicKey,
    this.keyId,
  }) : kemPublicKey = PqBytes.copy(kemPublicKey),
       kexPublicKey = kexPublicKey == null ? null : PqBytes.copy(kexPublicKey) {
    if (this.kexPublicKey != null) {
      requireLength(
        'kexPublicKey',
        this.kexPublicKey!,
        PqClassicalKeyAgreementAlgorithm.x25519.publicKeyBytes,
      );
    }
  }

  final Uint8List kemPublicKey;
  final Uint8List? kexPublicKey;
  final String? keyId;
}

/// Builds and opens the `recipients[]` key-wrap entries.
abstract final class PqMultiRecipient {
  /// Metadata key carrying the additional-recipient entries.
  static const metadataKey = pqForgeRecipientsMetadataKey;

  /// Metadata key naming the primary recipient's key id.
  static const primaryKeyIdKey = pqForgeRecipientKeyIdMetadataKey;

  /// True when [metadata] carries additional-recipient entries.
  static bool hasEntries(Map<String, Object?> metadata) =>
      metadata.containsKey(metadataKey);

  static Uint8List get _wrapAad =>
      PqBytes.utf8Bytes('pqforge/multi-recipient-wrap/v1');

  /// Encryptor side: one entry per additional recipient, each wrapping
  /// [demKey] under a KEK only that recipient can derive.
  static Future<List<Map<String, Object?>>> buildEntries({
    required PqForgeProfile profile,
    required Uint8List demKey,
    required List<PqRecipientSpec> recipients,
  }) async {
    requireLength('demKey', demKey, pqForgeDefaultSessionKeyBytes);
    final entries = <Map<String, Object?>>[];
    for (final recipient in recipients) {
      final encapsulated = PqKemPrimitives.encapsulate(
        profile.kem,
        recipient.kemPublicKey,
      );
      Uint8List? ephemeralPublic;
      Uint8List kek;
      if (recipient.kexPublicKey == null) {
        kek = _kekPqc(
          profile,
          encapsulated.sharedSecret,
          encapsulated.ciphertext,
        );
      } else {
        final ephemeral = await const PqForgeHybridKeyAgreement()
            .generateClassicalKeyPairBytes();
        ephemeralPublic = ephemeral.publicKey;
        final classicalShared =
            await PqForgeHybridKeyAgreement.x25519SharedSecret(
              secretKey: ephemeral.secretKey,
              remotePublicKey: recipient.kexPublicKey!,
            );
        try {
          kek = _kekHybrid(
            profile,
            encapsulated.sharedSecret,
            encapsulated.ciphertext,
            classicalShared,
            ephemeralPublic,
          );
        } finally {
          PqForgeCombiner.wipe(classicalShared);
          PqForgeCombiner.wipe(ephemeral.secretKey);
        }
      }
      try {
        final nonce = PqBytes.randomBytes(pqForgeDefaultAeadNonceBytes);
        final wrapped = PqSymmetricPrimitives.aesGcmEncrypt(
          key: kek,
          nonce: nonce,
          plaintext: demKey,
          aad: _wrapAad,
        );
        entries.add(<String, Object?>{
          if (recipient.keyId != null) 'keyId': recipient.keyId,
          'kemCiphertext': base64Encode(encapsulated.ciphertext),
          if (ephemeralPublic != null)
            'ephemeralPublicKey': base64Encode(ephemeralPublic),
          'nonce': base64Encode(nonce),
          'wrappedKey': base64Encode(wrapped),
        });
      } finally {
        PqForgeCombiner.wipe(kek);
      }
    }
    return entries;
  }

  /// Decryptor side: tries to unwrap the DEM key from the `recipients[]`
  /// entries in [metadata] with this recipient's keys.
  ///
  /// Entries whose `keyId` equals [recipientKeyId] are tried first. Hybrid
  /// entries are skipped when [recipientKexSecretKey] is absent. Returns null
  /// when no entry unwraps (the caller decides whether the primary path or an
  /// error applies); throws [PqForgeException] only for *structurally*
  /// malformed metadata.
  static Future<Uint8List?> unwrapDemKey({
    required PqForgeProfile profile,
    required Map<String, Object?> metadata,
    required Uint8List recipientSecretKey,
    Uint8List? recipientKexSecretKey,
    String? recipientKeyId,
  }) async {
    final entries = parseEntries(metadata);
    if (entries.isEmpty) return null;
    final ordered = recipientKeyId == null
        ? entries
        : [
            ...entries.where((e) => e.keyId == recipientKeyId),
            ...entries.where((e) => e.keyId != recipientKeyId),
          ];
    for (final entry in ordered) {
      if (entry.ephemeralPublicKey != null && recipientKexSecretKey == null) {
        continue; // hybrid entry, no X25519 key available
      }
      Uint8List? kek;
      try {
        final sharedSecret = PqKemPrimitives.decapsulate(
          profile.kem,
          recipientSecretKey,
          entry.kemCiphertext,
        );
        if (entry.ephemeralPublicKey == null) {
          kek = _kekPqc(profile, sharedSecret, entry.kemCiphertext);
        } else {
          final classicalShared =
              await PqForgeHybridKeyAgreement.x25519SharedSecret(
                secretKey: recipientKexSecretKey!,
                remotePublicKey: entry.ephemeralPublicKey!,
              );
          try {
            kek = _kekHybrid(
              profile,
              sharedSecret,
              entry.kemCiphertext,
              classicalShared,
              entry.ephemeralPublicKey!,
            );
          } finally {
            PqForgeCombiner.wipe(classicalShared);
          }
        }
        return PqSymmetricPrimitives.aesGcmDecrypt(
          key: kek,
          nonce: entry.nonce,
          ciphertext: entry.wrappedKey,
          aad: _wrapAad,
        );
      } catch (_) {
        // Wrong recipient for this entry (tag mismatch via the implicit-
        // rejection shared secret) — try the next one.
        continue;
      } finally {
        if (kek != null) PqForgeCombiner.wipe(kek);
      }
    }
    return null;
  }

  /// Parses and validates the `recipients[]` entries in [metadata]. Returns
  /// an empty list when the key is absent; throws [PqForgeException] when an
  /// entry is structurally malformed (untrusted container input).
  static List<
    ({
      String? keyId,
      Uint8List kemCiphertext,
      Uint8List? ephemeralPublicKey,
      Uint8List nonce,
      Uint8List wrappedKey,
    })
  >
  parseEntries(Map<String, Object?> metadata) {
    final raw = metadata[metadataKey];
    if (raw == null) return const [];
    if (raw is! List) {
      throw const PqForgeException('Malformed recipients metadata entry');
    }
    return [
      for (final item in raw)
        _parseEntry(item is Map ? Map<String, Object?>.from(item) : null),
    ];
  }

  static ({
    String? keyId,
    Uint8List kemCiphertext,
    Uint8List? ephemeralPublicKey,
    Uint8List nonce,
    Uint8List wrappedKey,
  })
  _parseEntry(Map<String, Object?>? entry) {
    if (entry == null) {
      throw const PqForgeException('Malformed recipients metadata entry');
    }
    final keyId = entry['keyId'];
    final ephemeral = entry['ephemeralPublicKey'];
    if (keyId is! String?) {
      throw const PqForgeException('Malformed recipients keyId');
    }
    final nonce = _decode(entry['nonce'], 'nonce');
    final wrappedKey = _decode(entry['wrappedKey'], 'wrappedKey');
    requireLength('recipients nonce', nonce, pqForgeDefaultAeadNonceBytes);
    requireLength(
      'recipients wrappedKey',
      wrappedKey,
      pqForgeDefaultSessionKeyBytes + 16,
    );
    final ephemeralPublicKey = ephemeral == null
        ? null
        : _decode(ephemeral, 'ephemeralPublicKey');
    if (ephemeralPublicKey != null) {
      requireLength(
        'recipients ephemeralPublicKey',
        ephemeralPublicKey,
        PqClassicalKeyAgreementAlgorithm.x25519.publicKeyBytes,
      );
    }
    return (
      keyId: keyId,
      kemCiphertext: _decode(entry['kemCiphertext'], 'kemCiphertext'),
      ephemeralPublicKey: ephemeralPublicKey,
      nonce: nonce,
      wrappedKey: wrappedKey,
    );
  }

  static Uint8List _decode(Object? value, String field) {
    if (value is! String) {
      throw PqForgeException('Malformed recipients $field');
    }
    try {
      return base64Decode(value);
    } on FormatException {
      throw PqForgeException('Malformed recipients $field');
    }
  }

  /// KEK for a post-quantum-only entry: plain HKDF-SHA-256 of the entry's own
  /// KEM shared secret, salted by its ciphertext.
  static Uint8List _kekPqc(
    PqForgeProfile profile,
    Uint8List sharedSecret,
    Uint8List kemCiphertext,
  ) {
    return PqSymmetricPrimitives.hkdfSha256(
      ikm: sharedSecret,
      salt: kemCiphertext,
      info: PqBytes.utf8Bytes(
        'pqforge/multi-recipient-kek/${profile.name}/${profile.kem.id}/v1',
      ),
      outputBytes: pqForgeDefaultSessionKeyBytes,
    );
  }

  /// KEK for a hybrid entry: the same concatenate-then-KDF combiner as the
  /// hybrid KEM-DEM (classical share first, ciphertext + ephemeral key as
  /// salt), domain-separated from both it and [_kekPqc].
  static Uint8List _kekHybrid(
    PqForgeProfile profile,
    Uint8List sharedSecret,
    Uint8List kemCiphertext,
    Uint8List classicalSharedSecret,
    Uint8List ephemeralPublicKey,
  ) {
    // SHA-512 combiner for the level 5 KEM, mirroring PqHybridKemDem (which
    // lives upstream of this module and cannot be imported without a cycle).
    final combinerProfile = profile.kem == PqKemAlgorithm.mlKem1024
        ? PqHybridProfile.heavy
        : PqHybridProfile.balanced;
    return PqForgeCombiner(profile: combinerProfile).combine(
      classicalSharedSecret: classicalSharedSecret,
      postQuantumSharedSecret: sharedSecret,
      info: PqBytes.utf8Bytes(
        'pqforge/multi-recipient-kek/${profile.name}/${profile.kem.id}/'
        'x25519/v1',
      ),
      salt: PqBytes.concat([kemCiphertext, ephemeralPublicKey]),
      length: pqForgeDefaultSessionKeyBytes,
    );
  }
}
