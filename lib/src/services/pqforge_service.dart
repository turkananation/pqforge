/// Ergonomic pqforge facade over algorithms, primitives, codecs, keys, and recipes.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_fips.dart';
import '../codecs/pq_envelope.dart';
import '../hybrid/pq_hybrid_combiner.dart';
import '../keys/pq_keys.dart';
import '../primitives/pq_primitives.dart';
import '../recipes/pq_recipes.dart';

typedef PqClassicalSignatureVerifier =
    bool Function(Uint8List message, Uint8List signature);

class PqForge {
  const PqForge({this.profile = PqForgeProfile.balanced});

  final PqForgeProfile profile;

  PqKeyBundle generateKeys({PqForgeProfile? profile, String? keyId}) {
    final selected = profile ?? this.profile;
    return PqKeyBundle(
      profile: selected,
      keyId: keyId,
      kemKeyPair: generateKemKeyPair(algorithm: selected.kem),
      signatureKeyPair: generateSignatureKeyPair(algorithm: selected.signature),
    );
  }

  PqKeyPair generateKemKeyPair({PqKemAlgorithm? algorithm, Uint8List? seed}) {
    return PqKemPrimitives.generateKeyPair(
      algorithm ?? profile.kem,
      seed: seed,
    );
  }

  PqKeyPair generateSignatureKeyPair({PqSignatureAlgorithm? algorithm}) {
    return PqSignaturePrimitives.generateKeyPair(
      algorithm ?? profile.signature,
    );
  }

  PqKeyPair generateSignatureKeyPairFromSeed(
    Uint8List seed, {
    PqSignatureAlgorithm? algorithm,
  }) {
    return PqSignaturePrimitives.generateKeyPairSeeded(
      algorithm ?? profile.signature,
      seed,
    );
  }

  PqKemEncapsulation encapsulate(
    Uint8List publicKey, {
    PqKemAlgorithm? algorithm,
    Uint8List? nonce,
  }) {
    return PqKemPrimitives.encapsulate(
      algorithm ?? profile.kem,
      publicKey,
      nonce: nonce,
    );
  }

  Uint8List decapsulate(
    Uint8List secretKey,
    Uint8List ciphertext, {
    PqKemAlgorithm? algorithm,
  }) {
    return PqKemPrimitives.decapsulate(
      algorithm ?? profile.kem,
      secretKey,
      ciphertext,
    );
  }

  Uint8List sign(
    Uint8List secretKey,
    Uint8List message, {
    PqSignatureAlgorithm? algorithm,
    Uint8List? context,
    bool preHash = false,
  }) {
    return PqSignaturePrimitives.sign(
      algorithm ?? profile.signature,
      secretKey,
      message,
      context: context,
      preHash: preHash,
    );
  }

  bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    PqSignatureAlgorithm? algorithm,
    Uint8List? context,
    bool preHash = false,
  }) {
    return PqSignaturePrimitives.verify(
      algorithm ?? profile.signature,
      publicKey,
      message,
      signature,
      context: context,
      preHash: preHash,
    );
  }

  PqEnvelope encrypt(
    Uint8List recipientPublicKey,
    Uint8List plaintext, {
    PqForgeProfile? profile,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
  }) {
    final selected = profile ?? this.profile;
    final encapsulated = PqKemPrimitives.encapsulate(
      selected.kem,
      recipientPublicKey,
    );
    final key = _kemDemKey(
      selected,
      encapsulated.sharedSecret,
      encapsulated.ciphertext,
    );
    final nonce = PqBytes.randomBytes(pqForgeDefaultAeadNonceBytes);
    final aadHash = aad == null ? null : PqBytes.sha256(aad);
    final payload = PqSymmetricPrimitives.aesGcmEncrypt(
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      aad: aad ?? encapsulated.ciphertext,
    );
    final effectiveSignatureAlgorithm = signerSecretKey == null
        ? signatureAlgorithm
        : (signatureAlgorithm ?? selected.signature);

    if (signerSecretKey == null) {
      return PqEnvelope(
        profile: selected,
        kemAlgorithm: selected.kem,
        signatureAlgorithm: effectiveSignatureAlgorithm,
        kemCiphertext: encapsulated.ciphertext,
        nonce: nonce,
        payload: payload,
        aadHash: aadHash,
        signerKeyId: signerKeyId,
        metadata: metadata,
      );
    }

    // Phase 2 (M1): sign a 32-byte digest of the header plus a single SHA-256 of
    // the payload — never the whole payload concatenated into a fresh buffer.
    // The signature's cost and memory are independent of payload size, and the
    // envelope is built exactly once (also fixes the M3 double-build).
    final digest = _envelopeSigningDigest(
      profile: selected,
      kemAlgorithm: selected.kem,
      signatureAlgorithm: effectiveSignatureAlgorithm,
      nonce: nonce,
      kemCiphertext: encapsulated.ciphertext,
      payload: payload,
      aadHash: aadHash,
      signerKeyId: signerKeyId,
      metadata: metadata,
    );
    final signature = sign(
      signerSecretKey,
      digest,
      algorithm: effectiveSignatureAlgorithm,
      context: _envelopeSignatureContext,
      preHash: true,
    );
    return PqEnvelope(
      profile: selected,
      kemAlgorithm: selected.kem,
      signatureAlgorithm: effectiveSignatureAlgorithm,
      kemCiphertext: encapsulated.ciphertext,
      nonce: nonce,
      payload: payload,
      aadHash: aadHash,
      signerKeyId: signerKeyId,
      signature: signature,
      metadata: metadata,
    );
  }

  PqEnvelope sealToKemPublicKey(
    Uint8List recipientPublicKey,
    Uint8List plaintext, {
    PqKemAlgorithm? algorithm,
    Uint8List? aad,
    Uint8List? info,
    Uint8List? nonce,
  }) {
    final selectedProfile = algorithm == null
        ? profile
        : PqForgeProfile(
            name: 'custom-${algorithm.id}-${profile.signature.id}',
            kem: algorithm,
            signature: profile.signature,
          );
    return encrypt(
      recipientPublicKey,
      plaintext,
      profile: selectedProfile,
      aad: aad,
      metadata: {
        'recipe': 'kem-dem',
        if (info != null) 'infoHashSha256': base64Encode(PqBytes.sha256(info)),
        if (nonce != null) 'requestedNonceIgnored': true,
      },
    );
  }

  Uint8List openFromKemSecretKey(
    Uint8List recipientSecretKey,
    PqEnvelope envelope, {
    Uint8List? aad,
    Uint8List? info,
  }) {
    _validateMetadataHash(
      metadata: envelope.metadata,
      field: 'infoHashSha256',
      label: 'info',
      supplied: info,
    );
    return decrypt(recipientSecretKey, envelope, aad: aad);
  }

  PqEnvelope sealAndSign(
    Uint8List recipientPublicKey,
    Uint8List signerSecretKey,
    Uint8List plaintext, {
    PqKemAlgorithm? kemAlgorithm,
    PqSignatureAlgorithm? signatureAlgorithm,
    Uint8List? aad,
    Uint8List? signatureContext,
  }) {
    final selectedProfile = kemAlgorithm == null && signatureAlgorithm == null
        ? profile
        : PqForgeProfile(
            name:
                'custom-${(kemAlgorithm ?? profile.kem).id}-'
                '${(signatureAlgorithm ?? profile.signature).id}',
            kem: kemAlgorithm ?? profile.kem,
            signature: signatureAlgorithm ?? profile.signature,
          );
    return encrypt(
      recipientPublicKey,
      plaintext,
      profile: selectedProfile,
      aad: aad,
      signerSecretKey: signerSecretKey,
      signatureAlgorithm: signatureAlgorithm,
      metadata: {
        'recipe': 'signed-kem-dem',
        if (signatureContext != null)
          'signatureContextHashSha256': base64Encode(
            PqBytes.sha256(signatureContext),
          ),
      },
    );
  }

  Uint8List openSignedFromKemSecretKey(
    Uint8List recipientSecretKey,
    Uint8List signerPublicKey,
    PqEnvelope envelope, {
    Uint8List? aad,
    Uint8List? signatureContext,
  }) {
    _validateMetadataHash(
      metadata: envelope.metadata,
      field: 'signatureContextHashSha256',
      label: 'signatureContext',
      supplied: signatureContext,
    );
    return decrypt(
      recipientSecretKey,
      envelope,
      aad: aad,
      signerPublicKey: signerPublicKey,
    );
  }

  Uint8List decrypt(
    Uint8List recipientSecretKey,
    PqEnvelope envelope, {
    Uint8List? aad,
    Uint8List? signerPublicKey,
  }) {
    _validateEnvelopeAad(envelope, aad);
    if (envelope.signature != null) {
      if (signerPublicKey == null) {
        throw const PqForgeException(
          'signerPublicKey is required for signed envelope',
        );
      }
      final ok = verify(
        signerPublicKey,
        envelopeSigningMessage(envelope),
        envelope.signature!,
        algorithm: envelope.signatureAlgorithm,
        context: _envelopeSignatureContext,
        preHash: true,
      );
      if (!ok) {
        throw const PqForgeException(
          'ML-DSA envelope signature verification failed',
        );
      }
    }
    final sharedSecret = PqKemPrimitives.decapsulate(
      envelope.kemAlgorithm,
      recipientSecretKey,
      envelope.kemCiphertext,
    );
    final key = _kemDemKey(
      envelope.profile,
      sharedSecret,
      envelope.kemCiphertext,
    );
    return PqSymmetricPrimitives.aesGcmDecrypt(
      key: key,
      nonce: envelope.nonce,
      ciphertext: envelope.payload,
      aad: aad ?? envelope.kemCiphertext,
    );
  }

  PqEnvelope encryptFileBytes(
    Uint8List recipientPublicKey,
    Uint8List fileBytes, {
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    PqForgeProfile profile = PqForgeProfile.maximum,
  }) {
    return encrypt(
      recipientPublicKey,
      fileBytes,
      aad: aad,
      metadata: {'recipe': 'file-encryption', ...metadata},
      profile: profile,
    );
  }

  Uint8List decryptFileBytes(
    Uint8List recipientSecretKey,
    PqEnvelope envelope, {
    Uint8List? aad,
  }) {
    return decrypt(recipientSecretKey, envelope, aad: aad);
  }

  Uint8List signDocument(
    Uint8List secretKey,
    Uint8List documentBytes, {
    required String documentId,
    PqSignatureAlgorithm? algorithm,
  }) {
    return sign(
      secretKey,
      PqRecipeMessages.document(
        documentId: documentId,
        documentBytes: documentBytes,
      ),
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/document/v1'),
      preHash: true,
    );
  }

  bool verifyDocument(
    Uint8List publicKey,
    Uint8List documentBytes,
    Uint8List signature, {
    required String documentId,
    PqSignatureAlgorithm? algorithm,
  }) {
    return verify(
      publicKey,
      PqRecipeMessages.document(
        documentId: documentId,
        documentBytes: documentBytes,
      ),
      signature,
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/document/v1'),
      preHash: true,
    );
  }

  Uint8List signText({
    required Uint8List signerSecretKey,
    required String text,
    required String textId,
    PqSignatureAlgorithm? algorithm,
  }) {
    final textBytes = PqBytes.utf8Bytes(text);
    return sign(
      signerSecretKey,
      PqRecipeMessages.text(
        textId: textId,
        encoding: 'utf-8',
        textBytes: textBytes,
      ),
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/text/v1'),
      preHash: true,
    );
  }

  bool verifyText({
    required Uint8List signerPublicKey,
    required String text,
    required String textId,
    required Uint8List signature,
    PqSignatureAlgorithm? algorithm,
  }) {
    final textBytes = PqBytes.utf8Bytes(text);
    return verify(
      signerPublicKey,
      PqRecipeMessages.text(
        textId: textId,
        encoding: 'utf-8',
        textBytes: textBytes,
      ),
      signature,
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/text/v1'),
      preHash: true,
    );
  }

  Uint8List signMedia({
    required Uint8List signerSecretKey,
    required String mediaId,
    required String mimeType,
    required Uint8List mediaBytes,
    PqSignatureAlgorithm? algorithm,
  }) {
    return sign(
      signerSecretKey,
      PqRecipeMessages.media(
        mediaId: mediaId,
        mimeType: mimeType,
        mediaBytes: mediaBytes,
      ),
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/media/v1'),
      preHash: true,
    );
  }

  bool verifyMedia({
    required Uint8List signerPublicKey,
    required String mediaId,
    required String mimeType,
    required Uint8List mediaBytes,
    required Uint8List signature,
    PqSignatureAlgorithm? algorithm,
  }) {
    return verify(
      signerPublicKey,
      PqRecipeMessages.media(
        mediaId: mediaId,
        mimeType: mimeType,
        mediaBytes: mediaBytes,
      ),
      signature,
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/media/v1'),
      preHash: true,
    );
  }

  Uint8List signWebhook({
    required Uint8List signerSecretKey,
    required String eventType,
    required int timestampMs,
    required Uint8List payload,
    PqSignatureAlgorithm? algorithm,
  }) {
    return sign(
      signerSecretKey,
      PqRecipeMessages.webhook(
        eventType: eventType,
        timestampMs: timestampMs,
        payload: payload,
      ),
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/webhook/v1'),
      preHash: true,
    );
  }

  bool verifyWebhook({
    required Uint8List signerPublicKey,
    required String eventType,
    required int timestampMs,
    required Uint8List payload,
    required Uint8List signature,
    PqSignatureAlgorithm? algorithm,
    int? nowMs,
    int maxSkewMs = 300000,
  }) {
    if (nowMs != null && (nowMs - timestampMs).abs() > maxSkewMs) {
      return false;
    }
    return verify(
      signerPublicKey,
      PqRecipeMessages.webhook(
        eventType: eventType,
        timestampMs: timestampMs,
        payload: payload,
      ),
      signature,
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/webhook/v1'),
      preHash: true,
    );
  }

  PqEnvelope sealText(
    Uint8List recipientPublicKey,
    String text, {
    required String textId,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    PqForgeProfile profile = PqForgeProfile.maximum,
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
  }) {
    return encrypt(
      recipientPublicKey,
      PqBytes.utf8Bytes(text),
      profile: profile,
      aad: PqRecipeMessages.textAad(textId: textId, aad: aad),
      metadata: {
        'recipe': 'text-seal',
        'textId': textId,
        'encoding': 'utf-8',
        ...metadata,
      },
      signerSecretKey: signerSecretKey,
      signatureAlgorithm: signatureAlgorithm,
      signerKeyId: signerKeyId,
    );
  }

  String openText(
    Uint8List recipientSecretKey,
    PqEnvelope envelope, {
    Uint8List? aad,
    Uint8List? signerPublicKey,
  }) {
    final textId = envelope.metadata['textId'];
    if (textId is! String || textId.isEmpty) {
      throw const PqForgeException(
        'text envelope metadata must include textId',
      );
    }
    final encoding = envelope.metadata['encoding'] as String? ?? 'utf-8';
    if (encoding != 'utf-8') {
      throw PqForgeException('Unsupported text envelope encoding: $encoding');
    }
    final plaintext = decrypt(
      recipientSecretKey,
      envelope,
      aad: PqRecipeMessages.textAad(textId: textId, aad: aad),
      signerPublicKey: signerPublicKey,
    );
    return utf8.decode(plaintext);
  }

  PqEnvelope sealEmail(
    Uint8List recipientPublicKey,
    Uint8List emailBytes, {
    required String messageId,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    PqForgeProfile profile = PqForgeProfile.maximum,
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
  }) {
    return encrypt(
      recipientPublicKey,
      emailBytes,
      profile: profile,
      aad: PqRecipeMessages.emailAad(messageId: messageId, aad: aad),
      metadata: {'recipe': 'email-seal', 'messageId': messageId, ...metadata},
      signerSecretKey: signerSecretKey,
      signatureAlgorithm: signatureAlgorithm,
      signerKeyId: signerKeyId,
    );
  }

  PqEnvelope sealMedia(
    Uint8List recipientPublicKey,
    Uint8List mediaBytes, {
    required String mediaId,
    required String mimeType,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    PqForgeProfile profile = PqForgeProfile.maximum,
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
  }) {
    return encrypt(
      recipientPublicKey,
      mediaBytes,
      profile: profile,
      aad: PqRecipeMessages.mediaAad(
        mediaId: mediaId,
        mimeType: mimeType,
        aad: aad,
      ),
      metadata: {
        'recipe': 'media-seal',
        'mediaId': mediaId,
        'mimeType': mimeType,
        'contentLength': mediaBytes.length,
        ...metadata,
      },
      signerSecretKey: signerSecretKey,
      signatureAlgorithm: signatureAlgorithm,
      signerKeyId: signerKeyId,
    );
  }

  Uint8List openMedia(
    Uint8List recipientSecretKey,
    PqEnvelope envelope, {
    Uint8List? aad,
    Uint8List? signerPublicKey,
  }) {
    final mediaId = envelope.metadata['mediaId'];
    final mimeType = envelope.metadata['mimeType'];
    if (mediaId is! String || mediaId.isEmpty) {
      throw const PqForgeException(
        'media envelope metadata must include mediaId',
      );
    }
    if (mimeType is! String || mimeType.isEmpty) {
      throw const PqForgeException(
        'media envelope metadata must include mimeType',
      );
    }
    return decrypt(
      recipientSecretKey,
      envelope,
      aad: PqRecipeMessages.mediaAad(
        mediaId: mediaId,
        mimeType: mimeType,
        aad: aad,
      ),
      signerPublicKey: signerPublicKey,
    );
  }

  Uint8List openEmail(
    Uint8List recipientSecretKey,
    PqEnvelope envelope, {
    Uint8List? aad,
    Uint8List? signerPublicKey,
  }) {
    final messageId = envelope.metadata['messageId'];
    if (messageId is! String || messageId.isEmpty) {
      throw const PqForgeException(
        'email envelope metadata must include messageId',
      );
    }
    return decrypt(
      recipientSecretKey,
      envelope,
      aad: PqRecipeMessages.emailAad(messageId: messageId, aad: aad),
      signerPublicKey: signerPublicKey,
    );
  }

  PqSignedToken issueToken({
    required Uint8List signerSecretKey,
    required String issuer,
    required String subject,
    required int issuedAtMs,
    required int expiresAtMs,
    Map<String, Object?> claims = const {},
    PqSignatureAlgorithm? algorithm,
  }) {
    final sigAlg = algorithm ?? PqSignatureAlgorithm.mlDsa44;
    final message = PqRecipeMessages.token(
      issuer: issuer,
      subject: subject,
      issuedAtMs: issuedAtMs,
      expiresAtMs: expiresAtMs,
      claims: claims,
    );
    final signature = sign(
      signerSecretKey,
      message,
      algorithm: sigAlg,
      context: PqBytes.utf8Bytes('pqforge/signed-token/v1'),
    );
    return PqSignedToken(
      issuer: issuer,
      subject: subject,
      issuedAtMs: issuedAtMs,
      expiresAtMs: expiresAtMs,
      claims: claims,
      signatureAlgorithm: sigAlg,
      signature: signature,
    );
  }

  bool verifyToken(
    Uint8List signerPublicKey,
    PqSignedToken token, {
    int? nowMs,
  }) {
    if (nowMs != null &&
        (nowMs < token.issuedAtMs || nowMs >= token.expiresAtMs)) {
      return false;
    }
    return verify(
      signerPublicKey,
      token.message(),
      token.signature,
      algorithm: token.signatureAlgorithm,
      context: PqBytes.utf8Bytes('pqforge/signed-token/v1'),
    );
  }

  PqEnvelope encryptFolderEntry(
    Uint8List recipientPublicKey,
    Uint8List fileBytes, {
    required String relativePath,
    Uint8List? aad,
    Map<String, Object?> metadata = const {},
    PqForgeProfile profile = PqForgeProfile.maximum,
    Uint8List? signerSecretKey,
    PqSignatureAlgorithm? signatureAlgorithm,
    String? signerKeyId,
  }) {
    final fileName = relativePath.split('/').last;
    return encrypt(
      recipientPublicKey,
      fileBytes,
      profile: profile,
      aad: PqRecipeMessages.folderEntryAad(
        relativePath: relativePath,
        aad: aad,
      ),
      metadata: {
        'recipe': 'folder-entry-encryption',
        'fileName': fileName,
        'relativePath': relativePath,
        'contentLength': fileBytes.length,
        ...metadata,
      },
      signerSecretKey: signerSecretKey,
      signatureAlgorithm: signatureAlgorithm,
      signerKeyId: signerKeyId,
    );
  }

  Uint8List decryptFolderEntry(
    Uint8List recipientSecretKey,
    PqEnvelope envelope, {
    Uint8List? aad,
    Uint8List? signerPublicKey,
  }) {
    final relativePath = envelope.metadata['relativePath'];
    if (relativePath is! String || relativePath.isEmpty) {
      throw const PqForgeException(
        'folder envelope metadata must include relativePath',
      );
    }
    return decrypt(
      recipientSecretKey,
      envelope,
      aad: PqRecipeMessages.folderEntryAad(
        relativePath: relativePath,
        aad: aad,
      ),
      signerPublicKey: signerPublicKey,
    );
  }

  PqEnvelope encryptRecord(
    Uint8List recipientPublicKey,
    Uint8List payload, {
    required String recordType,
    required String recordId,
    Uint8List? aad,
    PqForgeProfile profile = PqForgeProfile.maximum,
  }) {
    return encrypt(
      recipientPublicKey,
      payload,
      aad: aad,
      profile: profile,
      metadata: {
        'recipe': 'encrypted-record',
        'recordType': recordType,
        'recordId': recordId,
        'recordMessageHashSha256': base64Encode(
          PqBytes.sha256(
            PqRecipeMessages.record(
              recordType: recordType,
              recordId: recordId,
              payload: payload,
            ),
          ),
        ),
      },
    );
  }

  /// Wraps an exported key under a passphrase: KDF → AES-256-GCM with the key
  /// identity bound into the AAD.
  ///
  /// [kdf] selects the password KDF: [PqKdf.argon2id] (default — the stronger
  /// choice) or [PqKdf.pbkdf2HmacSha256] (the FIPS-approved one, required when
  /// [PqFipsMode] is enabled). [iterations]/[memoryPowerOf2]/[lanes] are
  /// Argon2id parameters; [pbkdf2Iterations] is the PBKDF2 cost.
  PqWrappedKey wrapKeyWithPassphrase(
    PqExportedKey key,
    String passphrase, {
    String kdf = PqKdf.argon2id,
    int iterations = 2,
    int memoryPowerOf2 = 16,
    int lanes = 4,
    int pbkdf2Iterations = 600000,
  }) {
    PqFipsMode.requireApprovedKdf(kdf);
    final salt = PqBytes.randomBytes(16);
    final nonce = PqBytes.randomBytes(pqForgeDefaultAeadNonceBytes);
    final wrappingKey = switch (kdf) {
      PqKdf.argon2id => PqSymmetricPrimitives.argon2id(
        password: passphrase,
        salt: salt,
        iterations: iterations,
        memoryPowerOf2: memoryPowerOf2,
        lanes: lanes,
      ),
      PqKdf.pbkdf2HmacSha256 => PqSymmetricPrimitives.pbkdf2Sha256(
        password: passphrase,
        salt: salt,
        iterations: pbkdf2Iterations,
      ),
      _ => throw PqForgeException('Unsupported key-wrap KDF: $kdf'),
    };
    final aad = _wrappedKeyAad(key.kind, key.algorithmId, key.keyId);
    final ciphertext = PqSymmetricPrimitives.aesGcmEncrypt(
      key: wrappingKey,
      nonce: nonce,
      plaintext: key.bytes,
      aad: aad,
    );
    return PqWrappedKey(
      kdf: kdf,
      aead: 'aes-256-gcm',
      salt: salt,
      nonce: nonce,
      ciphertext: ciphertext,
      keyKind: key.kind,
      algorithmId: key.algorithmId,
      keyId: key.keyId,
      iterations: kdf == PqKdf.pbkdf2HmacSha256 ? pbkdf2Iterations : iterations,
      memoryPowerOf2: memoryPowerOf2,
      lanes: lanes,
    );
  }

  PqExportedKey unwrapKeyWithPassphrase(
    PqWrappedKey wrapped,
    String passphrase,
  ) {
    PqFipsMode.requireApprovedKdf(wrapped.kdf);
    final wrappingKey = switch (wrapped.kdf) {
      PqKdf.argon2id => PqSymmetricPrimitives.argon2id(
        password: passphrase,
        salt: wrapped.salt,
        iterations: wrapped.iterations,
        memoryPowerOf2: wrapped.memoryPowerOf2,
        lanes: wrapped.lanes,
      ),
      PqKdf.pbkdf2HmacSha256 => PqSymmetricPrimitives.pbkdf2Sha256(
        password: passphrase,
        salt: wrapped.salt,
        iterations: wrapped.iterations,
      ),
      _ => throw PqForgeException('Unsupported key-wrap KDF: ${wrapped.kdf}'),
    };
    final aad = _wrappedKeyAad(
      wrapped.keyKind,
      wrapped.algorithmId,
      wrapped.keyId,
    );
    final bytes = PqSymmetricPrimitives.aesGcmDecrypt(
      key: wrappingKey,
      nonce: wrapped.nonce,
      ciphertext: wrapped.ciphertext,
      aad: aad,
    );
    return PqExportedKey(
      kind: wrapped.keyKind,
      algorithmId: wrapped.algorithmId,
      keyId: wrapped.keyId,
      bytes: bytes,
    );
  }

  PqIdentityBinding createIdentityBinding({
    required Uint8List authoritySecretKey,
    required String subjectId,
    required Uint8List identityPublicKey,
    required int notBeforeMs,
    required int expiresAtMs,
    PqSignatureAlgorithm? algorithm,
  }) {
    final sigAlg = algorithm ?? profile.signature;
    final message = PqRecipeMessages.identityBinding(
      subjectId: subjectId,
      identityPublicKey: identityPublicKey,
      notBeforeMs: notBeforeMs,
      expiresAtMs: expiresAtMs,
    );
    final signature = sign(
      authoritySecretKey,
      message,
      algorithm: sigAlg,
      context: PqBytes.utf8Bytes('pqforge/identity-binding/v1'),
    );
    return PqIdentityBinding(
      subjectId: subjectId,
      identityPublicKey: identityPublicKey,
      notBeforeMs: notBeforeMs,
      expiresAtMs: expiresAtMs,
      signatureAlgorithm: sigAlg,
      authoritySignature: signature,
    );
  }

  bool verifyIdentityBinding(
    Uint8List authorityPublicKey,
    PqIdentityBinding binding,
  ) {
    return verify(
      authorityPublicKey,
      binding.message(),
      binding.authoritySignature,
      algorithm: binding.signatureAlgorithm,
      context: PqBytes.utf8Bytes('pqforge/identity-binding/v1'),
    );
  }

  PqSignedLogEntry appendSignedLogEntry({
    required Uint8List signerSecretKey,
    required Uint8List previousHash,
    required Uint8List payload,
    required int timestampMs,
    PqSignatureAlgorithm? algorithm,
  }) {
    final sigAlg = algorithm ?? PqSignatureAlgorithm.mlDsa44;
    final message = PqRecipeMessages.logEntry(
      previousHash: previousHash,
      payload: payload,
      timestampMs: timestampMs,
    );
    final signature = sign(
      signerSecretKey,
      message,
      algorithm: sigAlg,
      context: PqBytes.utf8Bytes('pqforge/signed-log/v1'),
    );
    return PqSignedLogEntry(
      previousHash: previousHash,
      payload: payload,
      timestampMs: timestampMs,
      signatureAlgorithm: sigAlg,
      signature: signature,
    );
  }

  bool verifySignedLogEntry(Uint8List signerPublicKey, PqSignedLogEntry entry) {
    return verify(
      signerPublicKey,
      entry.message(),
      entry.signature,
      algorithm: entry.signatureAlgorithm,
      context: PqBytes.utf8Bytes('pqforge/signed-log/v1'),
    );
  }

  PqArtifactSignature signArtifact({
    required Uint8List signerSecretKey,
    required String artifactId,
    required int version,
    required Uint8List artifactBytes,
    PqSignatureAlgorithm? algorithm,
  }) {
    final sigAlg = algorithm ?? profile.signature;
    final artifactHash = PqBytes.sha256(artifactBytes);
    final message = PqRecipeMessages.artifact(
      artifactId: artifactId,
      version: version,
      artifactHash: artifactHash,
    );
    final signature = sign(
      signerSecretKey,
      message,
      algorithm: sigAlg,
      context: PqBytes.utf8Bytes('pqforge/artifact-signature/v1'),
      preHash: true,
    );
    return PqArtifactSignature(
      artifactId: artifactId,
      version: version,
      artifactHash: artifactHash,
      signatureAlgorithm: sigAlg,
      signature: signature,
    );
  }

  bool verifyArtifact(
    Uint8List signerPublicKey,
    Uint8List artifactBytes,
    PqArtifactSignature artifact,
  ) {
    final artifactHash = PqBytes.sha256(artifactBytes);
    if (!PqBytes.constantTimeEquals(artifactHash, artifact.artifactHash)) {
      return false;
    }
    return verify(
      signerPublicKey,
      artifact.message(),
      artifact.signature,
      algorithm: artifact.signatureAlgorithm,
      context: PqBytes.utf8Bytes('pqforge/artifact-signature/v1'),
      preHash: true,
    );
  }

  PqDualSignature dualSign({
    required Uint8List secretKey,
    required Uint8List message,
    required Uint8List classicalSignature,
    PqSignatureAlgorithm? algorithm,
    PqDualSignaturePolicy policy = PqDualSignaturePolicy.requireBoth,
  }) {
    final pqc = sign(
      secretKey,
      message,
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/dual-signature/v1'),
    );
    return PqDualSignature(
      pqcSignature: pqc,
      classicalSignature: classicalSignature,
      policy: policy,
    );
  }

  bool dualVerify({
    required Uint8List publicKey,
    required Uint8List message,
    required PqDualSignature signature,
    required PqClassicalSignatureVerifier classicalVerifier,
    PqSignatureAlgorithm? algorithm,
  }) {
    final pqcValid = verify(
      publicKey,
      message,
      signature.pqcSignature,
      algorithm: algorithm,
      context: PqBytes.utf8Bytes('pqforge/dual-signature/v1'),
    );
    final classicalValid = classicalVerifier(
      message,
      signature.classicalSignature,
    );
    return signature.combine(pqcValid, classicalValid);
  }

  Uint8List deriveHybridSessionKey({
    required Uint8List classicalSharedSecret,
    required Uint8List latticeSharedSecret,
    required Uint8List deploymentSalt,
    required Uint8List transcriptHash,
    Uint8List? roleContext,
    int? outputBytes,
  }) {
    requireLength('classicalSharedSecret', classicalSharedSecret, 32);
    requireLength('latticeSharedSecret', latticeSharedSecret, 32);
    requireLength(
      'deploymentSalt',
      deploymentSalt,
      pqForgeDefaultDeploymentSaltBytes,
    );
    requireLength('transcriptHash', transcriptHash, 32);
    // Delegates to the profile-agile PqForgeCombiner. The balanced profile
    // pins SHA-256, keeping this byte-compatible with prior releases while the
    // combiner owns the canonical classical||post-quantum join and wiping.
    return const PqForgeCombiner.balanced().combine(
      classicalSharedSecret: classicalSharedSecret,
      postQuantumSharedSecret: latticeSharedSecret,
      info: PqBytes.concat([
        PqBytes.utf8Bytes(profile.infoPrefix),
        ?roleContext,
      ]),
      salt: PqBytes.concat([deploymentSalt, transcriptHash]),
      length: outputBytes ?? profile.sessionKeyBytes,
    );
  }

  Uint8List hkdfSha256({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    int outputBytes = pqForgeDefaultSessionKeyBytes,
  }) {
    return PqSymmetricPrimitives.hkdfSha256(
      ikm: ikm,
      salt: salt,
      info: info,
      outputBytes: outputBytes,
    );
  }

  Uint8List aesGcmEncrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    Uint8List? aad,
  }) {
    return PqSymmetricPrimitives.aesGcmEncrypt(
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      aad: aad,
    );
  }

  Uint8List aesGcmDecrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    Uint8List? aad,
  }) {
    return PqSymmetricPrimitives.aesGcmDecrypt(
      key: key,
      nonce: nonce,
      ciphertext: ciphertext,
      aad: aad,
    );
  }

  Uint8List argon2id({
    required String password,
    required Uint8List salt,
    int outputBytes = pqForgeDefaultSessionKeyBytes,
    int iterations = 2,
    int memoryPowerOf2 = 16,
    int lanes = 4,
  }) {
    return PqSymmetricPrimitives.argon2id(
      password: password,
      salt: salt,
      outputBytes: outputBytes,
      iterations: iterations,
      memoryPowerOf2: memoryPowerOf2,
      lanes: lanes,
    );
  }

  /// The 32-byte digest fed to ML-DSA sign/verify (`preHash:true`) for an
  /// envelope's signature: `SHA-256(headerFields ‖ SHA-256(payload))`. The
  /// payload is hashed in one streaming pass, so neither the digest nor the
  /// signature scales with payload size (the M1 fix). The header binds every
  /// envelope field except the signature itself.
  Uint8List envelopeSigningMessage(PqEnvelope envelope) =>
      _envelopeSigningDigest(
        profile: envelope.profile,
        kemAlgorithm: envelope.kemAlgorithm,
        signatureAlgorithm: envelope.signatureAlgorithm,
        nonce: envelope.nonce,
        kemCiphertext: envelope.kemCiphertext,
        payload: envelope.payload,
        aadHash: envelope.aadHash,
        signerKeyId: envelope.signerKeyId,
        metadata: envelope.metadata,
      );

  Uint8List _envelopeSigningDigest({
    required PqForgeProfile profile,
    required PqKemAlgorithm kemAlgorithm,
    required PqSignatureAlgorithm? signatureAlgorithm,
    required Uint8List nonce,
    required Uint8List kemCiphertext,
    required Uint8List payload,
    required Uint8List? aadHash,
    required String? signerKeyId,
    required Map<String, Object?> metadata,
  }) {
    final header = PqBytes.lengthPrefixed([
      PqBytes.utf8Bytes('pqforge/envelope-signing-message/v1'),
      PqBytes.uint32(pqForgeEnvelopeVersion),
      PqBytes.utf8Bytes(profile.name),
      PqBytes.utf8Bytes(kemAlgorithm.id),
      PqBytes.utf8Bytes(signatureAlgorithm?.id ?? ''),
      nonce,
      kemCiphertext,
      aadHash ?? Uint8List(0),
      PqBytes.utf8Bytes(signerKeyId ?? ''),
      PqRecipeMessages.metadata(metadata),
    ]);
    final payloadHash = PqBytes.sha256(payload);
    return PqBytes.sha256(PqBytes.concat([header, payloadHash]));
  }

  Uint8List get _envelopeSignatureContext =>
      PqBytes.utf8Bytes('pqforge/envelope-signature/v1');

  /// Derives the per-message DEM key from a KEM shared secret and ciphertext.
  ///
  /// Exposed so the streaming `.pqfs` path derives a byte-identical key to the
  /// one-shot envelope path (both feed [_kemDemKey] / this method), keeping the
  /// two formats interoperable at the key-schedule level.
  static Uint8List deriveDemKey(
    PqForgeProfile profile,
    Uint8List sharedSecret,
    Uint8List kemCiphertext,
  ) {
    return PqSymmetricPrimitives.hkdfSha256(
      ikm: sharedSecret,
      salt: kemCiphertext,
      info: PqBytes.utf8Bytes(
        'pqforge/kem-dem/${profile.name}/${profile.kem.id}/v1',
      ),
      outputBytes: profile.sessionKeyBytes,
    );
  }

  Uint8List _kemDemKey(
    PqForgeProfile selected,
    Uint8List sharedSecret,
    Uint8List ciphertext,
  ) => deriveDemKey(selected, sharedSecret, ciphertext);

  Uint8List _wrappedKeyAad(String kind, String algorithmId, String? keyId) {
    return PqBytes.lengthPrefixed([
      PqBytes.utf8Bytes('pqforge/wrapped-key/v1'),
      PqBytes.utf8Bytes(kind),
      PqBytes.utf8Bytes(algorithmId),
      PqBytes.utf8Bytes(keyId ?? ''),
    ]);
  }

  void _validateEnvelopeAad(PqEnvelope envelope, Uint8List? aad) {
    if (envelope.aadHash == null) return;
    if (aad == null) {
      throw const PqForgeException('AAD is required for this envelope');
    }
    final actual = PqBytes.sha256(aad);
    if (!PqBytes.constantTimeEquals(actual, envelope.aadHash!)) {
      throw const PqForgeException('AAD hash mismatch');
    }
  }

  void _validateMetadataHash({
    required Map<String, Object?> metadata,
    required String field,
    required String label,
    Uint8List? supplied,
  }) {
    final encoded = metadata[field];
    if (encoded == null) return;
    if (encoded is! String) {
      throw PqForgeException('Invalid $label hash metadata');
    }
    if (supplied == null) {
      throw PqForgeException('$label is required for this envelope');
    }
    final expected = base64Decode(encoded);
    requireLength('$label hash', expected, 32);
    final actual = PqBytes.sha256(supplied);
    if (!PqBytes.constantTimeEquals(actual, expected)) {
      throw PqForgeException('$label hash mismatch');
    }
  }
}
