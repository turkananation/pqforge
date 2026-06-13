/// OpenSSL EVP AEAD bindings for interop verification — dev tool only.
///
/// This file lives in the **separate** `openssl_pqforge_interop` dev-tool
/// package (`publish_to: none`), NOT in the published `pqforge` package, which
/// stays pure Dart with no `dart:ffi` anywhere. It exists to cross-check the
/// pure-Dart AEAD engines (AES-256-GCM and ChaCha20-Poly1305 on both the
/// `package:cryptography` and PointyCastle backends) against OpenSSL's EVP
/// implementation byte for byte, and to measure the hardware throughput
/// ceiling pure Dart is compared against. Same policy as pqcrypto's
/// `tool/openssl_interop/lib/openssl_ml_kem.dart` for ML-KEM.
///
/// Nothing native is bundled: the system `libcrypto` is resolved at runtime
/// ([resolveLibcryptoPath]) and absence is non-fatal ([OpenSslAead.tryLoad]
/// returns null so harnesses can skip).
library;

// OpenSSL's C names are kept verbatim for greppability against its docs.
// ignore_for_file: camel_case_types

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Opaque `EVP_CIPHER_CTX`.
final class EVP_CIPHER_CTX extends Opaque {}

/// Opaque `EVP_CIPHER`.
final class EVP_CIPHER extends Opaque {}

typedef _EvpCipherCtxNewNative = Pointer<EVP_CIPHER_CTX> Function();
typedef _EvpCipherCtxNewDart = Pointer<EVP_CIPHER_CTX> Function();
typedef _EvpCipherCtxFreeNative = Void Function(Pointer<EVP_CIPHER_CTX>);
typedef _EvpCipherCtxFreeDart = void Function(Pointer<EVP_CIPHER_CTX>);
typedef _EvpCipherFnNative = Pointer<EVP_CIPHER> Function();
typedef _EvpCipherFnDart = Pointer<EVP_CIPHER> Function();
typedef _EvpInitNative =
    Int32 Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<EVP_CIPHER>,
      Pointer<Void>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _EvpInitDart =
    int Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<EVP_CIPHER>,
      Pointer<Void>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _EvpUpdateNative =
    Int32 Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<Uint8>,
      Pointer<Int32>,
      Pointer<Uint8>,
      Int32,
    );
typedef _EvpUpdateDart =
    int Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<Uint8>,
      Pointer<Int32>,
      Pointer<Uint8>,
      int,
    );
typedef _EvpFinalNative =
    Int32 Function(Pointer<EVP_CIPHER_CTX>, Pointer<Uint8>, Pointer<Int32>);
typedef _EvpFinalDart =
    int Function(Pointer<EVP_CIPHER_CTX>, Pointer<Uint8>, Pointer<Int32>);
typedef _EvpCtrlNative =
    Int32 Function(Pointer<EVP_CIPHER_CTX>, Int32, Int32, Pointer<Void>);
typedef _EvpCtrlDart =
    int Function(Pointer<EVP_CIPHER_CTX>, int, int, Pointer<Void>);
typedef _OpenSslVersionNative = Pointer<Utf8> Function(Int32);
typedef _OpenSslVersionDart = Pointer<Utf8> Function(int);

// EVP_CTRL_AEAD_* control codes (same values for GCM and ChaCha20-Poly1305).
const _evpCtrlAeadSetIvLen = 0x9;
const _evpCtrlAeadGetTag = 0x10;
const _evpCtrlAeadSetTag = 0x11;

/// AEAD authentication failure from OpenSSL (`EVP_DecryptFinal_ex` != 1) —
/// the analogue of pqforge's `PqForgeAuthTagException`, kept distinct so the
/// harness can assert tamper detection on both sides.
final class OpenSslAuthFailure implements Exception {
  const OpenSslAuthFailure(this.message);

  final String message;

  @override
  String toString() => 'OpenSslAuthFailure: $message';
}

/// Resolves a loadable `libcrypto` path/soname, or null when unavailable.
///
/// Order: the `LIBCRYPTO_PATH` environment override, then platform-typical
/// candidates (bare sonames go through the system loader).
String? resolveLibcryptoPath() {
  final override = Platform.environment['LIBCRYPTO_PATH'];
  final candidates = <String>[
    if (override != null && override.isNotEmpty) override,
    if (Platform.isLinux) ...[
      'libcrypto.so.3',
      'libcrypto.so.1.1',
      'libcrypto.so',
      '/usr/local/lib64/libcrypto.so',
      '/usr/local/lib/libcrypto.so',
    ],
    if (Platform.isMacOS) ...[
      '/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib',
      '/opt/homebrew/opt/openssl@3.6/lib/libcrypto.dylib',
      '/opt/homebrew/opt/openssl@3.5/lib/libcrypto.dylib',
      '/usr/local/opt/openssl@3/lib/libcrypto.3.dylib',
      'libcrypto.3.dylib',
    ],
    if (Platform.isWindows) ...[
      'libcrypto-3-x64.dll',
      'libcrypto-3.dll',
      'libcrypto-1_1-x64.dll',
    ],
  ];
  for (final candidate in candidates) {
    try {
      DynamicLibrary.open(candidate);
      return candidate;
    } on ArgumentError {
      continue;
    }
  }
  return null;
}

/// Thin wrapper over OpenSSL's EVP AEAD interface for the two pqforge suites.
///
/// API mirrors `PqForgeAeadEngine.seal`/`open` (a `ciphertext ‖ tag` body, a
/// 12-byte nonce, 32-byte key) so harness code can compare outputs directly.
/// FFI-level failures throw [StateError]; tag failures throw
/// [OpenSslAuthFailure].
final class OpenSslAead {
  OpenSslAead._(DynamicLibrary lib, this.libraryPath)
    : _ctxNew = lib
          .lookup<NativeFunction<_EvpCipherCtxNewNative>>('EVP_CIPHER_CTX_new')
          .asFunction<_EvpCipherCtxNewDart>(),
      _ctxFree = lib
          .lookup<NativeFunction<_EvpCipherCtxFreeNative>>(
            'EVP_CIPHER_CTX_free',
          )
          .asFunction<_EvpCipherCtxFreeDart>(),
      _aes256Gcm = lib
          .lookup<NativeFunction<_EvpCipherFnNative>>('EVP_aes_256_gcm')
          .asFunction<_EvpCipherFnDart>(),
      _chaCha20Poly1305 = lib
          .lookup<NativeFunction<_EvpCipherFnNative>>('EVP_chacha20_poly1305')
          .asFunction<_EvpCipherFnDart>(),
      _encryptInit = lib
          .lookup<NativeFunction<_EvpInitNative>>('EVP_EncryptInit_ex')
          .asFunction<_EvpInitDart>(),
      _encryptUpdate = lib
          .lookup<NativeFunction<_EvpUpdateNative>>('EVP_EncryptUpdate')
          .asFunction<_EvpUpdateDart>(),
      _encryptFinal = lib
          .lookup<NativeFunction<_EvpFinalNative>>('EVP_EncryptFinal_ex')
          .asFunction<_EvpFinalDart>(),
      _decryptInit = lib
          .lookup<NativeFunction<_EvpInitNative>>('EVP_DecryptInit_ex')
          .asFunction<_EvpInitDart>(),
      _decryptUpdate = lib
          .lookup<NativeFunction<_EvpUpdateNative>>('EVP_DecryptUpdate')
          .asFunction<_EvpUpdateDart>(),
      _decryptFinal = lib
          .lookup<NativeFunction<_EvpFinalNative>>('EVP_DecryptFinal_ex')
          .asFunction<_EvpFinalDart>(),
      _ctxCtrl = lib
          .lookup<NativeFunction<_EvpCtrlNative>>('EVP_CIPHER_CTX_ctrl')
          .asFunction<_EvpCtrlDart>(),
      _version = lib
          .lookup<NativeFunction<_OpenSslVersionNative>>('OpenSSL_version')
          .asFunction<_OpenSslVersionDart>();

  /// Loads the system libcrypto, or returns null so callers can skip cleanly
  /// (same contract as pqcrypto's interop loader).
  static OpenSslAead? tryLoad() {
    final path = resolveLibcryptoPath();
    if (path == null) return null;
    try {
      return OpenSslAead._(DynamicLibrary.open(path), path);
    } on ArgumentError {
      return null;
    }
  }

  /// The path/soname the library was loaded from.
  final String libraryPath;

  final _EvpCipherCtxNewDart _ctxNew;
  final _EvpCipherCtxFreeDart _ctxFree;
  final _EvpCipherFnDart _aes256Gcm;
  final _EvpCipherFnDart _chaCha20Poly1305;
  final _EvpInitDart _encryptInit;
  final _EvpUpdateDart _encryptUpdate;
  final _EvpFinalDart _encryptFinal;
  final _EvpInitDart _decryptInit;
  final _EvpUpdateDart _decryptUpdate;
  final _EvpFinalDart _decryptFinal;
  final _EvpCtrlDart _ctxCtrl;
  final _OpenSslVersionDart _version;

  static const tagLength = 16;

  /// `OpenSSL_version(OPENSSL_VERSION)` — e.g. `OpenSSL 3.0.13 30 Jan 2024`.
  String version() => _version(0).toDartString();

  Pointer<EVP_CIPHER> _cipherFor(String suiteId) => switch (suiteId) {
    'aes-256-gcm' => _aes256Gcm(),
    'chacha20-poly1305' => _chaCha20Poly1305(),
    _ => throw ArgumentError.value(suiteId, 'suiteId', 'unsupported suite'),
  };

  /// Seals [plaintext], returning `ciphertext ‖ tag` — the same body shape as
  /// `PqForgeAeadEngine.seal`, so outputs must match byte for byte.
  Uint8List seal({
    required String suiteId,
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
  }) {
    final ctx = _ctxNew();
    if (ctx == nullptr) throw StateError('EVP_CIPHER_CTX_new failed');
    try {
      return using((arena) {
        final keyP = _copyIn(arena, key);
        final ivP = _copyIn(arena, nonce);
        final outl = arena<Int32>();
        _check(
          _encryptInit(ctx, _cipherFor(suiteId), nullptr, nullptr, nullptr),
          'EVP_EncryptInit_ex(cipher)',
        );
        _check(
          _ctxCtrl(ctx, _evpCtrlAeadSetIvLen, nonce.length, nullptr),
          'EVP_CIPHER_CTX_ctrl(SET_IVLEN)',
        );
        _check(
          _encryptInit(ctx, nullptr, nullptr, keyP, ivP),
          'EVP_EncryptInit_ex(key, iv)',
        );
        if (aad.isNotEmpty) {
          _check(
            _encryptUpdate(ctx, nullptr, outl, _copyIn(arena, aad), aad.length),
            'EVP_EncryptUpdate(aad)',
          );
        }
        final outP = arena<Uint8>(plaintext.length + tagLength);
        var written = 0;
        if (plaintext.isNotEmpty) {
          _check(
            _encryptUpdate(
              ctx,
              outP,
              outl,
              _copyIn(arena, plaintext),
              plaintext.length,
            ),
            'EVP_EncryptUpdate',
          );
          written = outl.value;
        }
        _check(_encryptFinal(ctx, outP + written, outl), 'EVP_EncryptFinal_ex');
        written += outl.value;
        final tagP = arena<Uint8>(tagLength);
        _check(
          _ctxCtrl(ctx, _evpCtrlAeadGetTag, tagLength, tagP.cast()),
          'EVP_CIPHER_CTX_ctrl(GET_TAG)',
        );
        final body = Uint8List(written + tagLength)
          ..setRange(0, written, outP.asTypedList(written))
          ..setRange(written, written + tagLength, tagP.asTypedList(tagLength));
        return body;
      });
    } finally {
      _ctxFree(ctx);
    }
  }

  /// Opens a `ciphertext ‖ tag` [cipherTextWithTag] body; throws
  /// [OpenSslAuthFailure] when the tag (or bound [aad]) does not verify.
  Uint8List open({
    required String suiteId,
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List cipherTextWithTag,
    required Uint8List aad,
  }) {
    if (cipherTextWithTag.length < tagLength) {
      throw const OpenSslAuthFailure('body shorter than the tag');
    }
    final ciphertextLength = cipherTextWithTag.length - tagLength;
    final ctx = _ctxNew();
    if (ctx == nullptr) throw StateError('EVP_CIPHER_CTX_new failed');
    try {
      return using((arena) {
        final keyP = _copyIn(arena, key);
        final ivP = _copyIn(arena, nonce);
        final outl = arena<Int32>();
        _check(
          _decryptInit(ctx, _cipherFor(suiteId), nullptr, nullptr, nullptr),
          'EVP_DecryptInit_ex(cipher)',
        );
        _check(
          _ctxCtrl(ctx, _evpCtrlAeadSetIvLen, nonce.length, nullptr),
          'EVP_CIPHER_CTX_ctrl(SET_IVLEN)',
        );
        _check(
          _decryptInit(ctx, nullptr, nullptr, keyP, ivP),
          'EVP_DecryptInit_ex(key, iv)',
        );
        if (aad.isNotEmpty) {
          _check(
            _decryptUpdate(ctx, nullptr, outl, _copyIn(arena, aad), aad.length),
            'EVP_DecryptUpdate(aad)',
          );
        }
        final outP = arena<Uint8>(ciphertextLength + 1);
        var written = 0;
        if (ciphertextLength > 0) {
          final ctP = arena<Uint8>(ciphertextLength)
            ..asTypedList(
              ciphertextLength,
            ).setAll(0, cipherTextWithTag.sublist(0, ciphertextLength));
          _check(
            _decryptUpdate(ctx, outP, outl, ctP, ciphertextLength),
            'EVP_DecryptUpdate',
          );
          written = outl.value;
        }
        final tagP = arena<Uint8>(tagLength)
          ..asTypedList(
            tagLength,
          ).setAll(0, cipherTextWithTag.sublist(ciphertextLength));
        _check(
          _ctxCtrl(ctx, _evpCtrlAeadSetTag, tagLength, tagP.cast()),
          'EVP_CIPHER_CTX_ctrl(SET_TAG)',
        );
        if (_decryptFinal(ctx, outP + written, outl) != 1) {
          throw const OpenSslAuthFailure('AEAD tag verification failed');
        }
        written += outl.value;
        return Uint8List.fromList(outP.asTypedList(written));
      });
    } finally {
      _ctxFree(ctx);
    }
  }

  static Pointer<Uint8> _copyIn(Arena arena, Uint8List bytes) {
    // calloc rejects zero-length allocations; callers never dereference the
    // pointer for empty input, so one spare byte keeps the call valid.
    final p = arena<Uint8>(bytes.isEmpty ? 1 : bytes.length);
    if (bytes.isNotEmpty) p.asTypedList(bytes.length).setAll(0, bytes);
    return p;
  }

  static void _check(int status, String operation) {
    if (status != 1) {
      throw StateError('$operation failed (status $status)');
    }
  }
}
