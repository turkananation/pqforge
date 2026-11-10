/// Double Ratchet, Signal revision 4 (2025-11-04), sections 3 and 7.2.
///
/// The symmetric ratchet is HMAC. The root KDF is HKDF. The Diffie-Hellman
/// ratchet is X25519 through [PqForgeHybridKeyAgreement.x25519SharedSecret].
/// HMAC is pqcrypto. This is not PQXDH, not the Sparse Post-Quantum Ratchet,
/// and not a libsignal byte match: the AEAD is pqforge AES-256-GCM (or
/// ChaCha20-Poly1305) under the message key with a 12-byte zero nonce,
/// which is safe because each message key is used once.
///
/// ```dart
/// final bobKey = await RatchetKeyPair.generate();
/// final secret = SharedSecret32(sharedSecretBytes);
/// final alice = await DoubleRatchet.initiate(
///   sharedSecret: secret,
///   remoteRatchetKey: bobKey.publicKey,
/// );
/// final bob = DoubleRatchet.accept(
///   sharedSecret: secret,
///   ratchetKey: bobKey,
/// );
/// final message = alice.seal(plaintext, aad: aad);
/// final clear = await bob.open(message, aad: aad);
/// ```
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart' as pqc;
import 'package:zeroize/zeroize.dart';

import '../algorithms/pq_fips.dart';
import '../cipher/pq_cipher_suite.dart';
import '../exceptions/pqforge_exception.dart';
import '../hybrid/pqforge_hybrid_key_agreement.dart';
import '../primitives/pq_primitives.dart';
import 'pq_ratchet_types.dart';

/// SHA-256 or SHA-512, fixed for the life of a session.
enum DoubleRatchetHash {
  /// HMAC-SHA-256 and HKDF-SHA-256. Outputs are already 32 bytes.
  sha256,

  /// HMAC-SHA-512 and HKDF-SHA-512. Chain and message keys are the
  /// leftmost 32 bytes, which is the length section 3 assigns them.
  sha512,
}

/// One Double Ratchet message: a 40-byte header and `ciphertext || tag`.
///
/// Header layout, big-endian: `dh (32) || pn (uint32) || n (uint32)`.
/// [parse] views [bytes]. It does not copy.
final class DoubleRatchetMessage {
  DoubleRatchetMessage._(this.bytes)
    : dh = RatchetPublicKey.view(Uint8List.sublistView(bytes, 0, 32)),
      pn = ByteData.sublistView(bytes, 32, 36).getUint32(0),
      n = ByteData.sublistView(bytes, 36, 40).getUint32(0);

  /// Parses a message. The header is a view of [bytes].
  factory DoubleRatchetMessage.parse(Uint8List bytes) {
    if (bytes.length < headerBytes + 16) {
      throw const PqForgeException('Double Ratchet message is truncated');
    }
    return DoubleRatchetMessage._(bytes);
  }

  static const headerBytes = 40;

  /// Header and ciphertext. Owned by [seal], viewed by [parse].
  final Uint8List bytes;

  /// Sender ratchet public key. A view of the first 32 bytes.
  final RatchetPublicKey dh;

  /// Previous sending-chain length.
  final int pn;

  /// Message number in the sending chain.
  final int n;

  /// Header bytes. A view.
  Uint8List get header => Uint8List.sublistView(bytes, 0, headerBytes);

  /// `ciphertext || tag`. A view.
  Uint8List get ciphertext => Uint8List.sublistView(bytes, headerBytes);
}

/// Signal Double Ratchet over X25519 and one pqforge AEAD.
final class DoubleRatchet {
  DoubleRatchet._({
    required Uint8List rootKey,
    required this._dhSecret,
    required this._dhPublic,
    required this.remoteRatchetKey,
    required Uint8List? sendingChain,
    required this.hash,
    required this.suite,
    required this._info,
    required this.maxSkip,
  }) : _root = rootKey,
       _sending = sendingChain;

  /// Alice. Mixes one X25519 into [sharedSecret] and can [seal] immediately.
  static Future<DoubleRatchet> initiate({
    required SharedSecret32 sharedSecret,
    required RatchetPublicKey remoteRatchetKey,
    DoubleRatchetHash hash = DoubleRatchetHash.sha256,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
    Uint8List? info,
    int maxSkip = defaultMaxSkip,
  }) async {
    _requireSession(suite, maxSkip);
    final ours = await RatchetKeyPair.generate();
    final root = Uint8List.fromList(sharedSecret.bytes);
    final session = DoubleRatchet._(
      rootKey: root,
      dhSecret: ours.secretKey,
      dhPublic: ours.publicKey,
      remoteRatchetKey: RatchetPublicKey(remoteRatchetKey.bytes),
      sendingChain: null,
      hash: hash,
      suite: suite,
      info: _infoBytes(info),
      maxSkip: maxSkip,
    );
    final dh = await session._exchange(ours.secretKey, remoteRatchetKey.bytes);
    try {
      session._sending = session._mix(dh);
    } finally {
      secureZero(dh);
    }
    return session;
  }

  /// Bob. [ratchetKey] is the public key Alice already used. The sending
  /// chain appears only after the first [open].
  static DoubleRatchet accept({
    required SharedSecret32 sharedSecret,
    required RatchetKeyPair ratchetKey,
    DoubleRatchetHash hash = DoubleRatchetHash.sha256,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
    Uint8List? info,
    int maxSkip = defaultMaxSkip,
  }) {
    _requireSession(suite, maxSkip);
    return DoubleRatchet._(
      rootKey: Uint8List.fromList(sharedSecret.bytes),
      dhSecret: Uint8List.fromList(ratchetKey.secretKey),
      dhPublic: RatchetPublicKey(ratchetKey.publicKey.bytes),
      remoteRatchetKey: null,
      sendingChain: null,
      hash: hash,
      suite: suite,
      info: _infoBytes(info),
      maxSkip: maxSkip,
    );
  }

  /// Restores a session from [toBytes]. Refuses anything that is not a
  /// 32-byte ratchet secret, including an expanded ML-KEM private key.
  factory DoubleRatchet.fromBytes(Uint8List bytes) {
    final reader = _Reader(bytes);
    final magic = reader.take(4);
    for (var i = 0; i < 4; i++) {
      if (magic[i] != _stateMagic[i]) {
        throw const PqForgeException('Not a Double Ratchet session');
      }
    }
    if (reader.u8() != 1) {
      throw const PqForgeException('Unknown Double Ratchet session version');
    }
    final hash = switch (reader.u8()) {
      1 => DoubleRatchetHash.sha256,
      2 => DoubleRatchetHash.sha512,
      _ => throw const PqForgeException('Unknown Double Ratchet hash'),
    };
    final suite = switch (reader.u8()) {
      1 => PqForgeCipherSuite.aes256Gcm,
      2 => PqForgeCipherSuite.chaCha20Poly1305,
      _ => throw const PqForgeException('Unknown Double Ratchet AEAD'),
    };
    PqFipsMode.requireApprovedSuite(suite);
    final maxSkip = reader.u32();
    final ns = reader.u32();
    final nr = reader.u32();
    final pn = reader.u32();
    final root = reader.secret('rootKey');
    final dhSecret = reader.secret('dhSecret');
    final dhPublic = RatchetPublicKey(reader.secret('dhPublic'));
    final flags = reader.u8();
    final remote = (flags & 1) == 0
        ? null
        : RatchetPublicKey(reader.secret('remoteRatchetKey'));
    final sending = (flags & 2) == 0 ? null : reader.secret('sendingChain');
    final receiving = (flags & 4) == 0 ? null : reader.secret('receivingChain');
    final info = reader.take(reader.u32());
    final skippedCount = reader.u32();
    final session =
        DoubleRatchet._(
            rootKey: root,
            dhSecret: dhSecret,
            dhPublic: dhPublic,
            remoteRatchetKey: remote,
            sendingChain: sending,
            hash: hash,
            suite: suite,
            info: Uint8List.fromList(info),
            maxSkip: maxSkip,
          )
          .._ns = ns
          .._nr = nr
          .._pn = pn
          .._receiving = receiving;
    try {
      for (var i = 0; i < skippedCount; i++) {
        final dh = reader.secret('skippedDh');
        final n = reader.u32();
        final mk = reader.secret('skippedMessageKey');
        session._skipped[_SkipId.own(dh, n)] = mk;
      }
      if (!reader.done) {
        throw const PqForgeException(
          'Trailing bytes on a Double Ratchet session',
        );
      }
      return session;
    } catch (error) {
      session.dispose();
      rethrow;
    }
  }

  /// Default [maxSkip]. The specification leaves the number to the
  /// application. This is the value the tests pin when the caller does not.
  static const defaultMaxSkip = 1000;

  static const _stateMagic = <int>[0x44, 0x52, 0x30, 0x31]; // DR01

  /// HKDF info used when the caller does not pass one. Distinct from the
  /// other HKDF labels in this package.
  static final Uint8List defaultInfo = Uint8List.fromList(
    utf8.encode('pqforge-double-ratchet-v1'),
  );

  final DoubleRatchetHash hash;
  final PqForgeCipherSuite suite;
  final int maxSkip;
  final Uint8List _info;

  final Uint8List _root;
  Uint8List _dhSecret;
  RatchetPublicKey _dhPublic;
  RatchetPublicKey? remoteRatchetKey;
  Uint8List? _sending;
  Uint8List? _receiving;
  int _ns = 0;
  int _nr = 0;
  int _pn = 0;
  final Map<_SkipId, Uint8List> _skipped = {};
  bool _disposed = false;

  /// How many skipped message keys are stored.
  int get skippedCount => _skipped.length;

  /// Copy of the sending chain key, or null when Bob has not opened yet.
  /// Wipe the copy. This exists so a test can show a Diffie-Hellman step
  /// does not continue the previous chain.
  Uint8List? copySendingChainKey() {
    _live();
    final chain = _sending;
    return chain == null ? null : Uint8List.fromList(chain);
  }

  /// Encrypts one message. The message key is wiped before this returns.
  /// Does not return the message key.
  DoubleRatchetMessage seal(Uint8List plaintext, {Uint8List? aad}) {
    _live();
    final chain = _sending;
    if (chain == null) {
      throw const PqForgeException(
        'The sending chain starts after the first received header',
      );
    }
    if (_ns == 0xFFFFFFFF) {
      throw const PqForgeException('Sending chain counter exhausted');
    }
    final messageKey = _advance(chain);
    final pn = _pn;
    final n = _ns;
    _ns++;
    try {
      final body = _encrypt(
        messageKey,
        plaintext,
        _aad(aad, _headerBytes(_dhPublic.bytes, pn, n)),
      );
      final out = Uint8List(DoubleRatchetMessage.headerBytes + body.length);
      _writeHeader(out, _dhPublic.bytes, pn, n);
      out.setRange(DoubleRatchetMessage.headerBytes, out.length, body);
      return DoubleRatchetMessage._(out);
    } finally {
      secureZero(messageKey);
    }
  }

  /// Decrypts one message. Out-of-order messages inside [maxSkip] open.
  /// A header past [maxSkip] throws and does not grow the skipped-key map.
  Future<Uint8List> open(DoubleRatchetMessage message, {Uint8List? aad}) async {
    _live();
    final cached = _takeSkipped(message.dh.bytes, message.n);
    if (cached != null) {
      try {
        return _decrypt(cached, message, aad);
      } finally {
        secureZero(cached);
      }
    }
    if (remoteRatchetKey == null ||
        !_same(remoteRatchetKey!.bytes, message.dh.bytes)) {
      _skip(message.pn);
      await _dhRatchet(message.dh.bytes);
    }
    _skip(message.n);
    final receiving = _receiving;
    if (receiving == null) {
      throw const PqForgeException('Receiving chain is not initialized');
    }
    if (_nr == 0xFFFFFFFF) {
      throw const PqForgeException('Receiving chain counter exhausted');
    }
    final messageKey = _advance(receiving);
    _nr++;
    try {
      return _decrypt(messageKey, message, aad);
    } finally {
      secureZero(messageKey);
    }
  }

  /// [open] for a raw message buffer.
  Future<Uint8List> openBytes(Uint8List message, {Uint8List? aad}) =>
      open(DoubleRatchetMessage.parse(message), aad: aad);

  /// Session state. Every secret field is 32 bytes. An expanded ML-KEM
  /// private key cannot be written: there is no field for it.
  Uint8List toBytes() {
    _live();
    final info = _info;
    final builder = BytesBuilder(copy: false);
    builder.add(_stateMagic);
    builder.addByte(1);
    builder.addByte(hash == DoubleRatchetHash.sha256 ? 1 : 2);
    builder.addByte(suite == PqForgeCipherSuite.aes256Gcm ? 1 : 2);
    builder.add(_u32(maxSkip));
    builder.add(_u32(_ns));
    builder.add(_u32(_nr));
    builder.add(_u32(_pn));
    _addSecret(builder, _root);
    _addSecret(builder, _dhSecret);
    _addSecret(builder, _dhPublic.bytes);
    final remote = remoteRatchetKey;
    final sending = _sending;
    final receiving = _receiving;
    var flags = 0;
    if (remote != null) flags |= 1;
    if (sending != null) flags |= 2;
    if (receiving != null) flags |= 4;
    builder.addByte(flags);
    if (remote != null) _addSecret(builder, remote.bytes);
    if (sending != null) _addSecret(builder, sending);
    if (receiving != null) _addSecret(builder, receiving);
    builder.add(_u32(info.length));
    builder.add(info);
    builder.add(_u32(_skipped.length));
    for (final entry in _skipped.entries) {
      _addSecret(builder, entry.key.dh);
      builder.add(_u32(entry.key.n));
      _addSecret(builder, entry.value);
    }
    return builder.takeBytes();
  }

  /// Wipes root, chain, ratchet secret, and skipped message keys.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    secureZero(_root);
    secureZero(_dhSecret);
    final sending = _sending;
    final receiving = _receiving;
    if (sending != null) secureZero(sending);
    if (receiving != null) secureZero(receiving);
    for (final key in _skipped.values) {
      secureZero(key);
    }
    _skipped.clear();
  }

  Future<void> _dhRatchet(Uint8List remoteDh) async {
    _pn = _ns;
    _ns = 0;
    _nr = 0;
    remoteRatchetKey = RatchetPublicKey(remoteDh);
    final first = await _exchange(_dhSecret, remoteDh);
    try {
      final oldReceiving = _receiving;
      _receiving = _mix(first);
      if (oldReceiving != null) secureZero(oldReceiving);
    } finally {
      secureZero(first);
    }
    final next = await RatchetKeyPair.generate();
    secureZero(_dhSecret);
    _dhSecret = next.secretKey;
    _dhPublic = next.publicKey;
    final second = await _exchange(_dhSecret, remoteDh);
    try {
      final oldSending = _sending;
      _sending = _mix(second);
      if (oldSending != null) secureZero(oldSending);
    } finally {
      secureZero(second);
    }
  }

  /// `KDF_RK`. HKDF salt is the current root key. Overwrites that root in
  /// place and returns the new 32-byte chain key.
  Uint8List _mix(Uint8List dhOut) {
    final okm = _hkdf(salt: _root, ikm: dhOut, info: _info);
    try {
      _root.setRange(0, 32, okm);
      return Uint8List(32)..setRange(0, 32, okm, 32);
    } finally {
      secureZero(okm);
    }
  }

  /// `KDF_CK`. Replaces [chain] in place. Returns the message key.
  Uint8List _advance(Uint8List chain) {
    final messageKey = _hmac32(chain, _messageKeyInputBytes);
    final next = _hmac32(chain, _chainKeyInput);
    chain.setRange(0, 32, next);
    secureZero(next);
    return messageKey;
  }

  void _skip(int until) {
    if (_nr + maxSkip < until) {
      throw const PqForgeException(
        'Double Ratchet header skips more messages than maxSkip',
      );
    }
    final chain = _receiving;
    if (chain == null) return;
    while (_nr < until) {
      _skipped[_SkipId(remoteRatchetKey!.bytes, _nr)] = _advance(chain);
      _nr++;
    }
  }

  Uint8List? _takeSkipped(Uint8List dh, int n) {
    final id = _SkipId(dh, n);
    final key = _skipped.remove(id);
    return key;
  }

  Uint8List _hmac32(Uint8List key, Uint8List input) {
    final full = switch (hash) {
      DoubleRatchetHash.sha256 => pqc.hmacSha256(key, input),
      DoubleRatchetHash.sha512 => pqc.hmacSha512(key, input),
    };
    if (full.length == 32) return full;
    final out = Uint8List(32)..setRange(0, 32, full);
    secureZero(full);
    return out;
  }

  Uint8List _hkdf({
    required Uint8List salt,
    required Uint8List ikm,
    required Uint8List info,
  }) {
    final prk = switch (hash) {
      DoubleRatchetHash.sha256 => pqc.hmacSha256(salt, ikm),
      DoubleRatchetHash.sha512 => pqc.hmacSha512(salt, ikm),
    };
    try {
      final hashLen = prk.length;
      const output = 64;
      final blocks = (output + hashLen - 1) ~/ hashLen;
      final okm = Uint8List(blocks * hashLen);
      var previous = Uint8List(0);
      var offset = 0;
      try {
        for (var i = 1; i <= blocks; i++) {
          final data = Uint8List(previous.length + info.length + 1);
          data.setRange(0, previous.length, previous);
          data.setRange(previous.length, previous.length + info.length, info);
          data[data.length - 1] = i;
          final block = switch (hash) {
            DoubleRatchetHash.sha256 => pqc.hmacSha256(prk, data),
            DoubleRatchetHash.sha512 => pqc.hmacSha512(prk, data),
          };
          secureZero(data);
          okm.setRange(offset, offset + hashLen, block);
          if (previous.isNotEmpty) secureZero(previous);
          previous = block;
          offset += hashLen;
        }
        final out = Uint8List(output)..setRange(0, output, okm);
        return out;
      } finally {
        secureZero(okm);
        if (previous.isNotEmpty) secureZero(previous);
      }
    } finally {
      secureZero(prk);
    }
  }

  Future<Uint8List> _exchange(Uint8List secret, Uint8List remote) =>
      PqForgeHybridKeyAgreement.x25519SharedSecret(
        secretKey: secret,
        remotePublicKey: remote,
      );

  Uint8List _encrypt(Uint8List key, Uint8List plaintext, Uint8List aad) =>
      switch (suite) {
        PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmEncrypt(
          key: key,
          nonce: _zeroNonce,
          plaintext: plaintext,
          aad: aad,
        ),
        PqForgeCipherSuite.chaCha20Poly1305 =>
          PqSymmetricPrimitives.chacha20Poly1305Encrypt(
            key: key,
            nonce: _zeroNonce,
            plaintext: plaintext,
            aad: aad,
          ),
      };

  Uint8List _decrypt(
    Uint8List key,
    DoubleRatchetMessage message,
    Uint8List? aad,
  ) => switch (suite) {
    PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmDecrypt(
      key: key,
      nonce: _zeroNonce,
      ciphertext: message.ciphertext,
      aad: _aad(aad, message.header),
    ),
    PqForgeCipherSuite.chaCha20Poly1305 =>
      PqSymmetricPrimitives.chacha20Poly1305Decrypt(
        key: key,
        nonce: _zeroNonce,
        ciphertext: message.ciphertext,
        aad: _aad(aad, message.header),
      ),
  };

  void _live() {
    if (_disposed) {
      throw StateError('DoubleRatchet has been disposed');
    }
  }

  static void _requireSession(PqForgeCipherSuite suite, int maxSkip) {
    if (maxSkip < 0) {
      throw ArgumentError.value(maxSkip, 'maxSkip', 'must be non-negative');
    }
    PqFipsMode.requireApprovedSuite(suite);
  }

  static Uint8List _infoBytes(Uint8List? info) {
    final value = info ?? defaultInfo;
    if (value.length > 1024) {
      throw ArgumentError.value(value.length, 'info', 'max 1024 bytes');
    }
    return Uint8List.fromList(value);
  }
}

final Uint8List _messageKeyInputBytes = Uint8List.fromList(const [0x01]);
final Uint8List _chainKeyInput = Uint8List.fromList(const [0x02]);
final Uint8List _zeroNonce = Uint8List(12);

Uint8List _aad(Uint8List? aad, Uint8List header) {
  if (aad == null || aad.isEmpty) return header;
  final out = Uint8List(aad.length + header.length);
  out.setRange(0, aad.length, aad);
  out.setRange(aad.length, out.length, header);
  return out;
}

Uint8List _headerBytes(Uint8List dh, int pn, int n) {
  final header = Uint8List(DoubleRatchetMessage.headerBytes);
  _writeHeader(header, dh, pn, n);
  return header;
}

void _writeHeader(Uint8List out, Uint8List dh, int pn, int n) {
  out.setRange(0, 32, dh);
  ByteData.sublistView(out).setUint32(32, pn);
  ByteData.sublistView(out).setUint32(36, n);
}

void _addSecret(BytesBuilder builder, Uint8List secret) {
  if (mlKemPrivateKeyLengths.contains(secret.length)) {
    throw const PqForgeException(
      'An expanded ML-KEM private key cannot be used as a session secret',
    );
  }
  if (secret.length != 32) {
    throw ArgumentError.value(
      secret.length,
      'session secret',
      'expected 32 bytes',
    );
  }
  builder.add(secret);
}

Uint8List _u32(int value) {
  final bytes = Uint8List(4);
  ByteData.sublistView(bytes).setUint32(0, value);
  return bytes;
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

final class _SkipId {
  _SkipId(Uint8List dh, this.n) : dh = Uint8List.fromList(dh);

  /// [dh] is already a private copy. The map owns it.
  _SkipId.own(this.dh, this.n);

  final Uint8List dh;
  final int n;

  @override
  bool operator ==(Object other) =>
      other is _SkipId && other.n == n && _same(dh, other.dh);

  @override
  int get hashCode {
    var hash = n;
    for (var i = 0; i < dh.length; i += 4) {
      hash =
          0x1fffffff &
          (hash * 31 +
              dh[i] +
              (dh[i + 1] << 8) +
              (dh[i + 2] << 16) +
              (dh[i + 3] << 24));
    }
    return hash;
  }
}

final class _Reader {
  _Reader(this.bytes);

  final Uint8List bytes;
  int _offset = 0;

  bool get done => _offset == bytes.length;

  Uint8List take(int length) {
    if (_offset + length > bytes.length) {
      throw const PqForgeException('Truncated Double Ratchet session');
    }
    final out = Uint8List.sublistView(bytes, _offset, _offset + length);
    _offset += length;
    return out;
  }

  int u8() => take(1)[0];

  int u32() => ByteData.sublistView(take(4)).getUint32(0);

  Uint8List secret(String name) => PqRatchetSecrets.copy32(name, take(32));
}
