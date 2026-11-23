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
import 'dart:math';
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

/// One Double Ratchet message.
///
/// A clear header is 40 bytes: `dh (32) || pn (uint32) || n (uint32)`,
/// then `ciphertext || tag`. [parse] views [bytes]. It does not copy.
///
/// An encrypted header is `DRH1 || version=1 || nonce(12) || AEAD(header)`.
/// The body AEAD follows. [headerEncrypted] is true for that layout.
/// The nonce is random because the header key is reused for the chain.
/// It is 12 bytes, not 128 bits. A header key lasts one sending chain.
final class DoubleRatchetMessage {
  DoubleRatchetMessage._(this.bytes, {this.headerEncrypted = false});

  /// Parses a clear-header message. The header is a view of [bytes].
  factory DoubleRatchetMessage.parse(Uint8List bytes) {
    if (bytes.length >= 4 &&
        bytes[0] == 0x44 &&
        bytes[1] == 0x52 &&
        bytes[2] == 0x48 &&
        bytes[3] == 0x31) {
      if (bytes.length < 4 + 1 + 12 + headerBytes + 16 + 16) {
        throw const PqForgeException('Double Ratchet message is truncated');
      }
      if (bytes[4] != 1) {
        throw const PqForgeException('Unknown Double Ratchet header version');
      }
      if (bytes.length < 21) {
        throw const PqForgeException('Double Ratchet message is truncated');
      }
      final length = ByteData.sublistView(bytes, 17, 21).getUint32(0);
      if (length < headerBytes + 16 || bytes.length < 21 + length + 16) {
        throw const PqForgeException('Double Ratchet message is truncated');
      }
      return DoubleRatchetMessage._(bytes, headerEncrypted: true);
    }
    if (bytes.length < headerBytes + 16) {
      throw const PqForgeException('Double Ratchet message is truncated');
    }
    return DoubleRatchetMessage._(bytes);
  }

  static const headerBytes = 40;

  /// Header and ciphertext. Owned by [seal], viewed by [parse].
  final Uint8List bytes;

  /// True when the 40-byte header is AEAD'd under the header key.
  final bool headerEncrypted;

  /// Sender ratchet public key. A view of the first 32 bytes.
  /// Throws when [headerEncrypted] is true.
  RatchetPublicKey get dh {
    if (headerEncrypted) {
      throw StateError('Double Ratchet header is encrypted');
    }
    return RatchetPublicKey.view(Uint8List.sublistView(bytes, 0, 32));
  }

  /// Previous sending-chain length.
  int get pn {
    if (headerEncrypted) {
      throw StateError('Double Ratchet header is encrypted');
    }
    return ByteData.sublistView(bytes, 32, 36).getUint32(0);
  }

  /// Message number in the sending chain.
  int get n {
    if (headerEncrypted) {
      throw StateError('Double Ratchet header is encrypted');
    }
    return ByteData.sublistView(bytes, 36, 40).getUint32(0);
  }

  /// Header bytes. A view. The encrypted header includes its tag.
  Uint8List get header {
    if (!headerEncrypted) {
      return Uint8List.sublistView(bytes, 0, headerBytes);
    }
    final length = ByteData.sublistView(bytes, 17, 21).getUint32(0);
    return Uint8List.sublistView(bytes, 21, 21 + length);
  }

  /// `ciphertext || tag`. A view.
  Uint8List get ciphertext {
    if (!headerEncrypted) {
      return Uint8List.sublistView(bytes, headerBytes);
    }
    return Uint8List.sublistView(bytes, 21 + header.length);
  }

  /// 12-byte header nonce. Empty when the header is clear.
  Uint8List get headerNonce =>
      headerEncrypted ? Uint8List.sublistView(bytes, 5, 17) : Uint8List(0);
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
    required this._ratchetKeys,
    this.encryptHeaders = false,
    Uint8List? sendingHeaderKey,
    Uint8List? receivingHeaderKey,
    Uint8List? nextSendingHeaderKey,
    Uint8List? nextReceivingHeaderKey,
  }) : _root = rootKey,
       _sending = sendingChain,
       _hks = sendingHeaderKey,
       _hkr = receivingHeaderKey,
       _nhks = nextSendingHeaderKey,
       _nhkr = nextReceivingHeaderKey;

  /// Alice. Mixes one X25519 into [sharedSecret] and can [seal] immediately.
  /// [ratchetKey] fixes the first X25519 pair. [ratchetKeys] fixes each
  /// later pair. Tests pass both. A production caller omits them.
  static Future<DoubleRatchet> initiate({
    required SharedSecret32 sharedSecret,
    required RatchetPublicKey remoteRatchetKey,
    DoubleRatchetHash hash = DoubleRatchetHash.sha256,
    PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
    Uint8List? info,
    int maxSkip = defaultMaxSkip,
    RatchetKeyPair? ratchetKey,
    Future<RatchetKeyPair> Function(int step)? ratchetKeys,
    bool encryptHeaders = false,
  }) async {
    _requireSession(suite, maxSkip);
    final generated = ratchetKey == null;
    final ours = ratchetKey ?? await RatchetKeyPair.generate();
    final secret = Uint8List.fromList(ours.secretKey);
    final public = RatchetPublicKey(ours.publicKey.bytes);
    if (generated) ours.wipe();
    final root = Uint8List.fromList(sharedSecret.bytes);
    final session = DoubleRatchet._(
      rootKey: root,
      dhSecret: secret,
      dhPublic: public,
      remoteRatchetKey: RatchetPublicKey(remoteRatchetKey.bytes),
      sendingChain: null,
      hash: hash,
      suite: suite,
      info: _infoBytes(info),
      maxSkip: maxSkip,
      ratchetKeys: ratchetKeys,
      encryptHeaders: encryptHeaders,
    );
    final dh = await session._exchange(secret, remoteRatchetKey.bytes);
    try {
      if (!encryptHeaders) {
        session._sending = session._mix(dh);
      } else {
        final shared = session._sharedHeaderKeys(sharedSecret.bytes);
        session._hks = shared.$1;
        session._nhkr = shared.$2;
        final mixed = session._mixHe(dh);
        session._sending = mixed.$1;
        session._nhks = mixed.$2;
      }
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
    Future<RatchetKeyPair> Function(int step)? ratchetKeys,
    bool encryptHeaders = false,
  }) {
    _requireSession(suite, maxSkip);
    final session = DoubleRatchet._(
      rootKey: Uint8List.fromList(sharedSecret.bytes),
      dhSecret: Uint8List.fromList(ratchetKey.secretKey),
      dhPublic: RatchetPublicKey(ratchetKey.publicKey.bytes),
      remoteRatchetKey: null,
      sendingChain: null,
      hash: hash,
      suite: suite,
      info: _infoBytes(info),
      maxSkip: maxSkip,
      ratchetKeys: ratchetKeys,
      encryptHeaders: encryptHeaders,
    );
    if (encryptHeaders) {
      final shared = session._sharedHeaderKeys(sharedSecret.bytes);
      session._nhks = shared.$2;
      session._nhkr = shared.$1;
    }
    return session;
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
    final version = reader.u8();
    if (version != 1 && version != 2) {
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
            ratchetKeys: null,
            encryptHeaders: version == 2,
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
      if (version == 2) {
        final headerFlags = reader.u8();
        if ((headerFlags & 1) != 0) {
          session._hks = reader.secret('sendingHeaderKey');
        }
        if ((headerFlags & 2) != 0) {
          session._hkr = reader.secret('receivingHeaderKey');
        }
        if ((headerFlags & 4) != 0) {
          session._nhks = reader.secret('nextSendingHeaderKey');
        }
        if ((headerFlags & 8) != 0) {
          session._nhkr = reader.secret('nextReceivingHeaderKey');
        }
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
  final bool encryptHeaders;
  final Uint8List _info;
  final Future<RatchetKeyPair> Function(int step)? _ratchetKeys;
  int _ratchetStep = 0;

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
  Uint8List? _hks;
  Uint8List? _hkr;
  Uint8List? _nhks;
  Uint8List? _nhkr;
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
  /// Does not return the message key. [takeSendingMessageKey] is the same
  /// chain step for a caller that encrypts elsewhere.
  DoubleRatchetMessage seal(Uint8List plaintext, {Uint8List? aad}) {
    final taken = takeSendingMessageKey();
    try {
      final clear = _headerBytes(taken.dh.bytes, taken.pn, taken.n);
      if (!encryptHeaders) {
        final body = _encrypt(taken.messageKey, plaintext, _aad(aad, clear));
        final out = Uint8List(DoubleRatchetMessage.headerBytes + body.length);
        out.setRange(0, clear.length, clear);
        out.setRange(clear.length, out.length, body);
        return DoubleRatchetMessage._(out);
      }
      final headerKey = _hks;
      if (headerKey == null) {
        throw const PqForgeException('Sending header key is not initialized');
      }
      final sealedHeader = _sealHeader(headerKey, clear);
      try {
        final body = _encrypt(
          taken.messageKey,
          plaintext,
          _aad(aad, sealedHeader.$2),
        );
        return DoubleRatchetMessage._(
          _packEncrypted(sealedHeader.$1, sealedHeader.$2, body),
          headerEncrypted: true,
        );
      } finally {
        secureZero(sealedHeader.$2);
      }
    } finally {
      secureZero(taken.messageKey);
    }
  }

  /// Next sending message key. The caller wipes [messageKey].
  /// Does not encrypt. The header fields are the ones [seal] would write.
  ({Uint8List messageKey, int pn, int n, RatchetPublicKey dh})
  takeSendingMessageKey() {
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
    return (messageKey: messageKey, pn: pn, n: n, dh: _dhPublic);
  }

  /// Decrypts one message. Out-of-order messages inside [maxSkip] open.
  /// A header past [maxSkip] throws and does not grow the skipped-key map.
  Future<Uint8List> open(DoubleRatchetMessage message, {Uint8List? aad}) async {
    if (message.headerEncrypted) {
      if (!encryptHeaders) {
        throw const PqForgeException('Double Ratchet header is encrypted');
      }
      return _openEncrypted(message, aad);
    }
    if (encryptHeaders) {
      throw const PqForgeException('Double Ratchet header is not encrypted');
    }
    final messageKey = await takeReceivingMessageKey(
      dh: message.dh.bytes,
      pn: message.pn,
      n: message.n,
    );
    try {
      return _decrypt(messageKey, message, aad);
    } finally {
      secureZero(messageKey);
    }
  }

  /// Next receiving message key for a header. The caller wipes it.
  /// Does not decrypt. Same chain rules as [open].
  Future<Uint8List> takeReceivingMessageKey({
    required Uint8List dh,
    required int pn,
    required int n,
  }) async {
    if (encryptHeaders) {
      throw StateError('An encrypted header is opened with open');
    }
    _live();
    final cached = _takeSkipped(dh, n);
    if (cached != null) return cached;
    if (remoteRatchetKey == null || !_same(remoteRatchetKey!.bytes, dh)) {
      _skip(pn);
      await _dhRatchet(dh);
    }
    _skip(n);
    final receiving = _receiving;
    if (receiving == null) {
      throw const PqForgeException('Receiving chain is not initialized');
    }
    if (_nr == 0xFFFFFFFF) {
      throw const PqForgeException('Receiving chain counter exhausted');
    }
    final messageKey = _advance(receiving);
    _nr++;
    return messageKey;
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
    builder.addByte(encryptHeaders ? 2 : 1);
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
    if (encryptHeaders) {
      var flags = 0;
      if (_hks != null) flags |= 1;
      if (_hkr != null) flags |= 2;
      if (_nhks != null) flags |= 4;
      if (_nhkr != null) flags |= 8;
      builder.addByte(flags);
      if (_hks != null) _addSecret(builder, _hks!);
      if (_hkr != null) _addSecret(builder, _hkr!);
      if (_nhks != null) _addSecret(builder, _nhks!);
      if (_nhkr != null) _addSecret(builder, _nhkr!);
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
    _wipeHeader(_hks);
    _wipeHeader(_hkr);
    _wipeHeader(_nhks);
    _wipeHeader(_nhkr);
    _hks = null;
    _hkr = null;
    _nhks = null;
    _nhkr = null;
  }

  Future<RatchetKeyPair> _freshRatchetKey() {
    final keys = _ratchetKeys;
    if (keys == null) return RatchetKeyPair.generate();
    final step = _ratchetStep;
    _ratchetStep += 1;
    return keys(step);
  }

  Future<void> _dhRatchet(Uint8List remoteDh) async {
    if (encryptHeaders) {
      await _dhRatchetHe(remoteDh);
      return;
    }
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
    final next = await _freshRatchetKey();
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
    if (encryptHeaders) {
      final headerKey = _hkr;
      if (headerKey == null) return;
      while (_nr < until) {
        _skipped[_SkipId(headerKey, _nr)] = _advance(chain);
        _nr++;
      }
      return;
    }
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
    int output = 64,
  }) {
    final prk = switch (hash) {
      DoubleRatchetHash.sha256 => pqc.hmacSha256(salt, ikm),
      DoubleRatchetHash.sha512 => pqc.hmacSha512(salt, ikm),
    };
    try {
      final hashLen = prk.length;
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

  /// Encrypts [clear] under the current sending header key.
  /// The caller wipes [encrypted] if it copies it into a larger buffer
  /// that it will not keep. The nonce is 12 random bytes.
  ({Uint8List nonce, Uint8List encrypted}) encryptSendingHeader(
    Uint8List clear,
  ) {
    _live();
    if (!encryptHeaders) {
      throw StateError('This session does not encrypt headers');
    }
    final key = _hks;
    if (key == null) {
      throw const PqForgeException('Sending header key is not initialized');
    }
    final sealed = _sealHeader(key, clear);
    return (nonce: sealed.$1, encrypted: sealed.$2);
  }

  /// Decrypts a header that is not the 40-byte Double Ratchet header.
  /// [read] pulls `dh`, `pn`, and `n` out of the clear header. The message
  /// key is the caller's to wipe. [clearHeader] is too.
  Future<({Uint8List messageKey, Uint8List clearHeader})> openExternalHeader({
    required Uint8List nonce,
    required Uint8List encrypted,
    required ({Uint8List dh, int pn, int n}) Function(Uint8List clear) read,
  }) async {
    _live();
    if (!encryptHeaders) {
      throw StateError('This session does not encrypt headers');
    }
    final skipped = _takeSkippedHeader(nonce, encrypted, read);
    if (skipped != null) return skipped;
    final current = _tryHeader(_hkr, nonce, encrypted);
    final next = current == null ? _tryHeader(_nhkr, nonce, encrypted) : null;
    final clear = current ?? next;
    if (clear == null) {
      throw const PqForgeException('Double Ratchet header did not decrypt');
    }
    final fields = read(clear);
    if (next != null) {
      _skip(fields.pn);
      await _dhRatchetHe(fields.dh);
    }
    _skip(fields.n);
    final receiving = _receiving;
    if (receiving == null) {
      secureZero(clear);
      throw const PqForgeException('Receiving chain is not initialized');
    }
    if (_nr == 0xFFFFFFFF) {
      secureZero(clear);
      throw const PqForgeException('Receiving chain counter exhausted');
    }
    final messageKey = _advance(receiving);
    _nr++;
    return (messageKey: messageKey, clearHeader: clear);
  }

  Future<Uint8List> _openEncrypted(
    DoubleRatchetMessage message,
    Uint8List? aad,
  ) async {
    final opened = await openExternalHeader(
      nonce: message.headerNonce,
      encrypted: message.header,
      read: (clear) {
        if (clear.length != DoubleRatchetMessage.headerBytes) {
          throw const PqForgeException('Double Ratchet header is truncated');
        }
        return (
          dh: Uint8List.fromList(Uint8List.sublistView(clear, 0, 32)),
          pn: ByteData.sublistView(clear, 32, 36).getUint32(0),
          n: ByteData.sublistView(clear, 36, 40).getUint32(0),
        );
      },
    );
    try {
      return _encryptLike(
        opened.messageKey,
        message.ciphertext,
        _aad(aad, message.header),
        decrypt: true,
      );
    } finally {
      secureZero(opened.messageKey);
      secureZero(opened.clearHeader);
    }
  }

  ({Uint8List messageKey, Uint8List clearHeader})? _takeSkippedHeader(
    Uint8List nonce,
    Uint8List encrypted,
    ({Uint8List dh, int pn, int n}) Function(Uint8List clear) read,
  ) {
    for (final entry in _skipped.entries.toList()) {
      final clear = _tryHeader(entry.key.dh, nonce, encrypted);
      if (clear == null) continue;
      final fields = read(clear);
      if (fields.n != entry.key.n) {
        secureZero(clear);
        continue;
      }
      final messageKey = _skipped.remove(entry.key);
      if (messageKey == null) {
        secureZero(clear);
        continue;
      }
      return (messageKey: messageKey, clearHeader: clear);
    }
    return null;
  }

  Uint8List? _tryHeader(Uint8List? key, Uint8List nonce, Uint8List encrypted) {
    if (key == null) return null;
    try {
      return _encryptLike(key, encrypted, nonce, decrypt: true);
    } catch (_) {
      return null;
    }
  }

  (Uint8List, Uint8List) _sealHeader(Uint8List key, Uint8List clear) {
    final nonce = _randomNonce();
    final encrypted = _encryptLike(key, clear, nonce, decrypt: false);
    return (nonce, encrypted);
  }

  Uint8List _packEncrypted(
    Uint8List nonce,
    Uint8List encrypted,
    Uint8List body,
  ) {
    final out = Uint8List(21 + encrypted.length + body.length);
    out[0] = 0x44;
    out[1] = 0x52;
    out[2] = 0x48;
    out[3] = 0x31;
    out[4] = 1;
    out.setRange(5, 17, nonce);
    ByteData.sublistView(out).setUint32(17, encrypted.length);
    out.setRange(21, 21 + encrypted.length, encrypted);
    out.setRange(21 + encrypted.length, out.length, body);
    return out;
  }

  (Uint8List, Uint8List) _sharedHeaderKeys(Uint8List sharedSecret) {
    final salt = Uint8List(hash == DoubleRatchetHash.sha256 ? 32 : 64);
    final info = Uint8List.fromList(utf8.encode('pqforge-header-keys-v1'));
    final okm = _hkdf(salt: salt, ikm: sharedSecret, info: info);
    secureZero(salt);
    try {
      return (
        Uint8List(32)..setRange(0, 32, okm),
        Uint8List(32)..setRange(0, 32, okm, 32),
      );
    } finally {
      secureZero(okm);
    }
  }

  (Uint8List, Uint8List) _mixHe(Uint8List dhOut) {
    final okm = _hkdf(salt: _root, ikm: dhOut, info: _info, output: 96);
    try {
      _root.setRange(0, 32, okm);
      return (
        Uint8List(32)..setRange(0, 32, okm, 32),
        Uint8List(32)..setRange(0, 32, okm, 64),
      );
    } finally {
      secureZero(okm);
    }
  }

  Future<void> _dhRatchetHe(Uint8List remoteDh) async {
    _pn = _ns;
    _ns = 0;
    _nr = 0;
    final previousSending = _hks;
    _hks = _nhks;
    _nhks = null;
    if (previousSending != null && !identical(previousSending, _hks)) {
      secureZero(previousSending);
    }
    final previousReceiving = _hkr;
    _hkr = _nhkr;
    _nhkr = null;
    if (previousReceiving != null && !identical(previousReceiving, _hkr)) {
      secureZero(previousReceiving);
    }
    remoteRatchetKey = RatchetPublicKey(remoteDh);
    final first = await _exchange(_dhSecret, remoteDh);
    try {
      final oldReceiving = _receiving;
      final mixed = _mixHe(first);
      _receiving = mixed.$1;
      _nhkr = mixed.$2;
      if (oldReceiving != null) secureZero(oldReceiving);
    } finally {
      secureZero(first);
    }
    final next = await _freshRatchetKey();
    secureZero(_dhSecret);
    _dhSecret = next.secretKey;
    _dhPublic = next.publicKey;
    final second = await _exchange(_dhSecret, remoteDh);
    try {
      final oldSending = _sending;
      final mixed = _mixHe(second);
      _sending = mixed.$1;
      _nhks = mixed.$2;
      if (oldSending != null) secureZero(oldSending);
    } finally {
      secureZero(second);
    }
  }

  Uint8List _encryptLike(
    Uint8List key,
    Uint8List data,
    Uint8List aad, {
    required bool decrypt,
  }) {
    if (!decrypt) {
      return switch (suite) {
        PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmEncrypt(
          key: key,
          nonce: aad.length == 12 ? aad : _zeroNonce,
          plaintext: data,
          aad: aad.length == 12 ? aad : aad,
        ),
        PqForgeCipherSuite.chaCha20Poly1305 =>
          PqSymmetricPrimitives.chacha20Poly1305Encrypt(
            key: key,
            nonce: aad.length == 12 ? aad : _zeroNonce,
            plaintext: data,
            aad: aad,
          ),
      };
    }
    final nonce = aad.length == 12 ? aad : _zeroNonce;
    return switch (suite) {
      PqForgeCipherSuite.aes256Gcm => PqSymmetricPrimitives.aesGcmDecrypt(
        key: key,
        nonce: nonce,
        ciphertext: data,
        aad: aad,
      ),
      PqForgeCipherSuite.chaCha20Poly1305 =>
        PqSymmetricPrimitives.chacha20Poly1305Decrypt(
          key: key,
          nonce: nonce,
          ciphertext: data,
          aad: aad,
        ),
    };
  }

  Uint8List _randomNonce() {
    final out = Uint8List(12);
    final random = Random.secure();
    for (var i = 0; i < out.length; i++) {
      out[i] = random.nextInt(256);
    }
    return out;
  }

  static void _wipeHeader(Uint8List? key) {
    if (key != null) secureZero(key);
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
