/// HKDF labels for the ML-KEM Braid, SPQR, and the Triple Ratchet.
///
/// SHA-256. 32-byte outputs except where the specification asks for 64 or 96.
/// Section 7.2 of Double Ratchet revision 4 repeats the INIT `ikm` and info
/// for `KDF_SCKA_CK`. Those fields do not depend on the chain key or the
/// counter. Section 5.2 does. This file follows section 5.2.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:zeroize/zeroize.dart';

import '../primitives/pq_primitives.dart';

/// Domain-separated HKDF-SHA-256 for the braid and the two ratchets around it.
abstract final class SpqrKdf {
  /// Braid `PROTOCOL_INFO`. Implementer-defined. Not a Signal string.
  static const braidProtocolInfo = 'pqforge-braid-v1_MLKEM768_SHA-256';

  /// SPQR `SPQR_PROTOCOL_INFO`.
  static const protocolInfo = 'pqforge-spqr-v1_MLKEM768_SHA-256';

  /// Triple Ratchet `TR_PROTOCOL_INFO`.
  static const tripleProtocolInfo =
      'pqforge-triple-ratchet-v1_X25519_MLKEM768_SHA-256';

  /// `KDF_SCKA_INIT`. 96 bytes: root, sender chain, receiver chain.
  static ({Uint8List root, Uint8List sender, Uint8List receiver}) chainStart(
    Uint8List sharedSecret,
  ) {
    final okm = _hkdf(
      ikm: sharedSecret,
      salt: Uint8List(32),
      info: _ascii('${protocolInfo}Chain Start'),
      length: 96,
    );
    return _split96(okm);
  }

  /// `KDF_SCKA_RK`. Salt is the current root. IKM is the braid output.
  static ({Uint8List root, Uint8List sender, Uint8List receiver}) addEpoch({
    required Uint8List root,
    required Uint8List sckaOutput,
  }) {
    final okm = _hkdf(
      ikm: sckaOutput,
      salt: root,
      info: _ascii('${protocolInfo}Chain Add Epoch'),
      length: 96,
    );
    return _split96(okm);
  }

  /// `KDF_SCKA_CK`. Info ends with the counter as a big-endian uint32.
  static ({Uint8List chain, Uint8List message}) chainKey(
    Uint8List chain, {
    required int counter,
  }) {
    if (counter < 0 || counter > 0xFFFFFFFF) {
      throw ArgumentError.value(counter, 'counter', 'uint32');
    }
    final info = _ascii('${protocolInfo}Chain Key');
    final full = Uint8List(info.length + 4);
    full.setRange(0, info.length, info);
    ByteData.sublistView(full).setUint32(info.length, counter);
    final okm = _hkdf(ikm: chain, salt: Uint8List(32), info: full, length: 64);
    final next = Uint8List.sublistView(okm, 0, 32);
    final message = Uint8List.sublistView(okm, 32, 64);
    final out = (
      chain: Uint8List.fromList(next),
      message: Uint8List.fromList(message),
    );
    secureZero(okm);
    return out;
  }

  /// `KDF_OK`. The epoch secret the braid returns. Not the raw ML-KEM secret.
  static Uint8List sckaKey(Uint8List sharedSecret, {required int epoch}) {
    final label = _ascii('$braidProtocolInfo:SCKA Key');
    final info = Uint8List(label.length + 8);
    info.setRange(0, label.length, label);
    info.setRange(label.length, info.length, epochBytes(epoch));
    return _hkdf(
      ikm: sharedSecret,
      salt: Uint8List(32),
      info: info,
      length: 32,
    );
  }

  /// `KDF_AUTH`. 64 bytes: the next authenticator root, then the MAC key.
  static ({Uint8List root, Uint8List mac}) authenticator({
    required Uint8List rootKey,
    required Uint8List updateKey,
    required int epoch,
  }) {
    final label = _ascii('$braidProtocolInfo:Authenticator Update');
    final info = Uint8List(label.length + 8);
    info.setRange(0, label.length, label);
    info.setRange(label.length, info.length, epochBytes(epoch));
    final okm = _hkdf(ikm: updateKey, salt: rootKey, info: info, length: 64);
    final out = (
      root: Uint8List.fromList(Uint8List.sublistView(okm, 0, 32)),
      mac: Uint8List.fromList(Uint8List.sublistView(okm, 32, 64)),
    );
    secureZero(okm);
    return out;
  }

  /// `KDF_HYBRID`. Salt is the post-quantum message key. IKM is the X25519 one.
  static Uint8List hybrid({
    required Uint8List ellipticMessageKey,
    required Uint8List postQuantumMessageKey,
  }) {
    return _hkdf(
      ikm: ellipticMessageKey,
      salt: postQuantumMessageKey,
      info: _ascii(tripleProtocolInfo),
      length: 32,
    );
  }

  /// Expands one PQXDH secret into the two Triple Ratchet seeds.
  static ({Uint8List elliptic, Uint8List braid}) split(Uint8List sharedSecret) {
    final okm = _hkdf(
      ikm: sharedSecret,
      salt: Uint8List(32),
      info: _ascii('${tripleProtocolInfo}Split SK'),
      length: 64,
    );
    final out = (
      elliptic: Uint8List.fromList(Uint8List.sublistView(okm, 0, 32)),
      braid: Uint8List.fromList(Uint8List.sublistView(okm, 32, 64)),
    );
    secureZero(okm);
    return out;
  }

  /// Big-endian uint64. The braid's `ToBytes(epoch)`.
  static Uint8List epochBytes(int epoch) {
    if (epoch < 0) {
      throw ArgumentError.value(epoch, 'epoch', 'negative');
    }
    final out = Uint8List(8);
    var value = epoch;
    for (var i = 7; i >= 0; i--) {
      out[i] = value & 0xff;
      value >>= 8;
    }
    if (value != 0) {
      throw ArgumentError.value(epoch, 'epoch', 'does not fit in uint64');
    }
    return out;
  }

  static ({Uint8List root, Uint8List sender, Uint8List receiver}) _split96(
    Uint8List okm,
  ) {
    final out = (
      root: Uint8List.fromList(Uint8List.sublistView(okm, 0, 32)),
      sender: Uint8List.fromList(Uint8List.sublistView(okm, 32, 64)),
      receiver: Uint8List.fromList(Uint8List.sublistView(okm, 64, 96)),
    );
    secureZero(okm);
    return out;
  }

  static Uint8List _hkdf({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    required int length,
  }) => PqSymmetricPrimitives.hkdfSha256(
    ikm: ikm,
    salt: salt,
    info: info,
    outputBytes: length,
  );

  static Uint8List _ascii(String value) =>
      Uint8List.fromList(utf8.encode(value));
}
