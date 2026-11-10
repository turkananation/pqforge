/// X-Wing HPKE message container.
///
/// Magic `XW01`. Not `PQF1`, and not a `.pqfs` header. The body is the
/// HPKE `enc` (1120 bytes) and then the AEAD ciphertext.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../exceptions/pqforge_exception.dart';
import 'pq_hpke.dart';

/// Bytes written by `pqforge hpke seal` and read by `pqforge hpke open`.
abstract final class PqXWingMessage {
  static const magic = 'XW01';

  static Uint8List encode({
    required HpkeSuite suite,
    required Uint8List enc,
    required Uint8List ciphertext,
  }) {
    if (suite.kem != HpkeKem.xWing) {
      throw ArgumentError.value(suite.kem, 'suite.kem', 'only X-Wing');
    }
    if (enc.length != HpkeKem.xWing.nEnc) {
      throw ArgumentError.value(
        enc.length,
        'enc',
        'expected ${HpkeKem.xWing.nEnc} bytes',
      );
    }
    if (ciphertext.isEmpty) {
      throw ArgumentError.value(ciphertext.length, 'ciphertext', 'empty');
    }
    final out = Uint8List(12 + enc.length + ciphertext.length);
    out.setRange(0, 4, ascii.encode(magic));
    _put16(out, 4, suite.kem.id);
    _put16(out, 6, suite.kdf.id);
    _put16(out, 8, suite.aead.id);
    _put16(out, 10, enc.length);
    out.setRange(12, 12 + enc.length, enc);
    out.setRange(12 + enc.length, out.length, ciphertext);
    return out;
  }

  static ({HpkeSuite suite, Uint8List enc, Uint8List ciphertext}) decode(
    Uint8List bytes,
  ) {
    if (bytes.length >= 4 &&
        ascii.decode(bytes.sublist(0, 4), allowInvalid: true) ==
            pqForgeEnvelopeMagic) {
      throw const PqForgeException('X-Wing messages are not PQF1 envelopes');
    }
    if (bytes.length < 12 ||
        ascii.decode(bytes.sublist(0, 4), allowInvalid: true) != magic) {
      throw const PqForgeException('Invalid X-Wing message magic');
    }
    final kem = HpkeKem.fromId(_get16(bytes, 4));
    if (kem != HpkeKem.xWing) {
      throw const PqForgeException('X-Wing message names a different KEM');
    }
    final kdf = HpkeKdf.fromId(_get16(bytes, 6));
    final aead = HpkeAead.fromId(_get16(bytes, 8));
    final encLen = _get16(bytes, 10);
    if (encLen != kem.nEnc || bytes.length <= 12 + encLen) {
      throw const PqForgeException('Invalid X-Wing message length');
    }
    return (
      suite: HpkeSuite(kem: kem, kdf: kdf, aead: aead),
      enc: Uint8List.sublistView(bytes, 12, 12 + encLen),
      ciphertext: Uint8List.sublistView(bytes, 12 + encLen),
    );
  }
}

void _put16(Uint8List out, int offset, int value) {
  out[offset] = (value >> 8) & 0xff;
  out[offset + 1] = value & 0xff;
}

int _get16(Uint8List bytes, int offset) =>
    (bytes[offset] << 8) | bytes[offset + 1];
