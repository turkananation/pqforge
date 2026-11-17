import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqXeddsa', () {
    test(
      'libsignal verify_signature accepts the published identity signature',
      () {
        final public = _hex(
          'ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64',
        );
        final message = _hex(
          '05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a',
        );
        final signature = _hex(
          '5de88ca9a89b4a115da79109c67c9c7464a3e4180274f1cb8c63c298'
          '4e286dfbede82deb9dcd9fae0bfbb821569b3d9001bd8130cd11d486'
          'cef047bd60b86e88',
        );
        expect(
          PqXeddsa.verify(
            publicKey: public,
            message: message,
            signature: signature,
          ),
          isTrue,
        );
        signature[0] ^= 1;
        expect(
          PqXeddsa.verify(
            publicKey: public,
            message: message,
            signature: signature,
          ),
          isFalse,
        );
      },
    );

    test('calculate_signature matches libsignal byte for byte', () {
      for (final vector in _signVectors) {
        final secret = _hex(vector.secret);
        final signature = PqXeddsa.sign(
          secretKey: secret,
          message: _hex(vector.message),
          randomness: _hex(vector.random),
        );
        expect(signature, _hex(vector.signature));
        expect(signature[63] >> 7, vector.signBit);
        expect(PqXeddsa.publicKeyFromSecret(secret), _hex(vector.public));
        expect(
          PqXeddsa.verify(
            publicKey: _hex(vector.public),
            message: _hex(vector.message),
            signature: signature,
          ),
          isTrue,
        );
      }
    });

    test('public key matches package:cryptography X25519', () async {
      final secret = _hex(
        'c097248412e58bf05df487968205132794178e367637f5818f81e0e6ce73e865',
      );
      final pair = await X25519().newKeyPairFromSeed(secret);
      final public = await pair.extractPublicKey();
      expect(public.bytes, PqXeddsa.publicKeyFromSecret(secret));
    });

    test('an unclamped secret signs as its clamped form', () {
      final unclamped = Uint8List(32)..fillRange(0, 32, 0xff);
      final clamped = Uint8List.fromList(unclamped);
      clamped[0] &= 248;
      clamped[31] &= 127;
      clamped[31] |= 64;
      final message = Uint8List.fromList('x'.codeUnits);
      final random = Uint8List(64)..fillRange(0, 64, 1);
      expect(
        PqXeddsa.sign(
          secretKey: unclamped,
          message: message,
          randomness: random,
        ),
        PqXeddsa.sign(secretKey: clamped, message: message, randomness: random),
      );
    });

    test('a generated signature verifies and a flipped message does not', () {
      final pair = PqXeddsa.generateKeyPair();
      final message = Uint8List.fromList('pqforge'.codeUnits);
      final signature = PqXeddsa.sign(
        secretKey: pair.secretKey,
        message: message,
      );
      expect(signature.length, PqXeddsa.signatureBytes);
      expect(
        PqXeddsa.verify(
          publicKey: pair.publicKey,
          message: message,
          signature: signature,
        ),
        isTrue,
      );
      expect(
        PqXeddsa.verify(
          publicKey: pair.publicKey,
          message: Uint8List.fromList('pqforgf'.codeUnits),
          signature: signature,
        ),
        isFalse,
      );
    });

    test('bad lengths are refused', () {
      final secret = Uint8List(32);
      expect(
        () => PqXeddsa.sign(secretKey: Uint8List(31), message: Uint8List(0)),
        throwsArgumentError,
      );
      expect(
        () => PqXeddsa.sign(
          secretKey: secret,
          message: Uint8List(0),
          randomness: Uint8List(63),
        ),
        throwsArgumentError,
      );
      expect(
        PqXeddsa.verify(
          publicKey: Uint8List(31),
          message: Uint8List(0),
          signature: Uint8List(64),
        ),
        isFalse,
      );
      expect(
        PqXeddsa.verify(
          publicKey: Uint8List(32),
          message: Uint8List(0),
          signature: Uint8List(63),
        ),
        isFalse,
      );
    });

    test('a public key with the high bit set is rejected', () {
      final public = _hex(
        'ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64',
      );
      public[31] |= 0x80;
      expect(
        PqXeddsa.verify(
          publicKey: public,
          message: Uint8List(0),
          signature: Uint8List(64),
        ),
        isFalse,
      );
    });

    test('non-canonical and small-order public keys are rejected', () {
      final signature = Uint8List(64);
      for (final public in [
        Uint8List(32),
        Uint8List(32)..[0] = 1,
        Uint8List(32)
          ..fillRange(0, 31, 0xff)
          ..[31] = 0x7f,
      ]) {
        expect(
          PqXeddsa.verify(
            publicKey: public,
            message: Uint8List(0),
            signature: signature,
          ),
          isFalse,
          reason: public.toString(),
        );
      }
    });

    test('libsignal accepts S + L and rejects S with bit 253 set', () {
      final vector = _signVectors.first;
      final signature = _hex(vector.signature);
      final message = _hex(vector.message);
      final public = _hex(vector.public);
      final plusL = _addOrder(signature, 1);
      expect(
        PqXeddsa.verify(publicKey: public, message: message, signature: plusL),
        isTrue,
      );
      final bit253 = Uint8List.fromList(signature);
      bit253[32 + 31] = (bit253[32 + 31] & 0x7f) | 0x20;
      bit253[63] |= signature[63] & 0x80;
      expect(
        PqXeddsa.verify(publicKey: public, message: message, signature: bit253),
        isFalse,
      );
    });

    test('sign does not mutate the secret or a caller-supplied Z', () {
      final secret = _hex(_signVectors.first.secret);
      final before = Uint8List.fromList(secret);
      final z = _hex(_z11);
      final zBefore = Uint8List.fromList(z);
      PqXeddsa.sign(secretKey: secret, message: Uint8List(0), randomness: z);
      expect(secret, before);
      expect(z, zBefore);
    });

    test('signAll matches sign, including across isolates', () async {
      final secret = _hex(_signVectors[4].secret);
      final messages = [
        Uint8List(0),
        Uint8List.fromList('a'.codeUnits),
        Uint8List.fromList('bb'.codeUnits),
        Uint8List(4096)..fillRange(0, 4096, 0xab),
      ];
      final zs = [
        for (final fill in [1, 2, 3, 4]) Uint8List(64)..fillRange(0, 64, fill),
      ];
      final batch = await PqXeddsa.signAll(
        secretKey: secret,
        messages: messages,
        randomness: zs,
      );
      expect(batch, hasLength(4));
      for (var i = 0; i < messages.length; i++) {
        expect(
          batch[i],
          PqXeddsa.sign(
            secretKey: secret,
            message: messages[i],
            randomness: zs[i],
          ),
        );
      }
      final checks = await PqXeddsa.verifyAll(
        publicKeys: List.filled(4, PqXeddsa.publicKeyFromSecret(secret)),
        messages: messages,
        signatures: batch,
      );
      expect(checks, everyElement(isTrue));
      final flipped = Uint8List.fromList(batch[3])..[0] ^= 1;
      final mixed = await PqXeddsa.verifyAll(
        publicKeys: List.filled(4, PqXeddsa.publicKeyFromSecret(secret)),
        messages: messages,
        signatures: [batch[0], batch[1], batch[2], flipped],
      );
      expect(mixed, [true, true, true, false]);
    });

    test('batch length mismatches throw and an empty batch is empty', () async {
      final secret = Uint8List(32);
      expect(
        await PqXeddsa.signAll(secretKey: secret, messages: const []),
        isEmpty,
      );
      expect(
        () => PqXeddsa.signAll(
          secretKey: secret,
          messages: [Uint8List(0)],
          randomness: const [],
        ),
        throwsArgumentError,
      );
      expect(
        () => PqXeddsa.verifyAll(
          publicKeys: [Uint8List(32)],
          messages: [Uint8List(0), Uint8List(0)],
          signatures: [Uint8List(64)],
        ),
        throwsArgumentError,
      );
    });

    test('signAll draws Z on the caller isolate', () async {
      final calls = <int>[];
      PqRandom.generator = (length) {
        calls.add(length);
        return Uint8List(length)..fillRange(0, length, 7);
      };
      try {
        final secret = Uint8List(32)..[0] = 9;
        final signatures = await PqXeddsa.signAll(
          secretKey: secret,
          messages: [
            Uint8List(0),
            Uint8List.fromList(const [1]),
          ],
        );
        expect(calls, [64, 64]);
        final z = Uint8List(64)..fillRange(0, 64, 7);
        expect(
          signatures[0],
          PqXeddsa.sign(
            secretKey: secret,
            message: Uint8List(0),
            randomness: z,
          ),
        );
      } finally {
        PqRandom.useDefault();
      }
    });

    test('Pqxdh.signedPrekeyAuthentic is the libsignal prekey check', () {
      final identity = PqXeddsa.generateKeyPair();
      final prekey = PqXeddsa.generateKeyPair();
      final signature = PqXeddsa.sign(
        secretKey: identity.secretKey,
        message: prekey.publicKey,
        randomness: Uint8List(64)..fillRange(0, 64, 9),
      );
      final kem = Uint8List(PqxdhKem.kyber1024.publicKeyBytes);
      expect(
        Pqxdh.signedPrekeyAuthentic(
          PqxdhBundle(
            identityKey: RatchetPublicKey(identity.publicKey),
            signedPrekey: RatchetPublicKey(prekey.publicKey),
            signedPrekeySignature: signature,
            kemPublicKey: kem,
          ),
        ),
        isTrue,
      );
      final bad = Uint8List.fromList(signature)..[0] ^= 1;
      expect(
        Pqxdh.signedPrekeyAuthentic(
          PqxdhBundle(
            identityKey: RatchetPublicKey(identity.publicKey),
            signedPrekey: RatchetPublicKey(prekey.publicKey),
            signedPrekeySignature: bad,
            kemPublicKey: kem,
          ),
        ),
        isFalse,
      );
    });
  });
}

final class _SignVector {
  const _SignVector({
    required this.secret,
    required this.public,
    required this.message,
    required this.random,
    required this.signature,
    required this.signBit,
  });

  final String secret;
  final String public;
  final String message;
  final String random;
  final String signature;
  final int signBit;
}

const _z11 =
    '1111111111111111111111111111111111111111111111111111111111111111'
    '1111111111111111111111111111111111111111111111111111111111111111';
const _z42 =
    '4242424242424242424242424242424242424242424242424242424242424242'
    '4242424242424242424242424242424242424242424242424242424242424242';
const _z7a =
    '7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a'
    '7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a';
const _z01 =
    '0101010101010101010101010101010101010101010101010101010101010101'
    '0101010101010101010101010101010101010101010101010101010101010101';
const _z5a =
    '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'
    '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a';
const _z03 =
    '0303030303030303030303030303030303030303030303030303030303030303'
    '0303030303030303030303030303030303030303030303030303030303030303';

const _signVectors = <_SignVector>[
  _SignVector(
    secret: 'c097248412e58bf05df487968205132794178e367637f5818f81e0e6ce73e865',
    public: 'ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64',
    message:
        '05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a',
    random: _z11,
    signature:
        'c597b68d75882c0c259cf7fb8dc252b7eb00a738ac70b3386e08aefc118233ca'
        '5ebc2ab575faa148d747fc70b30c5115dcdd2cbfcb459c2a045e36ff7ec29f8d',
    signBit: 1,
  ),
  _SignVector(
    secret: 'c097248412e58bf05df487968205132794178e367637f5818f81e0e6ce73e865',
    public: 'ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64',
    message: '',
    random: _z42,
    signature:
        '93feb1d909729de4e5cf4321228bccc00ccd8a882916bfd060aad795eb705d27'
        '37a02cf8a688a99c0a35a224c59472e0afd8c762eea83da1c27955bf5a4b878c',
    signBit: 1,
  ),
  _SignVector(
    secret: '0000000000000000000000000000000000000000000000000000000000000000',
    public: '2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74',
    message: '7071666f726765',
    random: _z7a,
    signature:
        '7ccbec1af0c2cbf37fb00b6082aa571d15e8c3d0b642d3d4afdf656028858f1a'
        '409e108ed55c9a668de7bf4c46fa16f599661aedf1bf0450cb32664fe206e38e',
    signBit: 1,
  ),
  _SignVector(
    secret: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    public: '847c0d2c375234f365e660955187a3735a0f7613d1609d3a6a4d8c53aeaa5a22',
    message: '78',
    random: _z01,
    signature:
        '300f708b124455a4c92d9ecd95503cab0e8c8c2df1d38a43216993717dc4a4f0'
        'a588f65614007133457699f91ebc9dcb13c72833ceaa7e8496ff38112f9f2a82',
    signBit: 1,
  ),
  _SignVector(
    secret: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    public: '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c',
    message: '6d7367',
    random: _z5a,
    signature:
        '1ef5a4ab5550e56034bf70da4c6cbe58597ceddcb6984910cf161f71d6cb7539'
        '963afaf2e10c6d4e6480c00ae9df84efd3d05ac0c8fdcea49c723a57fd5d148d',
    signBit: 1,
  ),
  _SignVector(
    secret: '0811000000000000000000000000000000000000000000000000000000000000',
    public: '169782214673e8e46fcec877e6813faca9698814b99fc6a08f15c09478434507',
    message: '626974',
    random: _z03,
    signature:
        'c50ff89e012a49289b64a688f6de80d551d8db4f5c1f395c08e13e446aec029b'
        '1c7c7ed73262efed66a92b21cabefe0898bfd1c128591fd64e306acc98ba270b',
    signBit: 0,
  ),
];

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Ed25519 L. libsignal reduces S modulo L after clearing the sign bit.
final BigInt _order = BigInt.parse(
  '7237005577332262213973186563042994240857116359379907606001950938285454250989',
);

Uint8List _addOrder(Uint8List signature, int multiples) {
  final out = Uint8List.fromList(signature);
  final sign = out[63] & 0x80;
  out[63] &= 0x7f;
  var s = BigInt.zero;
  for (var i = 31; i >= 0; i--) {
    s = (s << 8) | BigInt.from(out[32 + i]);
  }
  s += _order * BigInt.from(multiples);
  for (var i = 0; i < 32; i++) {
    out[32 + i] = (s & BigInt.from(0xff)).toInt();
    s >>= 8;
  }
  out[63] = (out[63] & 0x7f) | sign;
  return out;
}
