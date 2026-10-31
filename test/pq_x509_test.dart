import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  final notBefore = DateTime.utc(2026, 1, 1);
  final notAfter = DateTime.utc(2027, 1, 1);
  final now = DateTime.utc(2026, 6, 1);
  final serial = Uint8List.fromList([1]);

  group('PqX509', () {
    test('ML-DSA-65 leaf round-trips and a flipped TBS bit does not', () {
      final keys = PqSignaturePrimitives.generateKeyPair(
        PqSignatureAlgorithm.mlDsa65,
      );
      final name = PqX509Name.commonName('localhost');
      final der = PqX509.mintLeaf(
        subject: name,
        publicKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, keys.publicKey),
        algorithm: PqX509Algorithm.mlDsa65,
        sign: (tbs) => PqSignaturePrimitives.sign(
          PqSignatureAlgorithm.mlDsa65,
          keys.secretKey,
          tbs,
        ),
        notBefore: notBefore,
        notAfter: notAfter,
        serial: serial,
        subjectAltNames: [PqX509DnsName('localhost')],
      );
      final parsed = PqX509.parse(der).certificate!;
      expect(parsed.algorithm, PqX509Algorithm.mlDsa65);
      expect(parsed.version, 3);
      expect(PqX509.checkSignature(parsed, parsed.publicKey), isTrue);
      expect(
        PqX509.validate(chain: [der], anchors: [der], now: now).trusted,
        isTrue,
      );
      final flipped = Uint8List.fromList(der);
      final at = _indexOf(flipped, 'localhost'.codeUnits);
      flipped[at] ^= 1;
      final bad = PqX509.parse(flipped).certificate!;
      expect(PqX509.checkSignature(bad, parsed.publicKey), isFalse);
    });

    test('ML-DSA-87 and ML-DSA-44 verify inside PqX509', () {
      for (final algorithm in [
        PqSignatureAlgorithm.mlDsa87,
        PqSignatureAlgorithm.mlDsa44,
      ]) {
        final which = algorithm == PqSignatureAlgorithm.mlDsa87
            ? PqX509Algorithm.mlDsa87
            : PqX509Algorithm.mlDsa44;
        final keys = PqSignaturePrimitives.generateKeyPair(algorithm);
        final der = _leaf(
          publicKey: PqX509MlDsaKey(which, keys.publicKey),
          algorithm: which,
          sign: (tbs) =>
              PqSignaturePrimitives.sign(algorithm, keys.secretKey, tbs),
          notBefore: notBefore,
          notAfter: notAfter,
        );
        final parsed = PqX509.parse(der).certificate!;
        expect(PqX509.checkSignature(parsed, parsed.publicKey), isTrue);
      }
    });

    test('P-256, P-384, and Ed25519 leaves verify', () {
      final p256 = PqEcdsaP256.generateKeyPair();
      final p384 = PqEcdsaP384.generateKeyPair();
      final ed = PqEd25519.generateKeyPair();
      final cases =
          <(PqX509PublicKey, PqX509Algorithm, Uint8List Function(Uint8List))>[
            (
              PqX509EcdsaP256Key(p256.publicKey),
              PqX509Algorithm.ecdsaP256Sha256,
              (tbs) => PqX509.encodeEcdsaSignature(
                PqEcdsaP256.sign(privateKey: p256.secretKey, message: tbs),
              ),
            ),
            (
              PqX509EcdsaP384Key(p384.publicKey),
              PqX509Algorithm.ecdsaP384Sha384,
              (tbs) => PqX509.encodeEcdsaSignature(
                PqEcdsaP384.sign(privateKey: p384.secretKey, message: tbs),
              ),
            ),
            (
              PqX509Ed25519Key(ed.publicKey),
              PqX509Algorithm.ed25519,
              (tbs) => PqEd25519.sign(secretKey: ed.secretKey, message: tbs),
            ),
          ];
      for (final item in cases) {
        final der = _leaf(
          publicKey: item.$1,
          algorithm: item.$2,
          sign: item.$3,
          notBefore: notBefore,
          notAfter: notAfter,
        );
        final parsed = PqX509.parse(der).certificate!;
        expect(
          PqX509.checkSignature(parsed, parsed.publicKey),
          isTrue,
          reason: '${item.$2}',
        );
        expect(
          PqX509.validate(chain: [der], anchors: [der], now: now).trusted,
          isTrue,
        );
      }
    });

    test('RSA PKCS#1 and PSS leaves verify', () {
      final kp = PqRsa.generateKeyPair();
      final key = PqX509RsaKey(kp.modulus, kp.exponent);
      final pkcs1 = _leaf(
        publicKey: key,
        algorithm: PqX509Algorithm.rsaPkcs1Sha256,
        sign: (tbs) => PqRsa.signPkcs1(
          privateKey: kp.privateKey,
          message: tbs,
          hash: PqRsaHash.sha256,
        ),
        notBefore: notBefore,
        notAfter: notAfter,
      );
      final pss = _leaf(
        publicKey: key,
        algorithm: PqX509Algorithm.rsaPssSha256,
        sign: (tbs) => PqRsa.signPss(
          privateKey: kp.privateKey,
          message: tbs,
          hash: PqRsaHash.sha256,
        ),
        notBefore: notBefore,
        notAfter: notAfter,
      );
      for (final der in [pkcs1, pss]) {
        final parsed = PqX509.parse(der).certificate!;
        expect(PqX509.checkSignature(parsed, key), isTrue);
      }
    });

    test('validity is inclusive and a non-UTC clock is badTime', () {
      final keys = PqSignaturePrimitives.generateKeyPair(
        PqSignatureAlgorithm.mlDsa65,
      );
      final der = _leaf(
        publicKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, keys.publicKey),
        algorithm: PqX509Algorithm.mlDsa65,
        sign: (tbs) => PqSignaturePrimitives.sign(
          PqSignatureAlgorithm.mlDsa65,
          keys.secretKey,
          tbs,
        ),
        notBefore: notBefore,
        notAfter: notAfter,
      );
      expect(
        PqX509.validate(chain: [der], anchors: [der], now: notBefore).trusted,
        isTrue,
      );
      expect(
        PqX509.validate(chain: [der], anchors: [der], now: notAfter).trusted,
        isTrue,
      );
      expect(
        PqX509.validate(
          chain: [der],
          anchors: [der],
          now: notBefore.subtract(const Duration(seconds: 1)),
        ).failure,
        PqX509Failure.notYetValid,
      );
      expect(
        PqX509.validate(
          chain: [der],
          anchors: [der],
          now: DateTime(2026, 6, 1),
        ).failure,
        PqX509Failure.badTime,
      );
    });

    test(
      'v1 parses, a negative serial does not, and nine certificates are too long',
      () {
        final keys = PqSignaturePrimitives.generateKeyPair(
          PqSignatureAlgorithm.mlDsa65,
        );
        final name = PqX509Name.commonName('localhost');
        final der = PqX509.mint(
          issuer: name,
          subject: name,
          publicKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, keys.publicKey),
          algorithm: PqX509Algorithm.mlDsa65,
          sign: (tbs) => PqSignaturePrimitives.sign(
            PqSignatureAlgorithm.mlDsa65,
            keys.secretKey,
            tbs,
          ),
          notBefore: notBefore,
          notAfter: notAfter,
          serial: serial,
          includeEku: false,
          version3: false,
        );
        final parsed = PqX509.parse(der).certificate!;
        expect(parsed.version, 1);
        expect(parsed.extensions, isEmpty);
        expect(
          PqX509.validate(chain: [der], anchors: [der], now: now).trusted,
          isTrue,
        );
        final negative = Uint8List.fromList(der);
        final serialAt = _indexOf(negative, [0x02, 0x01, 0x01]);
        negative[serialAt + 2] = 0x80;
        expect(PqX509.parse(negative).failure, PqX509Failure.notDer);
        expect(
          PqX509.validate(
            chain: List<Uint8List>.filled(9, der),
            anchors: [der],
            now: now,
          ).failure,
          PqX509Failure.pathTooLong,
        );
      },
    );

    test(
      'a leaf plus an intermediate validates, and a broken link does not',
      () {
        final caKeys = PqSignaturePrimitives.generateKeyPair(
          PqSignatureAlgorithm.mlDsa65,
        );
        final leafKeys = PqSignaturePrimitives.generateKeyPair(
          PqSignatureAlgorithm.mlDsa65,
        );
        final caName = PqX509Name.commonName('ca');
        final leafName = PqX509Name.commonName('leaf');
        Uint8List caSign(Uint8List tbs) => PqSignaturePrimitives.sign(
          PqSignatureAlgorithm.mlDsa65,
          caKeys.secretKey,
          tbs,
        );
        final ca = PqX509.mint(
          issuer: caName,
          subject: caName,
          publicKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, caKeys.publicKey),
          algorithm: PqX509Algorithm.mlDsa65,
          sign: caSign,
          notBefore: notBefore,
          notAfter: notAfter,
          serial: Uint8List.fromList([2]),
          ca: true,
          digitalSignature: false,
          keyCertSign: true,
          includeEku: false,
          permittedDns: ['example.com'],
        );
        final leaf = PqX509.mint(
          issuer: caName,
          subject: leafName,
          publicKey: PqX509MlDsaKey(
            PqX509Algorithm.mlDsa65,
            leafKeys.publicKey,
          ),
          algorithm: PqX509Algorithm.mlDsa65,
          sign: caSign,
          notBefore: notBefore,
          notAfter: notAfter,
          serial: Uint8List.fromList([3]),
          subjectAltNames: [PqX509DnsName('www.example.com')],
          includeEku: true,
        );
        expect(
          PqX509.validate(chain: [leaf, ca], anchors: [ca], now: now).trusted,
          isTrue,
        );
        final outside = PqX509.mint(
          issuer: caName,
          subject: leafName,
          publicKey: PqX509MlDsaKey(
            PqX509Algorithm.mlDsa65,
            leafKeys.publicKey,
          ),
          algorithm: PqX509Algorithm.mlDsa65,
          sign: caSign,
          notBefore: notBefore,
          notAfter: notAfter,
          serial: Uint8List.fromList([4]),
          subjectAltNames: [PqX509DnsName('www.other.test')],
        );
        expect(
          PqX509.validate(
            chain: [outside, ca],
            anchors: [ca],
            now: now,
          ).failure,
          PqX509Failure.badConstraint,
        );
        final uri = PqX509.mint(
          issuer: caName,
          subject: caName,
          publicKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, caKeys.publicKey),
          algorithm: PqX509Algorithm.mlDsa65,
          sign: caSign,
          notBefore: notBefore,
          notAfter: notAfter,
          serial: Uint8List.fromList([5]),
          ca: true,
          digitalSignature: false,
          keyCertSign: true,
          includeEku: false,
          uriNameConstraint: true,
        );
        expect(
          PqX509.validate(chain: [leaf, uri], anchors: [uri], now: now).failure,
          PqX509Failure.badConstraint,
        );
        final broken = Uint8List.fromList(leaf);
        final at = _indexOf(broken, 'leaf'.codeUnits);
        broken[at] ^= 1;
        expect(
          PqX509.validate(chain: [broken, ca], anchors: [ca], now: now).failure,
          PqX509Failure.badSignature,
        );
      },
    );

    test('hostile DER stops before a signature check', () {
      expect(PqX509.parse(Uint8List(0)).failure, PqX509Failure.truncated);
      expect(
        PqX509.parse(Uint8List.fromList([0x30, 0x80, 0x00, 0x00])).failure,
        PqX509Failure.notDer,
      );
      expect(
        PqX509.parse(Uint8List.fromList([0x30, 0x81, 0x01, 0x00])).failure,
        PqX509Failure.notDer,
      );
      expect(
        PqX509.parse(Uint8List(PqX509.maxCertificateBytes + 1)).failure,
        PqX509Failure.tooLarge,
      );
    });
  });
}

Uint8List _leaf({
  required PqX509PublicKey publicKey,
  required PqX509Algorithm algorithm,
  required Uint8List Function(Uint8List tbs) sign,
  required DateTime notBefore,
  required DateTime notAfter,
}) {
  return PqX509.mintLeaf(
    subject: PqX509Name.commonName('localhost'),
    publicKey: publicKey,
    algorithm: algorithm,
    sign: sign,
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([1]),
    subjectAltNames: [PqX509DnsName('localhost')],
  );
}

int _indexOf(Uint8List haystack, List<int> needle) {
  for (var i = 0; i <= haystack.length - needle.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) match = false;
    }
    if (match) return i;
  }
  throw StateError('needle not found');
}
