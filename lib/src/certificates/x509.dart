import 'dart:typed_data';

import '../algorithms/pq_algorithms.dart';
import '../hybrid/pq_ecdsa_p256.dart';
import '../hybrid/pq_ecdsa_p384.dart';
import '../hybrid/pq_ed25519.dart';
import '../hybrid/pq_rsa.dart';
import '../primitives/pq_primitives.dart';
import 'x509_der.dart';

/// A parsed certificate, or the first reason parsing stopped.
final class PqX509Parsed {
  const PqX509Parsed.ok(this.certificate) : failure = null;

  const PqX509Parsed.fail(this.failure) : certificate = null;

  final PqX509Certificate? certificate;
  final PqX509Failure? failure;
}

/// A path check against caller-supplied anchors.
final class PqX509Path {
  const PqX509Path.trusted(this.leaf) : trusted = true, failure = null;

  const PqX509Path.fail(this.failure) : trusted = false, leaf = null;

  final bool trusted;
  final PqX509Certificate? leaf;
  final PqX509Failure? failure;
}

enum PqX509Failure {
  truncated,
  notDer,
  unsupportedVersion,
  unsupportedAlgorithm,
  badTime,
  badName,
  depth,
  tooLarge,
  badSignature,
  expired,
  notYetValid,
  untrusted,
  pathTooLong,
  badConstraint,
  mustStaple,
}

enum PqX509Algorithm {
  mlDsa44,
  mlDsa65,
  mlDsa87,
  ecdsaP256Sha256,
  ecdsaP384Sha384,
  ed25519,
  rsaPkcs1Sha256,
  rsaPkcs1Sha384,
  rsaPkcs1Sha512,
  rsaPssSha256,
  rsaPssSha384,
  rsaPssSha512,
}

sealed class PqX509PublicKey {
  const PqX509PublicKey();
}

final class PqX509MlDsaKey extends PqX509PublicKey {
  const PqX509MlDsaKey(this.algorithm, this.raw);

  final PqX509Algorithm algorithm;
  final Uint8List raw;
}

final class PqX509EcdsaP256Key extends PqX509PublicKey {
  const PqX509EcdsaP256Key(this.uncompressed);

  final Uint8List uncompressed;
}

final class PqX509EcdsaP384Key extends PqX509PublicKey {
  const PqX509EcdsaP384Key(this.uncompressed);

  final Uint8List uncompressed;
}

final class PqX509Ed25519Key extends PqX509PublicKey {
  const PqX509Ed25519Key(this.raw);

  final Uint8List raw;
}

final class PqX509RsaKey extends PqX509PublicKey {
  const PqX509RsaKey(this.modulus, this.exponent);

  final Uint8List modulus;
  final Uint8List exponent;
}

/// DER `Name`. Equality is the encoding, not a string.
final class PqX509Name {
  PqX509Name(this.der);

  /// One CN. PrintableString when every character fits, otherwise UTF8String.
  factory PqX509Name.commonName(String cn) {
    if (cn.isEmpty || cn.length > 64) {
      throw ArgumentError.value(cn, 'cn', 'empty or longer than 64');
    }
    final bytes = Uint8List.fromList(cn.codeUnits);
    for (final byte in bytes) {
      if (byte > 0x7f) {
        throw ArgumentError.value(cn, 'cn', 'not ASCII');
      }
    }
    final tag = _isPrintable(bytes) ? 0x13 : 0x0c;
    final atv = DerWriter()
      ..sequence(
        (DerWriter()
              ..oid(_cn)
              ..tlv(tag, bytes))
            .take(),
      );
    final set = DerWriter()..tlv(0x31, atv.take());
    return PqX509Name((DerWriter()..sequence(set.take())).take());
  }

  final Uint8List der;
}

final class PqX509Extension {
  const PqX509Extension(this.oid, this.critical, this.value);

  final List<int> oid;
  final bool critical;
  final Uint8List value;
}

sealed class PqX509GeneralName {
  const PqX509GeneralName();
}

final class PqX509DnsName extends PqX509GeneralName {
  const PqX509DnsName(this.ascii);

  final String ascii;
}

final class PqX509Ip4Name extends PqX509GeneralName {
  const PqX509Ip4Name(this.octets);

  final Uint8List octets;
}

final class PqX509Ip6Name extends PqX509GeneralName {
  const PqX509Ip6Name(this.octets);

  final Uint8List octets;
}

/// RFC 822 mailbox. The domain comparison is case-insensitive.
final class PqX509EmailName extends PqX509GeneralName {
  const PqX509EmailName(this.mailbox);

  final String mailbox;
}

/// Uniform resource identifier. Name constraints apply to the host.
final class PqX509UriName extends PqX509GeneralName {
  const PqX509UriName(this.uri);

  final String uri;
}

/// `directoryName`, the DER `Name`.
final class PqX509DirectoryName extends PqX509GeneralName {
  const PqX509DirectoryName(this.name);

  final Uint8List name;
}

/// A GeneralName this validator does not implement.
///
/// A certificate may carry one in a subjectAltName. A name constraint that
/// carries one cannot be evaluated, so the path fails closed.
final class PqX509OtherName extends PqX509GeneralName {
  const PqX509OtherName();
}

final class PqX509Certificate {
  PqX509Certificate({
    required this.der,
    required this.tbs,
    required this.algorithm,
    required this.signature,
    required this.issuerDer,
    required this.subjectDer,
    required this.serial,
    required this.notBefore,
    required this.notAfter,
    required this.publicKey,
    required this.version,
    required this.extensions,
    required this.subjectAltNames,
    required this.ca,
    required this.pathLen,
    required this.keyUsageBits,
    required this.extKeyUsage,
    this.issuerUniqueId,
    this.subjectUniqueId,
    this.mustStaple = false,
    this.pssSaltLength,
  });

  final Uint8List der;
  final Uint8List tbs;
  final PqX509Algorithm algorithm;
  final Uint8List signature;
  final Uint8List issuerDer;
  final Uint8List subjectDer;
  final Uint8List serial;
  final DateTime notBefore;
  final DateTime notAfter;
  final PqX509PublicKey publicKey;
  final int version;
  final List<PqX509Extension> extensions;
  final List<PqX509GeneralName> subjectAltNames;
  final bool? ca;
  final int? pathLen;
  final int? keyUsageBits;
  final List<List<int>> extKeyUsage;

  /// [1] IMPLICIT UniqueIdentifier, when the certificate has one.
  final Uint8List? issuerUniqueId;

  /// [2] IMPLICIT UniqueIdentifier, when the certificate has one.
  final Uint8List? subjectUniqueId;

  /// Critical or non-critical `id-pe-tlsfeature` listing `status_request` (5).
  final bool mustStaple;

  /// RSASSA-PSS salt length from the signature algorithm. Null otherwise.
  /// RFC 4055's omitted salt field is 20, and that 20 is stored here.
  final int? pssSaltLength;
}

/// X.509 certificates (RFC 5280) and the signature algorithms pqforge can
/// check. No sockets, no trust store, no TLS alerts.
abstract final class PqX509 {
  static const int maxCertificateBytes = 65536;
  static const int maxNameBytes = 8192;
  static const int maxChainLength = 8;

  /// DER only. Hostile input returns a [PqX509Failure] and does not throw.
  static PqX509Parsed parse(Uint8List der) {
    if (der.length > maxCertificateBytes) {
      return const PqX509Parsed.fail(PqX509Failure.tooLarge);
    }
    try {
      return _parse(der);
    } on _Stop catch (stop) {
      return PqX509Parsed.fail(stop.failure);
    }
  }

  /// Signature over [certificate.tbs] under [key]. False on any mismatch.
  static bool checkSignature(
    PqX509Certificate certificate,
    PqX509PublicKey key,
  ) {
    try {
      return _check(certificate, key);
    } catch (_) {
      return false;
    }
  }

  /// [ocspResponsePresent] must be true when any certificate on the path
  /// requires OCSP stapling (RFC 7633). [acceptedCriticalOids] are extensions
  /// this process implements. Any other critical extension is `badConstraint`.
  static PqX509Path validate({
    required List<Uint8List> chain,
    required List<Uint8List> anchors,
    required DateTime now,
    bool ocspResponsePresent = false,
    List<List<int>> acceptedCriticalOids = const [],
  }) {
    if (!now.isUtc) return const PqX509Path.fail(PqX509Failure.badTime);
    if (chain.isEmpty || anchors.isEmpty) {
      return const PqX509Path.fail(PqX509Failure.untrusted);
    }
    if (chain.length > maxChainLength) {
      return const PqX509Path.fail(PqX509Failure.pathTooLong);
    }
    final certs = <PqX509Certificate>[];
    for (final der in chain) {
      final parsed = parse(der);
      if (parsed.certificate == null) {
        return PqX509Path.fail(parsed.failure!);
      }
      certs.add(parsed.certificate!);
    }
    final roots = <PqX509Certificate>[];
    for (final der in anchors) {
      final parsed = parse(der);
      if (parsed.certificate == null) {
        return PqX509Path.fail(parsed.failure!);
      }
      roots.add(parsed.certificate!);
    }
    return _path(certs, roots, now, ocspResponsePresent, acceptedCriticalOids);
  }

  /// Self-signed v3 TLS leaf. [sign] is called once, on the exact TBS bytes
  /// embedded in the result. ECDSA signatures are DER `SEQUENCE { r, s }`
  /// from [encodeEcdsaSignature]. ML-DSA, Ed25519, and RSA signatures are raw.
  static Uint8List mintLeaf({
    required PqX509Name subject,
    required PqX509PublicKey publicKey,
    required PqX509Algorithm algorithm,
    required Uint8List Function(Uint8List tbs) sign,
    required DateTime notBefore,
    required DateTime notAfter,
    required Uint8List serial,
    required List<PqX509GeneralName> subjectAltNames,
  }) {
    return mint(
      issuer: subject,
      subject: subject,
      publicKey: publicKey,
      algorithm: algorithm,
      sign: sign,
      notBefore: notBefore,
      notAfter: notAfter,
      serial: serial,
      subjectAltNames: subjectAltNames,
    );
  }

  /// General certificate. [mintLeaf] is the TLS preset of this.
  /// [version3] false omits the version and every extension (a v1 certificate).
  static Uint8List mint({
    required PqX509Name issuer,
    required PqX509Name subject,
    required PqX509PublicKey publicKey,
    required PqX509Algorithm algorithm,
    required Uint8List Function(Uint8List tbs) sign,
    required DateTime notBefore,
    required DateTime notAfter,
    required Uint8List serial,
    List<PqX509GeneralName> subjectAltNames = const [],
    bool ca = false,
    int? pathLen,
    bool digitalSignature = true,
    bool keyCertSign = false,
    bool includeEku = true,
    List<String> permittedDns = const [],
    List<String> excludedDns = const [],
    List<String> permittedEmail = const [],
    List<String> excludedEmail = const [],
    List<String> permittedUri = const [],
    List<String> excludedUri = const [],
    List<PqX509Name> permittedDirectory = const [],
    List<PqX509Name> excludedDirectory = const [],
    bool permitOtherName = false,
    bool mustStaple = false,
    bool pssPublicKey = false,
    int? pssSaltLength,
    Uint8List? issuerUniqueId,
    Uint8List? subjectUniqueId,
    bool version3 = true,
  }) {
    _requireUtc(notBefore, 'notBefore');
    _requireUtc(notAfter, 'notAfter');
    if (!notBefore.isBefore(notAfter) && notBefore != notAfter) {
      throw ArgumentError('notBefore is after notAfter');
    }
    if (serial.isEmpty || serial.length > 20 || serial[0] == 0) {
      throw ArgumentError.value(
        serial,
        'serial',
        'not a positive 1..20 octet integer',
      );
    }
    if (pssSaltLength != null && (pssSaltLength < 0 || pssSaltLength > 512)) {
      throw ArgumentError.value(
        pssSaltLength,
        'pssSaltLength',
        'expected 0..512',
      );
    }
    if (!version3 &&
        (ca ||
            subjectAltNames.isNotEmpty ||
            includeEku ||
            permittedDns.isNotEmpty ||
            excludedDns.isNotEmpty ||
            permittedEmail.isNotEmpty ||
            excludedEmail.isNotEmpty ||
            permittedUri.isNotEmpty ||
            excludedUri.isNotEmpty ||
            permittedDirectory.isNotEmpty ||
            excludedDirectory.isNotEmpty ||
            permitOtherName ||
            mustStaple)) {
      throw ArgumentError('a v1 certificate cannot carry extensions');
    }
    final algorithmId = _algorithmDer(algorithm, pssSaltLength);
    final tbsBody = DerWriter();
    if (version3) {
      tbsBody.tlv(
        0xa0,
        (DerWriter()..integerUnsigned(Uint8List.fromList([2]))).take(),
      );
    }
    tbsBody.integerUnsigned(serial);
    tbsBody.raw(algorithmId);
    tbsBody.raw(issuer.der);
    tbsBody.sequence(_validity(notBefore, notAfter));
    tbsBody.raw(subject.der);
    tbsBody.raw(
      _spki(
        publicKey,
        algorithm: algorithm,
        pssPublicKey: pssPublicKey,
        pssSaltLength: pssSaltLength,
      ),
    );
    if (issuerUniqueId != null) tbsBody.bitString(issuerUniqueId, tag: 0x81);
    if (subjectUniqueId != null) tbsBody.bitString(subjectUniqueId, tag: 0x82);
    if (version3) {
      tbsBody.tlv(
        0xa3,
        (DerWriter()..sequence(
              _extensions(
                ca: ca,
                pathLen: pathLen,
                digitalSignature: digitalSignature,
                keyCertSign: keyCertSign,
                includeEku: includeEku && !ca,
                names: subjectAltNames,
                permittedDns: permittedDns,
                excludedDns: excludedDns,
                permittedEmail: permittedEmail,
                excludedEmail: excludedEmail,
                permittedUri: permittedUri,
                excludedUri: excludedUri,
                permittedDirectory: permittedDirectory,
                excludedDirectory: excludedDirectory,
                permitOtherName: permitOtherName,
                mustStaple: mustStaple,
              ),
            ))
            .take(),
      );
    }
    final tbs = (DerWriter()..sequence(tbsBody.take())).take();
    final signature = sign(tbs);
    if (signature.isEmpty) {
      throw ArgumentError.value(signature, 'sign', 'empty signature');
    }
    return (DerWriter()..sequence(
          (DerWriter()
                ..raw(tbs)
                ..raw(algorithmId)
                ..bitString(signature))
              .take(),
        ))
        .take();
  }

  /// DER `SEQUENCE { INTEGER r, INTEGER s }` from a raw `r || s`.
  static Uint8List encodeEcdsaSignature(Uint8List raw) {
    if (raw.length != 64 && raw.length != 96) {
      throw ArgumentError.value(raw.length, 'raw', 'expected 64 or 96 bytes');
    }
    final half = raw.length ~/ 2;
    final body = DerWriter()
      ..integerUnsigned(_trim(raw, 0, half))
      ..integerUnsigned(_trim(raw, half, raw.length));
    return (DerWriter()..sequence(body.take())).take();
  }
}

const _mlDsa44 = [2, 16, 840, 1, 101, 3, 4, 3, 17];
const _mlDsa65 = [2, 16, 840, 1, 101, 3, 4, 3, 18];
const _mlDsa87 = [2, 16, 840, 1, 101, 3, 4, 3, 19];
const _ecdsa256 = [1, 2, 840, 10045, 4, 3, 2];
const _ecdsa384 = [1, 2, 840, 10045, 4, 3, 3];
const _ecKey = [1, 2, 840, 10045, 2, 1];
const _p256 = [1, 2, 840, 10045, 3, 1, 7];
const _p384 = [1, 3, 132, 0, 34];
const _ed25519 = [1, 3, 101, 112];
const _rsaEncryption = [1, 2, 840, 113549, 1, 1, 1];
const _pkcs1Sha256 = [1, 2, 840, 113549, 1, 1, 11];
const _pkcs1Sha384 = [1, 2, 840, 113549, 1, 1, 12];
const _pkcs1Sha512 = [1, 2, 840, 113549, 1, 1, 13];
const _rsaPss = [1, 2, 840, 113549, 1, 1, 10];
const _mgf1 = [1, 2, 840, 113549, 1, 1, 8];
const _sha256 = [2, 16, 840, 1, 101, 3, 4, 2, 1];
const _sha384 = [2, 16, 840, 1, 101, 3, 4, 2, 2];
const _sha512 = [2, 16, 840, 1, 101, 3, 4, 2, 3];
const _cn = [2, 5, 4, 3];
const _keyUsage = [2, 5, 29, 15];
const _basic = [2, 5, 29, 19];
const _san = [2, 5, 29, 17];
const _eku = [2, 5, 29, 37];
const _ski = [2, 5, 29, 14];
const _aki = [2, 5, 29, 35];
const _names = [2, 5, 29, 30];
const _tlsFeature = [1, 3, 6, 1, 5, 5, 7, 1, 24];
const _serverAuth = [1, 3, 6, 1, 5, 5, 7, 3, 1];

final class _Stop implements Exception {
  _Stop(this.failure);
  final PqX509Failure failure;
}

PqX509Failure _map(DerFailure failure) => switch (failure) {
  DerFailure.truncated => PqX509Failure.truncated,
  DerFailure.notDer => PqX509Failure.notDer,
  DerFailure.depth => PqX509Failure.depth,
  DerFailure.tooLarge => PqX509Failure.tooLarge,
};

Never _die(PqX509Failure failure) => throw _Stop(failure);

DerSlice _need(DerWalk walk) {
  if (!walk.ok) _die(_map(walk.failure!));
  return walk.slice!;
}

PqX509Parsed _parse(Uint8List der) {
  if (der.isEmpty) _die(PqX509Failure.truncated);
  final reader = DerReader(der);
  final certificate = _need(reader.tag(0x30));
  if (!reader.finished) _die(PqX509Failure.notDer);
  final body = reader.nested(certificate);
  final tbs = _need(body.tag(0x30));
  final signatureAlgorithm = _need(body.tag(0x30));
  final signatureBits = _need(body.tag(0x03));
  if (!body.finished) _die(PqX509Failure.notDer);
  final outer = _algorithm(reader.nested(signatureAlgorithm));
  final built = _tbs(reader.nested(tbs), tbs.whole());
  if (built.algorithm != outer.algorithm ||
      built.pssSaltLength != outer.pssSalt) {
    _die(PqX509Failure.notDer);
  }
  return PqX509Parsed.ok(
    PqX509Certificate(
      der: Uint8List.fromList(der),
      tbs: built.tbs,
      algorithm: outer.algorithm,
      signature: _signatureBits(signatureBits, outer.algorithm),
      issuerDer: built.issuerDer,
      subjectDer: built.subjectDer,
      serial: built.serial,
      notBefore: built.notBefore,
      notAfter: built.notAfter,
      publicKey: built.publicKey,
      version: built.version,
      extensions: built.extensions,
      subjectAltNames: built.subjectAltNames,
      ca: built.ca,
      pathLen: built.pathLen,
      keyUsageBits: built.keyUsageBits,
      extKeyUsage: built.extKeyUsage,
      issuerUniqueId: built.issuerUniqueId,
      subjectUniqueId: built.subjectUniqueId,
      mustStaple: built.mustStaple,
      pssSaltLength: outer.pssSalt,
    ),
  );
}

final class _Built {
  _Built(this.certificate);
  final PqX509Certificate certificate;
  Uint8List get tbs => certificate.tbs;
  PqX509Algorithm get algorithm => certificate.algorithm;
  Uint8List get issuerDer => certificate.issuerDer;
  Uint8List get subjectDer => certificate.subjectDer;
  Uint8List get serial => certificate.serial;
  DateTime get notBefore => certificate.notBefore;
  DateTime get notAfter => certificate.notAfter;
  PqX509PublicKey get publicKey => certificate.publicKey;
  int get version => certificate.version;
  List<PqX509Extension> get extensions => certificate.extensions;
  List<PqX509GeneralName> get subjectAltNames => certificate.subjectAltNames;
  bool? get ca => certificate.ca;
  int? get pathLen => certificate.pathLen;
  int? get keyUsageBits => certificate.keyUsageBits;
  List<List<int>> get extKeyUsage => certificate.extKeyUsage;
  Uint8List? get issuerUniqueId => certificate.issuerUniqueId;
  Uint8List? get subjectUniqueId => certificate.subjectUniqueId;
  bool get mustStaple => certificate.mustStaple;
  int? get pssSaltLength => certificate.pssSaltLength;
}

_Built _tbs(DerReader reader, Uint8List tbs) {
  var version = 1;
  if (reader.offset < reader.end && reader.bytes[reader.offset] == 0xa0) {
    final explicit = _need(reader.tag(0xa0));
    final versionReader = reader.nested(explicit);
    final number = _need(versionReader.tag(0x02)).copy();
    if (!versionReader.finished || number.length != 1) {
      _die(PqX509Failure.notDer);
    }
    if (number[0] != 2) _die(PqX509Failure.unsupportedVersion);
    version = 3;
  }
  final serial = unsignedInteger(_need(reader.tag(0x02)).copy(), maxBytes: 20);
  if (serial == null) _die(PqX509Failure.notDer);
  final sig = _algorithm(reader.nested(_need(reader.tag(0x30))));
  final issuer = _need(reader.tag(0x30));
  if (issuer.whole().length > PqX509.maxNameBytes) _die(PqX509Failure.badName);
  final validity = reader.nested(_need(reader.tag(0x30)));
  final notBefore = _time(_need(validity.tag(_timeTag(validity))));
  final notAfter = _time(_need(validity.tag(_timeTag(validity))));
  if (!validity.finished) _die(PqX509Failure.notDer);
  if (notBefore.isAfter(notAfter)) _die(PqX509Failure.badTime);
  final subject = _need(reader.tag(0x30));
  if (subject.whole().length > PqX509.maxNameBytes) _die(PqX509Failure.badName);
  final publicKey = _publicKey(reader.nested(_need(reader.tag(0x30))), sig);
  Uint8List? issuerUniqueId;
  Uint8List? subjectUniqueId;
  if (reader.offset < reader.end && reader.bytes[reader.offset] == 0x81) {
    issuerUniqueId = _uniqueId(reader, 0x81);
  }
  if (reader.offset < reader.end && reader.bytes[reader.offset] == 0x82) {
    subjectUniqueId = _uniqueId(reader, 0x82);
  }
  if (reader.offset < reader.end &&
      (reader.bytes[reader.offset] == 0xa1 ||
          reader.bytes[reader.offset] == 0xa2)) {
    _die(PqX509Failure.notDer);
  }
  final extensions = <PqX509Extension>[];
  final names = <PqX509GeneralName>[];
  bool? ca;
  int? pathLen;
  int? keyUsage;
  final eku = <List<int>>[];
  var mustStaple = false;
  if (reader.offset < reader.end && reader.bytes[reader.offset] == 0xa3) {
    if (version != 3) _die(PqX509Failure.notDer);
    final explicit = reader.nested(_need(reader.tag(0xa3)));
    final list = explicit.nested(_need(explicit.tag(0x30)));
    if (!explicit.finished) _die(PqX509Failure.notDer);
    final seen = <String>{};
    while (!list.finished) {
      final extension = _extension(list.nested(_need(list.tag(0x30))));
      final key = extension.oid.join('.');
      if (!seen.add(key)) _die(PqX509Failure.notDer);
      extensions.add(extension);
      if (_arcs(extension.oid, _basic)) {
        final decoded = _basicConstraints(extension.value);
        ca = decoded.$1;
        pathLen = decoded.$2;
      } else if (_arcs(extension.oid, _keyUsage)) {
        keyUsage = _keyUsageBits(extension.value);
      } else if (_arcs(extension.oid, _eku)) {
        eku.addAll(_ekuOids(extension.value));
      } else if (_arcs(extension.oid, _san)) {
        names.addAll(_parseSan(extension.value));
      } else if (_arcs(extension.oid, _tlsFeature)) {
        mustStaple = _mustStaple(extension);
      }
    }
  }
  if (!reader.finished) _die(PqX509Failure.notDer);
  return _Built(
    PqX509Certificate(
      der: Uint8List(0),
      tbs: tbs,
      algorithm: sig.algorithm,
      signature: Uint8List(0),
      issuerDer: issuer.whole(),
      subjectDer: subject.whole(),
      serial: serial,
      notBefore: notBefore,
      notAfter: notAfter,
      publicKey: publicKey,
      version: version,
      extensions: extensions,
      subjectAltNames: names,
      ca: ca,
      pathLen: pathLen,
      keyUsageBits: keyUsage,
      extKeyUsage: eku,
      issuerUniqueId: issuerUniqueId,
      subjectUniqueId: subjectUniqueId,
      mustStaple: mustStaple,
      pssSaltLength: sig.pssSalt,
    ),
  );
}

Uint8List _uniqueId(DerReader reader, int tag) {
  final bits = _need(reader.tag(tag));
  if (bits.length < 1 || bits.bytes[bits.start] > 7) _die(PqX509Failure.notDer);
  return bits.copy();
}

/// `id-pe-tlsfeature`. An unknown feature inside a critical extension fails.
bool _mustStaple(PqX509Extension extension) {
  final reader = DerReader(extension.value);
  final body = reader.nested(_need(reader.tag(0x30)));
  if (!reader.finished || body.finished) _die(PqX509Failure.notDer);
  var staple = false;
  while (!body.finished) {
    final number = unsignedInteger(_need(body.tag(0x02)).copy(), maxBytes: 2);
    if (number == null) _die(PqX509Failure.notDer);
    final value = _int(number);
    if (value == 5) {
      staple = true;
    } else if (extension.critical) {
      _die(PqX509Failure.badConstraint);
    }
  }
  return staple;
}

int _timeTag(DerReader reader) {
  if (reader.offset >= reader.end) _die(PqX509Failure.truncated);
  final tag = reader.bytes[reader.offset];
  if (tag != 0x17 && tag != 0x18) _die(PqX509Failure.badTime);
  return tag;
}

DateTime _time(DerSlice slice) {
  final text = String.fromCharCodes(slice.copy());
  final match = RegExp(
    r'^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$',
  ).firstMatch(text);
  if (match == null) _die(PqX509Failure.badTime);
  var year = int.parse(match.group(1)!);
  if (match.group(1)!.length == 2) year += year >= 50 ? 1900 : 2000;
  final month = int.parse(match.group(2)!);
  final day = int.parse(match.group(3)!);
  final hour = int.parse(match.group(4)!);
  final minute = int.parse(match.group(5)!);
  final second = int.parse(match.group(6)!);
  if (month < 1 ||
      month > 12 ||
      day < 1 ||
      hour > 23 ||
      minute > 59 ||
      second > 59) {
    _die(PqX509Failure.badTime);
  }
  final time = DateTime.utc(year, month, day, hour, minute, second);
  if (time.year != year || time.month != month || time.day != day) {
    _die(PqX509Failure.badTime);
  }
  return time;
}

_SigId _algorithm(DerReader reader) {
  final oid = _need(reader.tag(0x06)).copy();
  if (_oidIs(oid, _rsaPss)) {
    if (reader.finished) _die(PqX509Failure.unsupportedAlgorithm);
    final parsed = _pssParameters(reader.nested(_need(reader.tag(0x30))));
    if (!reader.finished) _die(PqX509Failure.notDer);
    return parsed;
  }
  final algorithm = _algorithmOid(oid);
  if (algorithm == null) _die(PqX509Failure.unsupportedAlgorithm);
  if (reader.finished) {
    if (_isPkcs1(algorithm)) _die(PqX509Failure.notDer);
    return _SigId(algorithm);
  }
  if (!_isPkcs1(algorithm)) _die(PqX509Failure.notDer);
  final nullValue = _need(reader.tag(0x05));
  if (nullValue.length != 0 || !reader.finished) _die(PqX509Failure.notDer);
  return _SigId(algorithm);
}

/// RFC 4055. An omitted salt length is 20. An omitted hash is SHA-1, which
/// this library does not accept.
_SigId _pssParameters(DerReader reader) {
  if (reader.finished || reader.bytes[reader.offset] != 0xa0) {
    _die(PqX509Failure.unsupportedAlgorithm);
  }
  final hashId = reader.nested(_need(reader.tag(0xa0)));
  final hash = _hashKind(hashId);
  if (!hashId.finished || hash == null) {
    _die(PqX509Failure.unsupportedAlgorithm);
  }
  final algorithm = switch (hash) {
    256 => PqX509Algorithm.rsaPssSha256,
    384 => PqX509Algorithm.rsaPssSha384,
    _ => PqX509Algorithm.rsaPssSha512,
  };
  if (reader.offset >= reader.end || reader.bytes[reader.offset] != 0xa1) {
    _die(PqX509Failure.unsupportedAlgorithm);
  }
  final mgf = reader.nested(_need(reader.tag(0xa1)));
  final mgfBody = mgf.nested(_need(mgf.tag(0x30)));
  if (!mgf.finished || !_oidIs(_need(mgfBody.tag(0x06)).copy(), _mgf1)) {
    _die(PqX509Failure.unsupportedAlgorithm);
  }
  if (_hashKind(mgfBody) != hash || !mgfBody.finished) {
    _die(PqX509Failure.unsupportedAlgorithm);
  }
  var salt = 20;
  if (reader.offset < reader.end && reader.bytes[reader.offset] == 0xa2) {
    final saltWrap = reader.nested(_need(reader.tag(0xa2)));
    final saltValue = unsignedInteger(
      _need(saltWrap.tag(0x02)).copy(),
      maxBytes: 2,
    );
    if (!saltWrap.finished || saltValue == null) {
      _die(PqX509Failure.unsupportedAlgorithm);
    }
    salt = _int(saltValue);
    if (salt > 512) _die(PqX509Failure.unsupportedAlgorithm);
  }
  if (!reader.finished) {
    if (reader.bytes[reader.offset] != 0xa3) _die(PqX509Failure.notDer);
    final trailer = reader.nested(_need(reader.tag(0xa3)));
    final trailerValue = unsignedInteger(
      _need(trailer.tag(0x02)).copy(),
      maxBytes: 1,
    );
    if (!trailer.finished ||
        trailerValue == null ||
        trailerValue.length != 1 ||
        trailerValue[0] != 1) {
      _die(PqX509Failure.unsupportedAlgorithm);
    }
  }
  if (!reader.finished) _die(PqX509Failure.notDer);
  return _SigId(algorithm, salt);
}

int? _hashKind(DerReader reader) {
  final body = reader.nested(_need(reader.tag(0x30)));
  final oid = _need(body.tag(0x06)).copy();
  int? kind;
  if (_oidIs(oid, _sha256)) kind = 256;
  if (_oidIs(oid, _sha384)) kind = 384;
  if (_oidIs(oid, _sha512)) kind = 512;
  if (!body.finished) {
    final nullValue = _need(body.tag(0x05));
    if (nullValue.length != 0 || !body.finished) _die(PqX509Failure.notDer);
  }
  if (!reader.finished) _die(PqX509Failure.notDer);
  return kind;
}

PqX509PublicKey _publicKey(DerReader reader, _SigId signature) {
  final algorithm = signature.algorithm;
  final algorithmId = reader.nested(_need(reader.tag(0x30)));
  final oid = _need(algorithmId.tag(0x06)).copy();
  final bits = _need(reader.tag(0x03));
  if (!reader.finished) _die(PqX509Failure.notDer);
  if (bits.length < 1 || bits.bytes[bits.start] != 0) {
    _die(PqX509Failure.notDer);
  }
  final key = Uint8List.sublistView(bits.bytes, bits.start + 1, bits.end);
  switch (algorithm) {
    case PqX509Algorithm.mlDsa44:
    case PqX509Algorithm.mlDsa65:
    case PqX509Algorithm.mlDsa87:
      if (!algorithmId.finished || !_oidIs(oid, _sigOid(algorithm))) {
        _die(PqX509Failure.unsupportedAlgorithm);
      }
      final expected = _mlDsa(algorithm).publicKeyBytes;
      if (key.length != expected) _die(PqX509Failure.unsupportedAlgorithm);
      return PqX509MlDsaKey(algorithm, Uint8List.fromList(key));
    case PqX509Algorithm.ecdsaP256Sha256:
    case PqX509Algorithm.ecdsaP384Sha384:
      if (!_oidIs(oid, _ecKey)) _die(PqX509Failure.unsupportedAlgorithm);
      final curve = _need(algorithmId.tag(0x06)).copy();
      final p256 = algorithm == PqX509Algorithm.ecdsaP256Sha256;
      if (!_oidIs(curve, p256 ? _p256 : _p384) || !algorithmId.finished) {
        _die(PqX509Failure.unsupportedAlgorithm);
      }
      final normalized = p256
          ? PqEcdsaP256.normalizePoint(Uint8List.fromList(key))
          : PqEcdsaP384.normalizePoint(Uint8List.fromList(key));
      if (normalized == null) _die(PqX509Failure.unsupportedAlgorithm);
      return p256
          ? PqX509EcdsaP256Key(normalized)
          : PqX509EcdsaP384Key(normalized);
    case PqX509Algorithm.ed25519:
      if (!algorithmId.finished || !_oidIs(oid, _ed25519)) {
        _die(PqX509Failure.unsupportedAlgorithm);
      }
      if (key.length != 32) _die(PqX509Failure.unsupportedAlgorithm);
      return PqX509Ed25519Key(Uint8List.fromList(key));
    case PqX509Algorithm.rsaPkcs1Sha256:
    case PqX509Algorithm.rsaPkcs1Sha384:
    case PqX509Algorithm.rsaPkcs1Sha512:
    case PqX509Algorithm.rsaPssSha256:
    case PqX509Algorithm.rsaPssSha384:
    case PqX509Algorithm.rsaPssSha512:
      final pssKey = _oidIs(oid, _rsaPss);
      if (!_oidIs(oid, _rsaEncryption) && !pssKey) {
        _die(PqX509Failure.unsupportedAlgorithm);
      }
      if (pssKey) {
        if (!_isPss(algorithm)) _die(PqX509Failure.unsupportedAlgorithm);
        if (algorithmId.finished ||
            algorithmId.bytes[algorithmId.offset] == 0x05) {
          _die(PqX509Failure.unsupportedAlgorithm);
        }
        final params = _pssParameters(
          algorithmId.nested(_need(algorithmId.tag(0x30))),
        );
        if (!algorithmId.finished ||
            params.algorithm != algorithm ||
            params.pssSalt != signature.pssSalt) {
          _die(PqX509Failure.unsupportedAlgorithm);
        }
      } else {
        final nullValue = _need(algorithmId.tag(0x05));
        if (nullValue.length != 0 || !algorithmId.finished) {
          _die(PqX509Failure.notDer);
        }
      }
      final rsa = DerReader(Uint8List.fromList(key));
      final body = rsa.nested(_need(rsa.tag(0x30)));
      if (!rsa.finished) _die(PqX509Failure.notDer);
      final modulus = unsignedInteger(
        _need(body.tag(0x02)).copy(),
        maxBytes: 513,
      );
      final exponent = unsignedInteger(
        _need(body.tag(0x02)).copy(),
        maxBytes: 4,
      );
      if (!body.finished || modulus == null || exponent == null) {
        _die(PqX509Failure.notDer);
      }
      final bits = (modulus.length - 1) * 8 + _topBits(modulus[0]);
      if (bits != 2048 && bits != 3072 && bits != 4096) {
        _die(PqX509Failure.unsupportedAlgorithm);
      }
      if (exponent.last.isEven || _int(exponent) < 3) {
        _die(PqX509Failure.unsupportedAlgorithm);
      }
      return PqX509RsaKey(modulus, exponent);
  }
}

Uint8List _signatureBits(DerSlice bits, PqX509Algorithm algorithm) {
  if (bits.length < 1 || bits.bytes[bits.start] != 0) {
    _die(PqX509Failure.notDer);
  }
  final payload = Uint8List.fromList(
    Uint8List.sublistView(bits.bytes, bits.start + 1, bits.end),
  );
  switch (algorithm) {
    case PqX509Algorithm.mlDsa44:
    case PqX509Algorithm.mlDsa65:
    case PqX509Algorithm.mlDsa87:
      if (payload.length != _mlDsa(algorithm).signatureBytes) {
        _die(PqX509Failure.notDer);
      }
      return payload;
    case PqX509Algorithm.ed25519:
      if (payload.length != 64) _die(PqX509Failure.notDer);
      return payload;
    case PqX509Algorithm.ecdsaP256Sha256:
    case PqX509Algorithm.ecdsaP384Sha384:
      return _ecdsaRaw(
        payload,
        algorithm == PqX509Algorithm.ecdsaP256Sha256 ? 32 : 48,
      );
    case PqX509Algorithm.rsaPkcs1Sha256:
    case PqX509Algorithm.rsaPkcs1Sha384:
    case PqX509Algorithm.rsaPkcs1Sha512:
    case PqX509Algorithm.rsaPssSha256:
    case PqX509Algorithm.rsaPssSha384:
    case PqX509Algorithm.rsaPssSha512:
      if (payload.isEmpty) _die(PqX509Failure.notDer);
      return payload;
  }
}

Uint8List _ecdsaRaw(Uint8List der, int width) {
  final reader = DerReader(der);
  final body = reader.nested(_need(reader.tag(0x30)));
  if (!reader.finished) _die(PqX509Failure.notDer);
  final r = unsignedInteger(_need(body.tag(0x02)).copy(), maxBytes: width + 1);
  final s = unsignedInteger(_need(body.tag(0x02)).copy(), maxBytes: width + 1);
  if (!body.finished || r == null || s == null) _die(PqX509Failure.notDer);
  return Uint8List(width * 2)
    ..setRange(width - r.length, width, r)
    ..setRange(width * 2 - s.length, width * 2, s);
}

bool _check(PqX509Certificate certificate, PqX509PublicKey key) {
  final message = certificate.tbs;
  final signature = certificate.signature;
  switch (certificate.algorithm) {
    case PqX509Algorithm.mlDsa44:
    case PqX509Algorithm.mlDsa65:
    case PqX509Algorithm.mlDsa87:
      if (key is! PqX509MlDsaKey || key.algorithm != certificate.algorithm) {
        return false;
      }
      return PqSignaturePrimitives.verify(
        _mlDsa(certificate.algorithm),
        key.raw,
        message,
        signature,
      );
    case PqX509Algorithm.ecdsaP256Sha256:
      if (key is! PqX509EcdsaP256Key) return false;
      return PqEcdsaP256.verify(
        publicKey: key.uncompressed,
        message: message,
        signature: signature,
      );
    case PqX509Algorithm.ecdsaP384Sha384:
      if (key is! PqX509EcdsaP384Key) return false;
      return PqEcdsaP384.verify(
        publicKey: key.uncompressed,
        message: message,
        signature: signature,
      );
    case PqX509Algorithm.ed25519:
      if (key is! PqX509Ed25519Key) return false;
      return PqEd25519.verify(
        publicKey: key.raw,
        message: message,
        signature: signature,
      );
    case PqX509Algorithm.rsaPkcs1Sha256:
    case PqX509Algorithm.rsaPkcs1Sha384:
    case PqX509Algorithm.rsaPkcs1Sha512:
      if (key is! PqX509RsaKey) return false;
      return PqRsa.verifyPkcs1(
        modulus: key.modulus,
        exponent: key.exponent,
        message: message,
        signature: signature,
        hash: _rsaHash(certificate.algorithm),
      );
    case PqX509Algorithm.rsaPssSha256:
    case PqX509Algorithm.rsaPssSha384:
    case PqX509Algorithm.rsaPssSha512:
      if (key is! PqX509RsaKey) return false;
      return PqRsa.verifyPss(
        modulus: key.modulus,
        exponent: key.exponent,
        message: message,
        signature: signature,
        hash: _rsaHash(certificate.algorithm),
        saltLength: certificate.pssSaltLength,
      );
  }
}

PqX509Path _path(
  List<PqX509Certificate> certs,
  List<PqX509Certificate> anchors,
  DateTime now,
  bool ocspResponsePresent,
  List<List<int>> acceptedCriticalOids,
) {
  PqX509Certificate? anchor;
  for (final candidate in anchors) {
    if (_same(candidate.subjectDer, certs.last.issuerDer)) anchor = candidate;
  }
  if (anchor == null) return const PqX509Path.fail(PqX509Failure.untrusted);
  for (var i = 0; i < certs.length - 1; i++) {
    if (!_same(certs[i].issuerDer, certs[i + 1].subjectDer)) {
      return const PqX509Path.fail(PqX509Failure.untrusted);
    }
  }
  final selfSignedLeaf =
      certs.length == 1 &&
      _same(anchor.subjectDer, certs.first.subjectDer) &&
      _same(anchor.issuerDer, certs.first.issuerDer);
  for (var i = 0; i < certs.length; i++) {
    final issuerKey = i == certs.length - 1
        ? anchor.publicKey
        : certs[i + 1].publicKey;
    if (!_check(certs[i], issuerKey)) {
      return const PqX509Path.fail(PqX509Failure.badSignature);
    }
  }
  final path = selfSignedLeaf
      ? certs
      : <PqX509Certificate>[anchor, ...certs.reversed];
  for (final certificate in path) {
    if (now.isBefore(certificate.notBefore)) {
      return const PqX509Path.fail(PqX509Failure.notYetValid);
    }
    if (now.isAfter(certificate.notAfter)) {
      return const PqX509Path.fail(PqX509Failure.expired);
    }
    final critical = _critical(certificate, acceptedCriticalOids);
    if (critical != null) return PqX509Path.fail(critical);
    if (certificate.mustStaple && !ocspResponsePresent) {
      return const PqX509Path.fail(PqX509Failure.mustStaple);
    }
  }
  for (var i = 0; i < path.length - 1; i++) {
    final certificate = path[i];
    if (certificate.ca != true) {
      return const PqX509Path.fail(PqX509Failure.badConstraint);
    }
    final usage = certificate.keyUsageBits;
    if (usage != null && (usage & (1 << 5)) == 0) {
      return const PqX509Path.fail(PqX509Failure.badConstraint);
    }
    if (certificate.pathLen != null &&
        path.length - 2 - i > certificate.pathLen!) {
      return const PqX509Path.fail(PqX509Failure.badConstraint);
    }
  }
  final constraints = _constraints(path);
  if (constraints != null) return PqX509Path.fail(constraints);
  return PqX509Path.trusted(certs.first);
}

PqX509Failure? _critical(
  PqX509Certificate certificate,
  List<List<int>> accepted,
) {
  for (final extension in certificate.extensions) {
    if (!extension.critical) continue;
    if (_arcs(extension.oid, _keyUsage) ||
        _arcs(extension.oid, _basic) ||
        _arcs(extension.oid, _eku) ||
        _arcs(extension.oid, _san) ||
        _arcs(extension.oid, _ski) ||
        _arcs(extension.oid, _aki) ||
        _arcs(extension.oid, _names) ||
        _arcs(extension.oid, _tlsFeature)) {
      continue;
    }
    var known = false;
    for (final oid in accepted) {
      if (_arcs(extension.oid, oid)) known = true;
    }
    if (!known) return PqX509Failure.badConstraint;
  }
  return null;
}

PqX509Failure? _constraints(List<PqX509Certificate> path) {
  final permitted = <_Subtree>[];
  final excluded = <_Subtree>[];
  for (var i = 0; i < path.length; i++) {
    final failed = _constrained(path[i], permitted, excluded);
    if (failed != null) return failed;
    for (final extension in path[i].extensions) {
      if (!_arcs(extension.oid, _names)) continue;
      final decoded = _nameConstraints(extension.value);
      if (decoded == null) return PqX509Failure.badConstraint;
      permitted.add(decoded.$1);
      excluded.add(decoded.$2);
    }
  }
  return null;
}

PqX509Failure? _constrained(
  PqX509Certificate certificate,
  List<_Subtree> permitted,
  List<_Subtree> excluded,
) {
  final names = <PqX509GeneralName>[...certificate.subjectAltNames];
  final directoryConstrained =
      permitted.any((set) => set.directory.isNotEmpty) ||
      excluded.any((set) => set.directory.isNotEmpty);
  final subject = directoryConstrained
      ? _rdns(certificate.subjectDer)
      : const <List<(Uint8List, String)>>[];
  if (directoryConstrained && subject == null) {
    return PqX509Failure.badConstraint;
  }
  if (subject != null && subject.isNotEmpty) {
    names.add(PqX509DirectoryName(certificate.subjectDer));
  }
  for (final name in names) {
    switch (name) {
      case PqX509DnsName():
        if (_outside(permitted, excluded, (set, excludedSet) {
          return _form(
            set.dns,
            excludedSet.dns,
            (base) => _dnsWithin(name.ascii, base),
          );
        })) {
          return PqX509Failure.badConstraint;
        }
      case PqX509EmailName():
        if (_outside(permitted, excluded, (set, excludedSet) {
          return _form(
            set.email,
            excludedSet.email,
            (base) => _emailWithin(name.mailbox, base),
          );
        })) {
          return PqX509Failure.badConstraint;
        }
      case PqX509UriName():
        if (_outside(permitted, excluded, (set, excludedSet) {
          return _form(
            set.uri,
            excludedSet.uri,
            (base) => _uriWithin(name.uri, base),
          );
        })) {
          return PqX509Failure.badConstraint;
        }
      case PqX509DirectoryName():
        final rdns = identical(name.name, certificate.subjectDer)
            ? subject
            : _rdns(name.name);
        if (rdns == null) return PqX509Failure.badConstraint;
        if (_outside(permitted, excluded, (set, excludedSet) {
          if (excludedSet.directory.any((base) {
            final constraint = _rdns(base);
            return constraint != null && _dnWithin(rdns, constraint);
          })) {
            return true;
          }
          for (final setDir in set.directory) {
            final constraint = _rdns(setDir);
            if (constraint == null) return true;
            if (constraint.isEmpty) continue;
            if (!_dnWithin(rdns, constraint)) return true;
          }
          return false;
        })) {
          return PqX509Failure.badConstraint;
        }
      case PqX509Ip4Name():
      case PqX509Ip6Name():
        final octets = name is PqX509Ip4Name
            ? name.octets
            : (name as PqX509Ip6Name).octets;
        if (octets.length != 4 && octets.length != 16) continue;
        if (_outside(permitted, excluded, (set, excludedSet) {
          return _form(
            set.ip.where((base) => base.length == octets.length * 2).toList(),
            excludedSet.ip,
            (base) => _ipWithin(octets, base),
          );
        })) {
          return PqX509Failure.badConstraint;
        }
      case PqX509OtherName():
        break;
    }
  }
  return null;
}

bool _outside(
  List<_Subtree> permitted,
  List<_Subtree> excluded,
  bool Function(_Subtree set, _Subtree excludedSet) one,
) {
  for (var i = 0; i < permitted.length; i++) {
    if (one(permitted[i], excluded[i])) return true;
  }
  return false;
}

bool _form<T>(
  List<T> permitted,
  List<T> excluded,
  bool Function(T base) within,
) {
  for (final base in excluded) {
    if (within(base)) return true;
  }
  if (permitted.isEmpty) return false;
  for (final base in permitted) {
    if (within(base)) return false;
  }
  return true;
}

(_Subtree, _Subtree)? _nameConstraints(Uint8List value) {
  final reader = DerReader(value);
  DerSlice? bodySlice;
  try {
    bodySlice = _need(reader.tag(0x30));
    if (!reader.finished) return null;
  } on _Stop {
    return null;
  }
  final body = DerReader(value, offset: bodySlice.start, end: bodySlice.end);
  final permitted = _Subtree();
  final excluded = _Subtree();
  while (!body.finished) {
    final tag = body.bytes[body.offset];
    if (tag != 0xa0 && tag != 0xa1) return null;
    final into = tag == 0xa0 ? permitted : excluded;
    final subtrees = body.nested(_need(body.tag(tag)));
    if (subtrees.finished) return null;
    while (!subtrees.finished) {
      final tree = subtrees.nested(_need(subtrees.tag(0x30)));
      final base = _generalName(tree);
      if (base == null || !tree.finished) return null;
      switch (base) {
        case PqX509DnsName():
          into.dns.add(base.ascii);
        case PqX509EmailName():
          into.email.add(base.mailbox);
        case PqX509UriName():
          into.uri.add(base.uri);
        case PqX509DirectoryName():
          into.directory.add(base.name);
        case PqX509Ip4Name():
        case PqX509Ip6Name():
          final octets = base is PqX509Ip4Name
              ? base.octets
              : (base as PqX509Ip6Name).octets;
          final constraint = _ipConstraint(octets);
          if (constraint == null) return null;
          into.ip.add(constraint);
        case PqX509OtherName():
          return null;
      }
    }
  }
  return (permitted, excluded);
}

final class _Subtree {
  final dns = <String>[];
  final email = <String>[];
  final uri = <String>[];
  final directory = <Uint8List>[];
  final ip = <Uint8List>[];
}

final class _SigId {
  _SigId(this.algorithm, [this.pssSalt]);

  final PqX509Algorithm algorithm;
  final int? pssSalt;
}

Uint8List? _ipConstraint(Uint8List octets) {
  if (octets.length == 8 || octets.length == 32) return octets;
  return null;
}

PqX509GeneralName? _generalName(DerReader reader) {
  if (reader.offset >= reader.end) return null;
  final tag = reader.bytes[reader.offset];
  const known = {0x81, 0x82, 0x86, 0x87, 0xa4};
  if (!known.contains(tag)) return null;
  final value = _need(reader.tag(tag)).copy();
  switch (tag) {
    case 0x81:
      if (!_ia5(value) || !String.fromCharCodes(value).contains('@')) {
        return null;
      }
      return PqX509EmailName(String.fromCharCodes(value));
    case 0x82:
      if (!_ia5(value)) return null;
      return PqX509DnsName(String.fromCharCodes(value).toLowerCase());
    case 0x86:
      if (!_ia5(value)) return null;
      return PqX509UriName(String.fromCharCodes(value));
    case 0xa4:
      if (value.isEmpty || value[0] != 0x30) return null;
      return PqX509DirectoryName(value);
    default:
      if (value.length == 4 || value.length == 8) return PqX509Ip4Name(value);
      if (value.length == 16 || value.length == 32) return PqX509Ip6Name(value);
      return null;
  }
}

bool _dnsWithin(String name, String base) {
  final left = name.toLowerCase();
  var right = base.toLowerCase();
  if (right.startsWith('.')) {
    right = right.substring(1);
    return left != right && left.endsWith('.$right');
  }
  return left == right || left.endsWith('.$right');
}

bool _emailWithin(String mailbox, String base) {
  final mail = mailbox.toLowerCase();
  final constraint = base.toLowerCase();
  final at = mail.lastIndexOf('@');
  if (at <= 0 || at == mail.length - 1) return false;
  final host = mail.substring(at + 1);
  if (constraint.startsWith('.')) {
    final domain = constraint.substring(1);
    return host != domain && host.endsWith('.$domain');
  }
  if (constraint.contains('@')) return mail == constraint;
  return host == constraint;
}

bool _uriWithin(String uri, String base) {
  final host = _uriHost(uri);
  if (host == null) return false;
  final constraint = base.toLowerCase();
  if (constraint.startsWith('.')) {
    final domain = constraint.substring(1);
    return host != domain && host.endsWith('.$domain');
  }
  return host == constraint;
}

String? _uriHost(String uri) {
  final scheme = uri.indexOf(':');
  if (scheme <= 0) return null;
  var rest = uri.substring(scheme + 1);
  if (!rest.startsWith('//')) return null;
  rest = rest.substring(2);
  final at = rest.indexOf('@');
  if (at >= 0) rest = rest.substring(at + 1);
  final slash = rest.indexOf('/');
  if (slash >= 0) rest = rest.substring(0, slash);
  if (rest.startsWith('[')) {
    final end = rest.indexOf(']');
    if (end < 0) return null;
    return rest.substring(1, end).toLowerCase();
  }
  final port = rest.lastIndexOf(':');
  if (port >= 0) rest = rest.substring(0, port);
  if (rest.isEmpty) return null;
  return rest.toLowerCase();
}

bool _ipWithin(Uint8List address, Uint8List constraint) {
  if (constraint.length != address.length * 2) return false;
  for (var i = 0; i < address.length; i++) {
    final mask = constraint[address.length + i];
    if ((address[i] & mask) != (constraint[i] & mask)) return false;
  }
  return true;
}

PqX509Extension _extension(DerReader reader) {
  final oid = _decodeOid(_need(reader.tag(0x06)).copy());
  if (oid == null) _die(PqX509Failure.notDer);
  var critical = false;
  if (reader.offset < reader.end && reader.bytes[reader.offset] == 0x01) {
    final boolean = _need(reader.tag(0x01)).copy();
    if (boolean.length != 1 || (boolean[0] != 0x00 && boolean[0] != 0xff)) {
      _die(PqX509Failure.notDer);
    }
    critical = boolean[0] == 0xff;
  }
  final value = _need(reader.tag(0x04)).copy();
  if (!reader.finished) _die(PqX509Failure.notDer);
  return PqX509Extension(oid, critical, value);
}

(bool, int?) _basicConstraints(Uint8List value) {
  final reader = DerReader(value);
  final body = reader.nested(_need(reader.tag(0x30)));
  if (!reader.finished) _die(PqX509Failure.notDer);
  if (body.finished) return (false, null);
  var ca = false;
  if (body.bytes[body.offset] == 0x01) {
    final boolean = _need(body.tag(0x01)).copy();
    if (boolean.length != 1 || (boolean[0] != 0x00 && boolean[0] != 0xff)) {
      _die(PqX509Failure.notDer);
    }
    ca = boolean[0] == 0xff;
  }
  int? pathLen;
  if (!body.finished) {
    final number = unsignedInteger(_need(body.tag(0x02)).copy(), maxBytes: 2);
    if (!body.finished || number == null) _die(PqX509Failure.notDer);
    pathLen = _int(number);
  }
  if (!ca && pathLen != null) _die(PqX509Failure.notDer);
  return (ca, pathLen);
}

int _keyUsageBits(Uint8List value) {
  final reader = DerReader(value);
  final bits = _need(reader.tag(0x03));
  if (!reader.finished || bits.length < 1) _die(PqX509Failure.notDer);
  final unused = bits.bytes[bits.start];
  if (unused > 7) _die(PqX509Failure.notDer);
  var usage = 0;
  var bit = 0;
  for (var i = bits.start + 1; i < bits.end; i++) {
    for (var shift = 7; shift >= 0; shift--) {
      if (i == bits.end - 1 && shift < unused) break;
      if ((bits.bytes[i] & (1 << shift)) != 0) usage |= 1 << bit;
      bit++;
      if (bit > 8) break;
    }
  }
  return usage;
}

List<List<int>> _ekuOids(Uint8List value) {
  final reader = DerReader(value);
  final body = reader.nested(_need(reader.tag(0x30)));
  if (!reader.finished) _die(PqX509Failure.notDer);
  final oids = <List<int>>[];
  while (!body.finished) {
    final oid = _decodeOid(_need(body.tag(0x06)).copy());
    if (oid == null) _die(PqX509Failure.notDer);
    oids.add(oid);
  }
  return oids;
}

List<PqX509GeneralName> _parseSan(Uint8List value) {
  final reader = DerReader(value);
  final body = reader.nested(_need(reader.tag(0x30)));
  if (!reader.finished) _die(PqX509Failure.notDer);
  final names = <PqX509GeneralName>[];
  while (!body.finished) {
    final tag = body.bytes[body.offset];
    const kept = {0x81, 0x82, 0x86, 0x87, 0xa4};
    if (!kept.contains(tag)) {
      _need(body.tag(tag));
      continue;
    }
    final name = _generalName(body);
    if (name == null) _die(PqX509Failure.badName);
    names.add(name);
  }
  return names;
}

Uint8List _algorithmDer(PqX509Algorithm algorithm, int? pssSaltLength) {
  final writer = DerWriter();
  if (_isPkcs1(algorithm)) {
    writer.sequence(
      (DerWriter()
            ..oid(_sigOid(algorithm))
            ..nullValue())
          .take(),
    );
  } else if (algorithm == PqX509Algorithm.rsaPssSha256 ||
      algorithm == PqX509Algorithm.rsaPssSha384 ||
      algorithm == PqX509Algorithm.rsaPssSha512) {
    writer.sequence(
      (DerWriter()
            ..oid(_rsaPss)
            ..sequence(_pssDer(algorithm, pssSaltLength)))
          .take(),
    );
  } else {
    writer.sequence((DerWriter()..oid(_sigOid(algorithm))).take());
  }
  return writer.take();
}

Uint8List _pssDer(PqX509Algorithm algorithm, int? saltLength) {
  final hash = _pssHash(algorithm);
  final salt =
      saltLength ??
      (hash == _sha256
          ? 32
          : hash == _sha384
          ? 48
          : 64);
  final hashId =
      (DerWriter()..sequence(
            (DerWriter()
                  ..oid(hash)
                  ..nullValue())
                .take(),
          ))
          .take();
  final mgf =
      (DerWriter()..sequence(
            (DerWriter()
                  ..oid(_mgf1)
                  ..raw(hashId))
                .take(),
          ))
          .take();
  return (DerWriter()
        ..tlv(0xa0, hashId)
        ..tlv(0xa1, mgf)
        ..tlv(0xa2, (DerWriter()..integerUnsigned(_u16(salt))).take()))
      .take();
}

Uint8List _spki(
  PqX509PublicKey key, {
  required PqX509Algorithm algorithm,
  required bool pssPublicKey,
  required int? pssSaltLength,
}) {
  final writer = DerWriter();
  switch (key) {
    case PqX509MlDsaKey():
      writer.sequence(
        (DerWriter()
              ..sequence((DerWriter()..oid(_sigOid(key.algorithm))).take())
              ..bitString(key.raw))
            .take(),
      );
    case PqX509EcdsaP256Key():
      writer.sequence(
        (DerWriter()
              ..sequence(
                (DerWriter()
                      ..oid(_ecKey)
                      ..oid(_p256))
                    .take(),
              )
              ..bitString(key.uncompressed))
            .take(),
      );
    case PqX509EcdsaP384Key():
      writer.sequence(
        (DerWriter()
              ..sequence(
                (DerWriter()
                      ..oid(_ecKey)
                      ..oid(_p384))
                    .take(),
              )
              ..bitString(key.uncompressed))
            .take(),
      );
    case PqX509Ed25519Key():
      writer.sequence(
        (DerWriter()
              ..sequence((DerWriter()..oid(_ed25519)).take())
              ..bitString(key.raw))
            .take(),
      );
    case PqX509RsaKey():
      if (pssPublicKey && !_isPss(algorithm)) {
        throw ArgumentError('a PSS public key requires a PSS signature');
      }
      final algorithmId = pssPublicKey
          ? (DerWriter()
                  ..oid(_rsaPss)
                  ..sequence(_pssDer(algorithm, pssSaltLength)))
                .take()
          : (DerWriter()
                  ..oid(_rsaEncryption)
                  ..nullValue())
                .take();
      writer.sequence(
        (DerWriter()
              ..sequence(algorithmId)
              ..bitString(
                (DerWriter()..sequence(
                      (DerWriter()
                            ..integerUnsigned(key.modulus)
                            ..integerUnsigned(key.exponent))
                          .take(),
                    ))
                    .take(),
              ))
            .take(),
      );
  }
  return writer.take();
}

Uint8List _extensions({
  required bool ca,
  required int? pathLen,
  required bool digitalSignature,
  required bool keyCertSign,
  required bool includeEku,
  required List<PqX509GeneralName> names,
  required List<String> permittedDns,
  required List<String> excludedDns,
  required List<String> permittedEmail,
  required List<String> excludedEmail,
  required List<String> permittedUri,
  required List<String> excludedUri,
  required List<PqX509Name> permittedDirectory,
  required List<PqX509Name> excludedDirectory,
  required bool permitOtherName,
  required bool mustStaple,
}) {
  final writer = DerWriter();
  writer.sequence(_extensionDer(_basic, true, _basicDer(ca, pathLen)));
  var mask = 0;
  if (digitalSignature) mask |= 1;
  if (keyCertSign) mask |= 1 << 5;
  if (mask != 0) {
    writer.sequence(_extensionDer(_keyUsage, true, _keyUsageDer(mask)));
  }
  if (includeEku) {
    writer.sequence(
      _extensionDer(
        _eku,
        false,
        (DerWriter()..sequence((DerWriter()..oid(_serverAuth)).take())).take(),
      ),
    );
  }
  if (names.isNotEmpty) {
    writer.sequence(_extensionDer(_san, false, _sanDer(names)));
  }
  if (permittedDns.isNotEmpty ||
      excludedDns.isNotEmpty ||
      permittedEmail.isNotEmpty ||
      excludedEmail.isNotEmpty ||
      permittedUri.isNotEmpty ||
      excludedUri.isNotEmpty ||
      permittedDirectory.isNotEmpty ||
      excludedDirectory.isNotEmpty ||
      permitOtherName) {
    writer.sequence(
      _extensionDer(
        _names,
        true,
        _nameConstraintsDer(
          permittedDns: permittedDns,
          excludedDns: excludedDns,
          permittedEmail: permittedEmail,
          excludedEmail: excludedEmail,
          permittedUri: permittedUri,
          excludedUri: excludedUri,
          permittedDirectory: permittedDirectory,
          excludedDirectory: excludedDirectory,
          permitOtherName: permitOtherName,
        ),
      ),
    );
  }
  if (mustStaple) {
    writer.sequence(
      _extensionDer(
        _tlsFeature,
        true,
        (DerWriter()..sequence(
              (DerWriter()..integerUnsigned(Uint8List.fromList([5]))).take(),
            ))
            .take(),
      ),
    );
  }
  return writer.take();
}

Uint8List _extensionDer(List<int> oid, bool critical, Uint8List value) {
  final writer = DerWriter()..oid(oid);
  if (critical) writer.tlv(0x01, const [0xff]);
  writer.tlv(0x04, value);
  return writer.take();
}

Uint8List _basicDer(bool ca, int? pathLen) {
  final writer = DerWriter();
  if (ca) writer.tlv(0x01, const [0xff]);
  if (pathLen != null) writer.integerUnsigned(Uint8List.fromList([pathLen]));
  return (DerWriter()..sequence(writer.take())).take();
}

Uint8List _keyUsageDer(int mask) {
  var last = 0;
  for (var bit = 0; bit <= 8; bit++) {
    if ((mask & (1 << bit)) != 0) last = bit;
  }
  var packed = 0;
  for (var bit = 0; bit <= last; bit++) {
    if ((mask & (1 << bit)) != 0) packed |= 0x80 >> bit;
  }
  return (DerWriter()
        ..bitString(Uint8List.fromList([packed]), unused: 7 - last))
      .take();
}

Uint8List _sanDer(List<PqX509GeneralName> names) {
  final writer = DerWriter();
  for (final name in names) {
    switch (name) {
      case PqX509DnsName():
        final bytes = Uint8List.fromList(name.ascii.codeUnits);
        if (!_ia5(bytes)) {
          throw ArgumentError.value(name.ascii, 'dns', 'not ASCII');
        }
        writer.tlv(0x82, bytes);
      case PqX509Ip4Name():
        if (name.octets.length != 4) {
          throw ArgumentError.value(name.octets.length, 'ip', 'expected 4');
        }
        writer.tlv(0x87, name.octets);
      case PqX509Ip6Name():
        if (name.octets.length != 16) {
          throw ArgumentError.value(name.octets.length, 'ip', 'expected 16');
        }
        writer.tlv(0x87, name.octets);
      case PqX509EmailName():
        final bytes = Uint8List.fromList(name.mailbox.codeUnits);
        if (!_ia5(bytes) || !name.mailbox.contains('@')) {
          throw ArgumentError.value(name.mailbox, 'email', 'not a mailbox');
        }
        writer.tlv(0x81, bytes);
      case PqX509UriName():
        final bytes = Uint8List.fromList(name.uri.codeUnits);
        if (!_ia5(bytes)) {
          throw ArgumentError.value(name.uri, 'uri', 'not ASCII');
        }
        writer.tlv(0x86, bytes);
      case PqX509DirectoryName():
        writer.tlv(0xa4, name.name);
      case PqX509OtherName():
        writer.tlv(0xa0, (DerWriter()..oid([1, 2, 3])).take());
    }
  }
  return (DerWriter()..sequence(writer.take())).take();
}

Uint8List _nameConstraintsDer({
  required List<String> permittedDns,
  required List<String> excludedDns,
  required List<String> permittedEmail,
  required List<String> excludedEmail,
  required List<String> permittedUri,
  required List<String> excludedUri,
  required List<PqX509Name> permittedDirectory,
  required List<PqX509Name> excludedDirectory,
  required bool permitOtherName,
}) {
  final permitted = _subtrees(
    dns: permittedDns,
    email: permittedEmail,
    uri: permittedUri,
    directory: permittedDirectory,
    otherName: permitOtherName,
  );
  final excluded = _subtrees(
    dns: excludedDns,
    email: excludedEmail,
    uri: excludedUri,
    directory: excludedDirectory,
    otherName: false,
  );
  final writer = DerWriter();
  if (permitted.isNotEmpty) writer.tlv(0xa0, permitted);
  if (excluded.isNotEmpty) writer.tlv(0xa1, excluded);
  return (DerWriter()..sequence(writer.take())).take();
}

Uint8List _subtrees({
  required List<String> dns,
  required List<String> email,
  required List<String> uri,
  required List<PqX509Name> directory,
  required bool otherName,
}) {
  final writer = DerWriter();
  for (final name in dns) {
    writer.sequence((DerWriter()..tlv(0x82, _ia5Name(name, 'dns'))).take());
  }
  for (final name in email) {
    writer.sequence((DerWriter()..tlv(0x81, _ia5Name(name, 'email'))).take());
  }
  for (final name in uri) {
    writer.sequence((DerWriter()..tlv(0x86, _ia5Name(name, 'uri'))).take());
  }
  for (final name in directory) {
    writer.sequence((DerWriter()..tlv(0xa4, name.der)).take());
  }
  if (otherName) {
    writer.sequence(
      (DerWriter()..tlv(0xa0, (DerWriter()..oid([1, 2, 3])).take())).take(),
    );
  }
  return writer.take();
}

Uint8List _ia5Name(String value, String label) {
  final bytes = Uint8List.fromList(value.codeUnits);
  if (!_ia5(bytes)) throw ArgumentError.value(value, label, 'not ASCII');
  return bytes;
}

Uint8List _validity(DateTime notBefore, DateTime notAfter) =>
    (DerWriter()
          ..raw(_timeDer(notBefore))
          ..raw(_timeDer(notAfter)))
        .take();

Uint8List _timeDer(DateTime time) {
  final year = time.year.toString().padLeft(4, '0');
  final body =
      '$year${_two(time.month)}${_two(time.day)}${_two(time.hour)}${_two(time.minute)}${_two(time.second)}Z';
  if (time.year >= 1950 && time.year <= 2049) {
    return (DerWriter()..tlv(0x17, body.substring(2).codeUnits)).take();
  }
  return (DerWriter()..tlv(0x18, body.codeUnits)).take();
}

String _two(int value) => value.toString().padLeft(2, '0');

Uint8List _trim(Uint8List raw, int start, int end) {
  var index = start;
  while (index < end - 1 && raw[index] == 0) {
    index++;
  }
  return Uint8List.sublistView(raw, index, end);
}

void _requireUtc(DateTime time, String name) {
  if (!time.isUtc) throw ArgumentError.value(time, name, 'must be UTC');
}

bool _isPrintable(Uint8List bytes) {
  const ok =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \'()+,-./:=?';
  for (final byte in bytes) {
    if (!ok.contains(String.fromCharCode(byte))) return false;
  }
  return true;
}

bool _ia5(Uint8List bytes) {
  if (bytes.isEmpty) return false;
  for (final byte in bytes) {
    if (byte < 0x01 || byte > 0x7f) return false;
  }
  return true;
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool _oidIs(Uint8List contents, List<int> arcs) => oidIs(contents, arcs);

bool _arcs(List<int> oid, List<int> expected) {
  if (oid.length != expected.length) return false;
  for (var i = 0; i < oid.length; i++) {
    if (oid[i] != expected[i]) return false;
  }
  return true;
}

List<int>? _decodeOid(Uint8List contents) {
  if (contents.isEmpty) return null;
  final arcs = <int>[];
  final first = contents[0];
  arcs.add(first ~/ 40);
  arcs.add(first % 40);
  var value = 0;
  var pending = false;
  for (var i = 1; i < contents.length; i++) {
    if (value > 0xffffff) return null;
    value = (value << 7) | (contents[i] & 0x7f);
    pending = true;
    if ((contents[i] & 0x80) == 0) {
      arcs.add(value);
      value = 0;
      pending = false;
    }
  }
  if (pending) return null;
  return arcs;
}

PqX509Algorithm? _algorithmOid(Uint8List contents) {
  if (_oidIs(contents, _mlDsa44)) return PqX509Algorithm.mlDsa44;
  if (_oidIs(contents, _mlDsa65)) return PqX509Algorithm.mlDsa65;
  if (_oidIs(contents, _mlDsa87)) return PqX509Algorithm.mlDsa87;
  if (_oidIs(contents, _ecdsa256)) return PqX509Algorithm.ecdsaP256Sha256;
  if (_oidIs(contents, _ecdsa384)) return PqX509Algorithm.ecdsaP384Sha384;
  if (_oidIs(contents, _ed25519)) return PqX509Algorithm.ed25519;
  if (_oidIs(contents, _pkcs1Sha256)) return PqX509Algorithm.rsaPkcs1Sha256;
  if (_oidIs(contents, _pkcs1Sha384)) return PqX509Algorithm.rsaPkcs1Sha384;
  if (_oidIs(contents, _pkcs1Sha512)) return PqX509Algorithm.rsaPkcs1Sha512;
  if (_oidIs(contents, _rsaPss)) return PqX509Algorithm.rsaPssSha256;
  return null;
}

List<int> _sigOid(PqX509Algorithm algorithm) => switch (algorithm) {
  PqX509Algorithm.mlDsa44 => _mlDsa44,
  PqX509Algorithm.mlDsa65 => _mlDsa65,
  PqX509Algorithm.mlDsa87 => _mlDsa87,
  PqX509Algorithm.ecdsaP256Sha256 => _ecdsa256,
  PqX509Algorithm.ecdsaP384Sha384 => _ecdsa384,
  PqX509Algorithm.ed25519 => _ed25519,
  PqX509Algorithm.rsaPkcs1Sha256 => _pkcs1Sha256,
  PqX509Algorithm.rsaPkcs1Sha384 => _pkcs1Sha384,
  PqX509Algorithm.rsaPkcs1Sha512 => _pkcs1Sha512,
  PqX509Algorithm.rsaPssSha256 ||
  PqX509Algorithm.rsaPssSha384 ||
  PqX509Algorithm.rsaPssSha512 => _rsaPss,
};

List<int> _pssHash(PqX509Algorithm algorithm) => switch (algorithm) {
  PqX509Algorithm.rsaPssSha256 => _sha256,
  PqX509Algorithm.rsaPssSha384 => _sha384,
  PqX509Algorithm.rsaPssSha512 => _sha512,
  _ => _sha256,
};

bool _isPkcs1(PqX509Algorithm algorithm) =>
    algorithm == PqX509Algorithm.rsaPkcs1Sha256 ||
    algorithm == PqX509Algorithm.rsaPkcs1Sha384 ||
    algorithm == PqX509Algorithm.rsaPkcs1Sha512;

bool _isPss(PqX509Algorithm algorithm) =>
    algorithm == PqX509Algorithm.rsaPssSha256 ||
    algorithm == PqX509Algorithm.rsaPssSha384 ||
    algorithm == PqX509Algorithm.rsaPssSha512;

Uint8List _u16(int value) {
  if (value <= 0xff) return Uint8List.fromList([value]);
  return Uint8List.fromList([(value >> 8) & 0xff, value & 0xff]);
}

List<List<(Uint8List, String)>>? _rdns(Uint8List name) {
  final reader = DerReader(name);
  final sequence = reader.tag(0x30);
  if (!sequence.ok || !reader.finished) return null;
  final body = reader.nested(sequence.slice!);
  final rdns = <List<(Uint8List, String)>>[];
  while (!body.finished) {
    final set = body.tag(0x31);
    if (!set.ok) return null;
    final values = body.nested(set.slice!);
    if (values.finished) return null;
    final atvs = <(Uint8List, String)>[];
    while (!values.finished) {
      final atv = values.tag(0x30);
      if (!atv.ok) return null;
      final inner = values.nested(atv.slice!);
      final oid = inner.tag(0x06);
      if (!oid.ok || inner.finished) return null;
      final tag = inner.bytes[inner.offset];
      final raw = inner.tag(tag);
      if (!raw.ok || !inner.finished) return null;
      final text = _directoryString(tag, raw.slice!.copy());
      if (text == null) return null;
      atvs.add((oid.slice!.copy(), text));
    }
    rdns.add(atvs);
  }
  return rdns;
}

bool _dnWithin(
  List<List<(Uint8List, String)>> name,
  List<List<(Uint8List, String)>> constraint,
) {
  if (constraint.length > name.length) return false;
  for (var i = 0; i < constraint.length; i++) {
    if (!_rdnEqual(name[i], constraint[i])) return false;
  }
  return true;
}

bool _rdnEqual(
  List<(Uint8List, String)> left,
  List<(Uint8List, String)> right,
) {
  if (left.length != right.length) return false;
  final pending = [...right];
  for (final item in left) {
    final index = pending.indexWhere(
      (other) => _same(item.$1, other.$1) && item.$2 == other.$2,
    );
    if (index < 0) return false;
    pending.removeAt(index);
  }
  return pending.isEmpty;
}

String? _directoryString(int tag, Uint8List bytes) {
  String text;
  if (tag == 0x0c || tag == 0x13 || tag == 0x16) {
    try {
      text = String.fromCharCodes(bytes);
      if (tag == 0x0c && text.codeUnits.any((unit) => unit > 0x7f)) {
        text = _utf8(bytes);
      }
    } catch (_) {
      return null;
    }
  } else if (tag == 0x1e) {
    if (bytes.length.isOdd) return null;
    final units = <int>[];
    for (var i = 0; i < bytes.length; i += 2) {
      units.add((bytes[i] << 8) | bytes[i + 1]);
    }
    text = String.fromCharCodes(units);
  } else {
    return null;
  }
  final collapsed = text.trim().replaceAll(RegExp(r'\s+'), ' ').toLowerCase();
  return collapsed;
}

String _utf8(Uint8List bytes) {
  var out = '';
  for (var i = 0; i < bytes.length;) {
    final lead = bytes[i];
    if (lead < 0x80) {
      out += String.fromCharCode(lead);
      i++;
    } else if (lead < 0xe0 && i + 1 < bytes.length) {
      out += String.fromCharCode(((lead & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
      i += 2;
    } else if (i + 2 < bytes.length) {
      out += String.fromCharCode(
        ((lead & 0x0f) << 12) |
            ((bytes[i + 1] & 0x3f) << 6) |
            (bytes[i + 2] & 0x3f),
      );
      i += 3;
    } else {
      throw const FormatException('utf8');
    }
  }
  return out;
}

PqSignatureAlgorithm _mlDsa(PqX509Algorithm algorithm) => switch (algorithm) {
  PqX509Algorithm.mlDsa44 => PqSignatureAlgorithm.mlDsa44,
  PqX509Algorithm.mlDsa65 => PqSignatureAlgorithm.mlDsa65,
  PqX509Algorithm.mlDsa87 => PqSignatureAlgorithm.mlDsa87,
  _ => PqSignatureAlgorithm.mlDsa65,
};

PqRsaHash _rsaHash(PqX509Algorithm algorithm) => switch (algorithm) {
  PqX509Algorithm.rsaPkcs1Sha384 ||
  PqX509Algorithm.rsaPssSha384 => PqRsaHash.sha384,
  PqX509Algorithm.rsaPkcs1Sha512 ||
  PqX509Algorithm.rsaPssSha512 => PqRsaHash.sha512,
  _ => PqRsaHash.sha256,
};

int _int(Uint8List bytes) {
  var value = 0;
  for (final byte in bytes) {
    value = (value << 8) | byte;
  }
  return value;
}

int _topBits(int top) {
  var count = 0;
  var value = top;
  while (value > 0) {
    count++;
    value >>= 1;
  }
  return count;
}
