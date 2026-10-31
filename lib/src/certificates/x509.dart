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

  /// Basic path. [chain] is leaf first. [anchors] are DER trust anchors.
  /// [now] must be UTC. Does not fetch, and does not read a trust store.
  static PqX509Path validate({
    required List<Uint8List> chain,
    required List<Uint8List> anchors,
    required DateTime now,
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
    return _path(certs, roots, now);
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
    bool uriNameConstraint = false,
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
    if (!version3 &&
        (ca ||
            subjectAltNames.isNotEmpty ||
            includeEku ||
            permittedDns.isNotEmpty ||
            uriNameConstraint)) {
      throw ArgumentError('a v1 certificate cannot carry extensions');
    }
    final algorithmId = _algorithmDer(algorithm);
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
    tbsBody.raw(_spki(publicKey));
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
                uriNameConstraint: uriNameConstraint,
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
  final algorithm = _algorithm(reader.nested(signatureAlgorithm));
  final built = _tbs(reader.nested(tbs), tbs.whole());
  if (built.algorithm != algorithm) _die(PqX509Failure.notDer);
  return PqX509Parsed.ok(
    PqX509Certificate(
      der: Uint8List.fromList(der),
      tbs: built.tbs,
      algorithm: algorithm,
      signature: _signatureBits(signatureBits, algorithm),
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
  final algorithm = _algorithm(reader.nested(_need(reader.tag(0x30))));
  final issuer = _need(reader.tag(0x30));
  if (issuer.whole().length > PqX509.maxNameBytes) _die(PqX509Failure.badName);
  final validity = reader.nested(_need(reader.tag(0x30)));
  final notBefore = _time(_need(validity.tag(_timeTag(validity))));
  final notAfter = _time(_need(validity.tag(_timeTag(validity))));
  if (!validity.finished) _die(PqX509Failure.notDer);
  if (notBefore.isAfter(notAfter)) _die(PqX509Failure.badTime);
  final subject = _need(reader.tag(0x30));
  if (subject.whole().length > PqX509.maxNameBytes) _die(PqX509Failure.badName);
  final publicKey = _publicKey(
    reader.nested(_need(reader.tag(0x30))),
    algorithm,
  );
  if (reader.offset < reader.end &&
      (reader.bytes[reader.offset] == 0xa1 ||
          reader.bytes[reader.offset] == 0x81 ||
          reader.bytes[reader.offset] == 0xa2 ||
          reader.bytes[reader.offset] == 0x82)) {
    _die(PqX509Failure.notDer);
  }
  final extensions = <PqX509Extension>[];
  final names = <PqX509GeneralName>[];
  bool? ca;
  int? pathLen;
  int? keyUsage;
  final eku = <List<int>>[];
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
      }
    }
  }
  if (!reader.finished) _die(PqX509Failure.notDer);
  return _Built(
    PqX509Certificate(
      der: Uint8List(0),
      tbs: tbs,
      algorithm: algorithm,
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
    ),
  );
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

PqX509Algorithm _algorithm(DerReader reader) {
  final oid = _need(reader.tag(0x06)).copy();
  if (_oidIs(oid, _rsaPss)) {
    if (reader.finished) _die(PqX509Failure.unsupportedAlgorithm);
    final algorithm = _pssParameters(reader.nested(_need(reader.tag(0x30))));
    if (!reader.finished) _die(PqX509Failure.notDer);
    return algorithm;
  }
  final algorithm = _algorithmOid(oid);
  if (algorithm == null) _die(PqX509Failure.unsupportedAlgorithm);
  if (reader.finished) {
    if (_isPkcs1(algorithm)) _die(PqX509Failure.notDer);
    return algorithm;
  }
  if (!_isPkcs1(algorithm)) _die(PqX509Failure.notDer);
  final nullValue = _need(reader.tag(0x05));
  if (nullValue.length != 0 || !reader.finished) _die(PqX509Failure.notDer);
  return algorithm;
}

PqX509Algorithm _pssParameters(DerReader reader) {
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
  final salt = hash ~/ 8;
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
  if (reader.offset >= reader.end || reader.bytes[reader.offset] != 0xa2) {
    _die(PqX509Failure.unsupportedAlgorithm);
  }
  final saltWrap = reader.nested(_need(reader.tag(0xa2)));
  final saltValue = unsignedInteger(
    _need(saltWrap.tag(0x02)).copy(),
    maxBytes: 2,
  );
  if (!saltWrap.finished || saltValue == null || _int(saltValue) != salt) {
    _die(PqX509Failure.unsupportedAlgorithm);
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
  return algorithm;
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

PqX509PublicKey _publicKey(DerReader reader, PqX509Algorithm algorithm) {
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
      final length = p256 ? 65 : 97;
      if (key.length != length || key[0] != 0x04) {
        _die(PqX509Failure.unsupportedAlgorithm);
      }
      final copy = Uint8List.fromList(key);
      return p256 ? PqX509EcdsaP256Key(copy) : PqX509EcdsaP384Key(copy);
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
      if (!_oidIs(oid, _rsaEncryption)) {
        _die(PqX509Failure.unsupportedAlgorithm);
      }
      final nullValue = _need(algorithmId.tag(0x05));
      if (nullValue.length != 0 || !algorithmId.finished) {
        _die(PqX509Failure.notDer);
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
      );
  }
}

PqX509Path _path(
  List<PqX509Certificate> certs,
  List<PqX509Certificate> anchors,
  DateTime now,
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
    final critical = _critical(certificate);
    if (critical != null) return PqX509Path.fail(critical);
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

PqX509Failure? _critical(PqX509Certificate certificate) {
  for (final extension in certificate.extensions) {
    if (!extension.critical) continue;
    if (_arcs(extension.oid, _keyUsage) ||
        _arcs(extension.oid, _basic) ||
        _arcs(extension.oid, _eku) ||
        _arcs(extension.oid, _san) ||
        _arcs(extension.oid, _ski) ||
        _arcs(extension.oid, _aki) ||
        _arcs(extension.oid, _names)) {
      continue;
    }
    return PqX509Failure.badConstraint;
  }
  return null;
}

PqX509Failure? _constraints(List<PqX509Certificate> path) {
  final permittedDns = <List<String>>[];
  final excludedDns = <List<String>>[];
  final permittedIp = <List<Uint8List>>[];
  final excludedIp = <List<Uint8List>>[];
  for (var i = 0; i < path.length; i++) {
    final failed = _constrained(
      path[i],
      permittedDns,
      excludedDns,
      permittedIp,
      excludedIp,
    );
    if (failed != null) return failed;
    for (final extension in path[i].extensions) {
      if (!_arcs(extension.oid, _names)) continue;
      final decoded = _nameConstraints(extension.value);
      if (decoded == null) return PqX509Failure.badConstraint;
      permittedDns.add(decoded.$1);
      excludedDns.add(decoded.$2);
      permittedIp.add(decoded.$3);
      excludedIp.add(decoded.$4);
    }
  }
  return null;
}

PqX509Failure? _constrained(
  PqX509Certificate certificate,
  List<List<String>> permittedDns,
  List<List<String>> excludedDns,
  List<List<Uint8List>> permittedIp,
  List<List<Uint8List>> excludedIp,
) {
  for (final name in certificate.subjectAltNames) {
    if (name is PqX509DnsName) {
      for (final excluded in excludedDns) {
        for (final base in excluded) {
          if (_dnsWithin(name.ascii, base)) return PqX509Failure.badConstraint;
        }
      }
      for (final permitted in permittedDns) {
        if (permitted.isEmpty) continue;
        var matched = false;
        for (final base in permitted) {
          if (_dnsWithin(name.ascii, base)) matched = true;
        }
        if (!matched) return PqX509Failure.badConstraint;
      }
    } else if (name is PqX509Ip4Name || name is PqX509Ip6Name) {
      final octets = name is PqX509Ip4Name
          ? name.octets
          : (name as PqX509Ip6Name).octets;
      if (octets.length != 4 && octets.length != 16) continue;
      for (final excluded in excludedIp) {
        for (final base in excluded) {
          if (_ipWithin(octets, base)) return PqX509Failure.badConstraint;
        }
      }
      for (final permitted in permittedIp) {
        final same = permitted.where(
          (base) => base.length == octets.length * 2,
        );
        if (same.isEmpty) continue;
        var matched = false;
        for (final base in same) {
          if (_ipWithin(octets, base)) matched = true;
        }
        if (!matched) return PqX509Failure.badConstraint;
      }
    }
  }
  return null;
}

(List<String>, List<String>, List<Uint8List>, List<Uint8List>)?
_nameConstraints(Uint8List value) {
  final reader = DerReader(value);
  DerSlice? bodySlice;
  try {
    bodySlice = _need(reader.tag(0x30));
    if (!reader.finished) return null;
  } on _Stop {
    return null;
  }
  final body = DerReader(value, offset: bodySlice.start, end: bodySlice.end);
  final permittedDns = <String>[];
  final excludedDns = <String>[];
  final permittedIp = <Uint8List>[];
  final excludedIp = <Uint8List>[];
  while (!body.finished) {
    final tag = body.bytes[body.offset];
    if (tag != 0xa0 && tag != 0xa1) return null;
    final subtrees = body.nested(_need(body.tag(tag)));
    if (subtrees.finished) return null;
    while (!subtrees.finished) {
      final tree = subtrees.nested(_need(subtrees.tag(0x30)));
      final base = _generalName(tree);
      if (base == null || !tree.finished) return null;
      if (tag == 0xa0) {
        if (base is PqX509DnsName) permittedDns.add(base.ascii);
        if (base is PqX509Ip4Name || base is PqX509Ip6Name) {
          final constraint = _ipConstraint(
            base is PqX509Ip4Name
                ? base.octets
                : (base as PqX509Ip6Name).octets,
          );
          if (constraint == null) return null;
          permittedIp.add(constraint);
        }
      } else {
        if (base is PqX509DnsName) excludedDns.add(base.ascii);
        if (base is PqX509Ip4Name || base is PqX509Ip6Name) {
          final constraint = _ipConstraint(
            base is PqX509Ip4Name
                ? base.octets
                : (base as PqX509Ip6Name).octets,
          );
          if (constraint == null) return null;
          excludedIp.add(constraint);
        }
      }
    }
  }
  return (permittedDns, excludedDns, permittedIp, excludedIp);
}

Uint8List? _ipConstraint(Uint8List octets) {
  if (octets.length == 8 || octets.length == 32) return octets;
  return null;
}

PqX509GeneralName? _generalName(DerReader reader) {
  if (reader.offset >= reader.end) return null;
  final tag = reader.bytes[reader.offset];
  if (tag != 0x82 && tag != 0x87) return null;
  final value = _need(reader.tag(tag)).copy();
  if (tag == 0x82) {
    if (!_ia5(value)) return null;
    return PqX509DnsName(String.fromCharCodes(value).toLowerCase());
  }
  if (value.length == 4) return PqX509Ip4Name(value);
  if (value.length == 16) return PqX509Ip6Name(value);
  if (value.length == 8 || value.length == 32) {
    return value.length == 8 ? PqX509Ip4Name(value) : PqX509Ip6Name(value);
  }
  return null;
}

bool _dnsWithin(String name, String base) {
  final left = name.toLowerCase();
  final right = base.toLowerCase();
  return left == right || left.endsWith('.$right');
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
    if (tag != 0x82 && tag != 0x87) {
      _need(body.tag(tag));
      continue;
    }
    final name = _generalName(body);
    if (name == null) _die(PqX509Failure.badName);
    names.add(name);
  }
  return names;
}

Uint8List _algorithmDer(PqX509Algorithm algorithm) {
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
            ..sequence(_pssDer(algorithm)))
          .take(),
    );
  } else {
    writer.sequence((DerWriter()..oid(_sigOid(algorithm))).take());
  }
  return writer.take();
}

Uint8List _pssDer(PqX509Algorithm algorithm) {
  final hash = _pssHash(algorithm);
  final salt = hash == _sha256
      ? 32
      : hash == _sha384
      ? 48
      : 64;
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
        ..tlv(
          0xa2,
          (DerWriter()..integerUnsigned(Uint8List.fromList([salt]))).take(),
        ))
      .take();
}

Uint8List _spki(PqX509PublicKey key) {
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
      writer.sequence(
        (DerWriter()
              ..sequence(
                (DerWriter()
                      ..oid(_rsaEncryption)
                      ..nullValue())
                    .take(),
              )
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
  required bool uriNameConstraint,
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
  if (permittedDns.isNotEmpty || uriNameConstraint) {
    writer.sequence(
      _extensionDer(
        _names,
        true,
        _nameConstraintsDer(permittedDns, uriNameConstraint),
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
    }
  }
  return (DerWriter()..sequence(writer.take())).take();
}

Uint8List _nameConstraintsDer(List<String> permittedDns, bool uri) {
  final subtrees = DerWriter();
  for (final name in permittedDns) {
    final bytes = Uint8List.fromList(name.codeUnits);
    if (!_ia5(bytes)) {
      throw ArgumentError.value(name, 'permittedDns', 'not ASCII');
    }
    subtrees.sequence((DerWriter()..tlv(0x82, bytes)).take());
  }
  if (uri) {
    subtrees.sequence(
      (DerWriter()..tlv(0x86, 'https://example.test'.codeUnits)).take(),
    );
  }
  return (DerWriter()
        ..sequence((DerWriter()..tlv(0xa0, subtrees.take())).take()))
      .take();
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
