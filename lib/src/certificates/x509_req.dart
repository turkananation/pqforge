part of 'x509.dart';

/// One `-addext` line, or several. This is the subset `openssl req` uses for
/// a name, a key usage, an extended key usage, and basic constraints.
final class PqX509Addext {
  PqX509Addext({
    required this.names,
    required this.ca,
    required this.pathLen,
    required this.hasBasic,
    required this.basicCritical,
    required this.keyUsage,
    required this.keyUsageCritical,
    required this.serverAuth,
    required this.clientAuth,
    required this.ekuCritical,
    required this.sanCritical,
    required this.hasSan,
    required this.hasKeyUsage,
    required this.hasEku,
  });

  final List<PqX509GeneralName> names;
  final bool ca;
  final int? pathLen;
  final bool hasBasic;
  final bool basicCritical;
  final int? keyUsage;
  final bool keyUsageCritical;
  final bool serverAuth;
  final bool clientAuth;
  final bool ekuCritical;
  final bool sanCritical;
  final bool hasSan;
  final bool hasKeyUsage;
  final bool hasEku;

  static PqX509Addext parse(Iterable<String> lines) => _parseAddext(lines);
}

/// A PKCS#10 request. [info] is the exact bytes the signature covers.
final class PqX509Request {
  PqX509Request({
    required this.der,
    required this.info,
    required this.subject,
    required this.publicKey,
    required this.algorithm,
    required this.signature,
    required this.pssSaltLength,
    required this.names,
    required this.ca,
    required this.pathLen,
    required this.hasBasic,
    required this.basicCritical,
    required this.keyUsageBits,
    required this.keyUsageCritical,
    required this.serverAuth,
    required this.clientAuth,
    required this.ekuCritical,
    required this.sanCritical,
    required this.hasExtensions,
  });

  final Uint8List der;
  final Uint8List info;
  final PqX509Name subject;
  final PqX509PublicKey publicKey;
  final PqX509Algorithm algorithm;
  final Uint8List signature;
  final int? pssSaltLength;
  final List<PqX509GeneralName> names;
  final bool? ca;
  final int? pathLen;
  final bool hasBasic;
  final bool basicCritical;
  final int? keyUsageBits;
  final bool keyUsageCritical;
  final bool serverAuth;
  final bool clientAuth;
  final bool ekuCritical;
  final bool sanCritical;
  final bool hasExtensions;
}

final class PqX509RequestParsed {
  const PqX509RequestParsed.ok(this.request) : failure = null;

  const PqX509RequestParsed.fail(this.failure) : request = null;

  final PqX509Request? request;
  final PqX509Failure? failure;
}

/// A private key read from an OpenSSL PEM block.
final class PqX509PrivateKey {
  PqX509PrivateKey._(this.algorithm, this.publicKey, this._sign);

  final PqX509Algorithm algorithm;
  final PqX509PublicKey publicKey;
  final Uint8List Function(Uint8List message) _sign;

  Uint8List sign(Uint8List message) => _sign(message);
}

const _extensionRequest = [1, 2, 840, 113549, 1, 9, 14];
const _country = [2, 5, 4, 6];
const _state = [2, 5, 4, 8];
const _locality = [2, 5, 4, 7];
const _organization = [2, 5, 4, 10];
const _unit = [2, 5, 4, 11];
const _emailAddress = [1, 2, 840, 113549, 1, 9, 1];

PqX509Name _subjectFromOpenssl(String subj) {
  if (!subj.startsWith('/')) {
    throw ArgumentError.value(subj, 'subj', 'must start with /');
  }
  final rdns = _splitSubject(subj.substring(1), '/');
  if (rdns.isEmpty) {
    throw ArgumentError.value(subj, 'subj', 'empty');
  }
  final sets = <Uint8List>[];
  for (final rdn in rdns) {
    if (rdn.isEmpty) throw ArgumentError.value(subj, 'subj', 'empty RDN');
    final atvs = <Uint8List>[];
    for (final piece in _splitSubject(rdn, '+')) {
      final split = _splitOnce(piece, '=');
      if (split == null || split.$1.isEmpty || split.$2.isEmpty) {
        throw ArgumentError.value(piece, 'subj', 'expected type=value');
      }
      atvs.add(_atv(split.$1, split.$2));
    }
    atvs.sort(_bytesLess);
    final set = DerWriter();
    for (final atv in atvs) {
      set.raw(atv);
    }
    sets.add((DerWriter()..tlv(0x31, set.take())).take());
  }
  final name = DerWriter();
  for (final set in sets) {
    name.raw(set);
  }
  return PqX509Name((DerWriter()..sequence(name.take())).take());
}

Uint8List _atv(String type, String value) {
  final oid = switch (type) {
    'C' || 'countryName' => _country,
    'ST' || 'stateOrProvinceName' => _state,
    'L' || 'localityName' => _locality,
    'O' || 'organizationName' => _organization,
    'OU' || 'organizationalUnitName' => _unit,
    'CN' || 'commonName' => _cn,
    'emailAddress' => _emailAddress,
    _ => throw ArgumentError.value(type, 'subj', 'unknown attribute'),
  };
  final bytes = Uint8List.fromList(value.codeUnits);
  if (type == 'C' || type == 'countryName') {
    if (bytes.length != 2 || !_isPrintable(bytes)) {
      throw ArgumentError.value(value, 'C', 'expected two printable letters');
    }
  }
  for (final byte in bytes) {
    if (byte > 0x7f && type == 'emailAddress') {
      throw ArgumentError.value(value, type, 'not ASCII');
    }
  }
  final encoded = type == 'emailAddress' || _isPrintable(bytes)
      ? bytes
      : Uint8List.fromList(utf8.encode(value));
  final tag = type == 'emailAddress'
      ? 0x16
      : _isPrintable(bytes)
      ? 0x13
      : 0x0c;
  if (type == 'emailAddress' && !_ia5(encoded)) {
    throw ArgumentError.value(value, type, 'not IA5');
  }
  if (type == 'CN' && encoded.length > 64) {
    throw ArgumentError.value(value, 'CN', 'longer than 64');
  }
  return (DerWriter()..sequence(
        (DerWriter()
              ..oid(oid)
              ..tlv(tag, encoded))
            .take(),
      ))
      .take();
}

int _bytesLess(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

List<String> _splitSubject(String text, String separator) {
  final out = <String>[];
  final current = StringBuffer();
  for (var i = 0; i < text.length; i++) {
    final char = text[i];
    if (char == '\\' && i + 1 < text.length) {
      current.write(text[++i]);
      continue;
    }
    if (char == separator) {
      out.add(current.toString());
      current.clear();
      continue;
    }
    current.write(char);
  }
  out.add(current.toString());
  return out;
}

(String, String)? _splitOnce(String text, String separator) {
  final current = StringBuffer();
  for (var i = 0; i < text.length; i++) {
    final char = text[i];
    if (char == '\\' && i + 1 < text.length) {
      current.write(text[++i]);
      continue;
    }
    if (char == separator) {
      return (current.toString(), text.substring(i + 1).replaceAll(r'\', ''));
    }
    current.write(char);
  }
  return null;
}

PqX509Addext _parseAddext(Iterable<String> lines) {
  final names = <PqX509GeneralName>[];
  var ca = false;
  int? pathLen;
  var hasBasic = false;
  var basicCritical = false;
  int? keyUsage;
  var keyUsageCritical = false;
  var serverAuth = false;
  var clientAuth = false;
  var ekuCritical = false;
  var sanCritical = false;
  var hasSan = false;
  var hasKeyUsage = false;
  var hasEku = false;
  for (final raw in lines) {
    final critical = raw.startsWith('critical,');
    final line = critical ? raw.substring('critical,'.length) : raw;
    final split = line.split('=');
    if (split.length < 2) {
      throw ArgumentError.value(raw, 'addext', 'expected name=value');
    }
    final name = split.first;
    final value = split.sublist(1).join('=');
    switch (name) {
      case 'subjectAltName':
        hasSan = true;
        sanCritical = critical;
        names.addAll(_addextNames(value));
      case 'keyUsage':
        hasKeyUsage = true;
        keyUsageCritical = critical;
        keyUsage = _addextUsage(value);
      case 'extendedKeyUsage':
        hasEku = true;
        ekuCritical = critical;
        for (final purpose in value.split(',')) {
          switch (purpose) {
            case 'serverAuth':
              serverAuth = true;
            case 'clientAuth':
              clientAuth = true;
            default:
              throw ArgumentError.value(purpose, 'extendedKeyUsage');
          }
        }
      case 'basicConstraints':
        hasBasic = true;
        basicCritical = critical;
        for (final part in value.split(',')) {
          if (part == 'CA:TRUE') ca = true;
          if (part == 'CA:FALSE') ca = false;
          if (part.startsWith('pathlen:')) {
            pathLen = int.tryParse(part.substring('pathlen:'.length));
            if (pathLen == null) {
              throw ArgumentError.value(part, 'pathlen');
            }
          }
        }
      default:
        throw ArgumentError.value(name, 'addext', 'unsupported extension');
    }
  }
  return PqX509Addext(
    names: names,
    ca: ca,
    pathLen: pathLen,
    hasBasic: hasBasic,
    basicCritical: basicCritical,
    keyUsage: keyUsage,
    keyUsageCritical: keyUsageCritical,
    serverAuth: serverAuth,
    clientAuth: clientAuth,
    ekuCritical: ekuCritical,
    sanCritical: sanCritical,
    hasSan: hasSan,
    hasKeyUsage: hasKeyUsage,
    hasEku: hasEku,
  );
}

List<PqX509GeneralName> _addextNames(String value) {
  final names = <PqX509GeneralName>[];
  for (final part in value.split(',')) {
    final split = part.split(':');
    if (split.length < 2) {
      throw ArgumentError.value(part, 'subjectAltName');
    }
    final kind = split.first;
    final rest = split.sublist(1).join(':');
    switch (kind) {
      case 'DNS':
        names.add(PqX509DnsName(rest.toLowerCase()));
      case 'email':
        names.add(PqX509EmailName(rest));
      case 'URI':
        names.add(PqX509UriName(rest));
      case 'IP':
        final ip = _ip(rest);
        names.add(ip.length == 4 ? PqX509Ip4Name(ip) : PqX509Ip6Name(ip));
      default:
        throw ArgumentError.value(kind, 'subjectAltName');
    }
  }
  return names;
}

Uint8List _ip(String text) {
  if (text.contains('.')) {
    final parts = text.split('.');
    if (parts.length != 4) throw ArgumentError.value(text, 'IP');
    return Uint8List.fromList([for (final part in parts) int.parse(part)]);
  }
  final halves = text.split('::');
  if (halves.length > 2) throw ArgumentError.value(text, 'IP');
  List<int> side(String value) {
    if (value.isEmpty) return const [];
    return [for (final piece in value.split(':')) int.parse(piece, radix: 16)];
  }

  final head = side(halves.first);
  final tail = halves.length == 2 ? side(halves[1]) : const <int>[];
  final missing = 8 - head.length - tail.length;
  if (missing < 0) throw ArgumentError.value(text, 'IP');
  final groups = [...head, for (var i = 0; i < missing; i++) 0, ...tail];
  final out = Uint8List(16);
  for (var i = 0; i < 8; i++) {
    out[i * 2] = groups[i] >> 8;
    out[i * 2 + 1] = groups[i] & 0xff;
  }
  return out;
}

int _addextUsage(String value) {
  var mask = 0;
  for (final name in value.split(',')) {
    if (name.isEmpty) continue;
    mask |= switch (name) {
      'digitalSignature' => 1,
      'nonRepudiation' || 'contentCommitment' => 1 << 1,
      'keyEncipherment' => 1 << 2,
      'dataEncipherment' => 1 << 3,
      'keyAgreement' => 1 << 4,
      'keyCertSign' => 1 << 5,
      'cRLSign' => 1 << 6,
      'encipherOnly' => 1 << 7,
      'decipherOnly' => 1 << 8,
      _ => throw ArgumentError.value(name, 'keyUsage'),
    };
  }
  return mask;
}

List<({String label, Uint8List der})> _pemBlocks(String pem) {
  final matches = RegExp(
    '-----BEGIN ([A-Z0-9 ]+)-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+)-----END \\1-----',
  ).allMatches(pem);
  if (matches.isEmpty) throw const FormatException('no PEM block');
  final out = <({String label, Uint8List der})>[];
  for (final match in matches) {
    final label = match.group(1)!;
    const kept = {
      'CERTIFICATE',
      'X509 CERTIFICATE',
      'CERTIFICATE REQUEST',
      'NEW CERTIFICATE REQUEST',
      'PRIVATE KEY',
      'EC PRIVATE KEY',
      'RSA PRIVATE KEY',
    };
    if (!kept.contains(label)) {
      throw FormatException('unexpected PEM label $label');
    }
    final body = match.group(2)!.replaceAll(RegExp(r'\s+'), '');
    final der = Uint8List.fromList(base64.decode(body));
    if (der.isEmpty) throw const FormatException('empty PEM block');
    out.add((label: label, der: der));
  }
  return out;
}

Uint8List _mintRequest({
  required PqX509Name subject,
  required PqX509PublicKey publicKey,
  required PqX509Algorithm algorithm,
  required Uint8List Function(Uint8List info) sign,
  required List<PqX509GeneralName> subjectAltNames,
  required bool ca,
  required int? pathLen,
  required bool includeBasic,
  required int? keyUsageMask,
  required bool includeEku,
  required bool clientAuth,
  required int? pssSaltLength,
  required bool pssPublicKey,
}) {
  final extensions = _extensions(
    ca: ca,
    pathLen: pathLen,
    digitalSignature: false,
    keyCertSign: false,
    includeEku: includeEku,
    names: subjectAltNames,
    permittedDns: const [],
    excludedDns: const [],
    permittedEmail: const [],
    excludedEmail: const [],
    permittedUri: const [],
    excludedUri: const [],
    permittedDirectory: const [],
    excludedDirectory: const [],
    permitOtherName: false,
    mustStaple: false,
    keyUsageMask: keyUsageMask,
    clientAuth: clientAuth,
    includeBasic: includeBasic,
    serverAuth: includeEku,
  );
  final info = DerWriter()
    ..integerUnsigned(Uint8List.fromList([0]))
    ..raw(subject.der)
    ..raw(
      _spki(
        publicKey,
        algorithm: algorithm,
        pssPublicKey: pssPublicKey,
        pssSaltLength: pssSaltLength,
      ),
    );
  if (extensions.isEmpty) {
    info.tlv(0xa0, const []);
  } else {
    final attribute =
        (DerWriter()
              ..oid(_extensionRequest)
              ..tlv(0x31, (DerWriter()..sequence(extensions)).take()))
            .take();
    info.tlv(0xa0, (DerWriter()..sequence(attribute)).take());
  }
  final body = (DerWriter()..sequence(info.take())).take();
  final signature = sign(body);
  return (DerWriter()..sequence(
        (DerWriter()
              ..raw(body)
              ..raw(_algorithmDer(algorithm, pssSaltLength))
              ..bitString(signature))
            .take(),
      ))
      .take();
}

PqX509RequestParsed _parseRequest(Uint8List der) {
  try {
    final reader = DerReader(der);
    final outer = reader.nested(_need(reader.tag(0x30)));
    if (!reader.finished) _die(PqX509Failure.notDer);
    final info = _need(outer.tag(0x30));
    final algorithmId = _need(outer.tag(0x30));
    final bits = _need(outer.tag(0x03));
    if (!outer.finished) _die(PqX509Failure.notDer);
    final signatureId = _algorithm(reader.nested(algorithmId));
    final body = reader.nested(info);
    final version = _need(body.tag(0x02));
    if (version.length != 1 || version.bytes[version.start] != 0) {
      _die(PqX509Failure.notDer);
    }
    final subject = _need(body.tag(0x30));
    final spki = _need(body.tag(0x30));
    final copied = _requestExtensions(body);
    if (!body.finished) _die(PqX509Failure.notDer);
    final publicKey = _publicKey(reader.nested(spki), signatureId);
    final signature = _signatureBits(bits, signatureId.algorithm);
    return PqX509RequestParsed.ok(
      PqX509Request(
        der: Uint8List.fromList(der),
        info: info.whole(),
        subject: PqX509Name(subject.whole()),
        publicKey: publicKey,
        algorithm: signatureId.algorithm,
        signature: signature,
        pssSaltLength: signatureId.pssSalt,
        names: copied.names,
        ca: copied.ca,
        pathLen: copied.pathLen,
        hasBasic: copied.hasBasic,
        basicCritical: copied.basicCritical,
        keyUsageBits: copied.keyUsageBits,
        keyUsageCritical: copied.keyUsageCritical,
        serverAuth: copied.serverAuth,
        clientAuth: copied.clientAuth,
        ekuCritical: copied.ekuCritical,
        sanCritical: copied.sanCritical,
        hasExtensions: copied.hasExtensions,
      ),
    );
  } on _Stop catch (error) {
    return PqX509RequestParsed.fail(error.failure);
  }
}

final class _Copied {
  _Copied({
    required this.names,
    required this.ca,
    required this.pathLen,
    required this.hasBasic,
    required this.basicCritical,
    required this.keyUsageBits,
    required this.keyUsageCritical,
    required this.serverAuth,
    required this.clientAuth,
    required this.ekuCritical,
    required this.sanCritical,
    required this.hasExtensions,
  });

  final List<PqX509GeneralName> names;
  final bool? ca;
  final int? pathLen;
  final bool hasBasic;
  final bool basicCritical;
  final int? keyUsageBits;
  final bool keyUsageCritical;
  final bool serverAuth;
  final bool clientAuth;
  final bool ekuCritical;
  final bool sanCritical;
  final bool hasExtensions;
}

_Copied _requestExtensions(DerReader body) {
  if (body.finished) {
    return _Copied(
      names: const [],
      ca: null,
      pathLen: null,
      hasBasic: false,
      basicCritical: false,
      keyUsageBits: null,
      keyUsageCritical: false,
      serverAuth: false,
      clientAuth: false,
      ekuCritical: false,
      sanCritical: false,
      hasExtensions: false,
    );
  }
  final attributes = body.nested(_need(body.tag(0xa0)));
  final names = <PqX509GeneralName>[];
  bool? ca;
  int? pathLen;
  var hasBasic = false;
  var basicCritical = false;
  int? keyUsageBits;
  var keyUsageCritical = false;
  var serverAuth = false;
  var clientAuth = false;
  var ekuCritical = false;
  var sanCritical = false;
  var hasExtensions = false;
  while (!attributes.finished) {
    final attribute = attributes.nested(_need(attributes.tag(0x30)));
    final oid = _need(attribute.tag(0x06)).copy();
    final set = attribute.nested(_need(attribute.tag(0x31)));
    if (!attribute.finished) _die(PqX509Failure.notDer);
    if (!_oidIs(oid, _extensionRequest)) continue;
    final extensions = set.nested(_need(set.tag(0x30)));
    if (!set.finished) _die(PqX509Failure.notDer);
    hasExtensions = true;
    while (!extensions.finished) {
      final extension = _extension(
        extensions.nested(_need(extensions.tag(0x30))),
      );
      if (_arcs(extension.oid, _basic)) {
        final parsed = _basicConstraints(extension.value);
        hasBasic = true;
        basicCritical = extension.critical;
        ca = parsed.$1;
        pathLen = parsed.$2;
      } else if (_arcs(extension.oid, _keyUsage)) {
        keyUsageBits = _keyUsageBits(extension.value);
        keyUsageCritical = extension.critical;
      } else if (_arcs(extension.oid, _eku)) {
        ekuCritical = extension.critical;
        for (final purpose in _ekuOids(extension.value)) {
          if (_arcs(purpose, _serverAuth)) serverAuth = true;
          if (_arcs(purpose, _clientAuth)) clientAuth = true;
        }
      } else if (_arcs(extension.oid, _san)) {
        sanCritical = extension.critical;
        names.addAll(_parseSan(extension.value));
      } else if (extension.critical) {
        _die(PqX509Failure.badConstraint);
      }
    }
  }
  return _Copied(
    names: names,
    ca: ca,
    pathLen: pathLen,
    hasBasic: hasBasic,
    basicCritical: basicCritical,
    keyUsageBits: keyUsageBits,
    keyUsageCritical: keyUsageCritical,
    serverAuth: serverAuth,
    clientAuth: clientAuth,
    ekuCritical: ekuCritical,
    sanCritical: sanCritical,
    hasExtensions: hasExtensions,
  );
}

Uint8List _signRequest({
  required Uint8List request,
  required PqX509Name issuer,
  required PqX509Algorithm algorithm,
  required Uint8List Function(Uint8List tbs) sign,
  required DateTime notBefore,
  required DateTime notAfter,
  required Uint8List serial,
  required int? pssSaltLength,
}) {
  final parsed = _parseRequest(request);
  final csr = parsed.request;
  if (csr == null) {
    throw FormatException(parsed.failure!.name);
  }
  if (!_verifySignature(
    algorithm: csr.algorithm,
    key: csr.publicKey,
    message: csr.info,
    signature: csr.signature,
    pssSaltLength: csr.pssSaltLength,
  )) {
    throw const FormatException('CSR signature did not verify');
  }
  final copied = csr.hasExtensions;
  return PqX509.mint(
    issuer: issuer,
    subject: csr.subject,
    publicKey: csr.publicKey,
    algorithm: algorithm,
    sign: sign,
    notBefore: notBefore,
    notAfter: notAfter,
    serial: serial,
    pssSaltLength: pssSaltLength,
    subjectAltNames: csr.names,
    ca: csr.ca ?? false,
    pathLen: csr.pathLen,
    digitalSignature: !copied,
    keyCertSign: (csr.ca ?? false) && !copied,
    includeBasic: !copied || csr.hasBasic,
    keyUsageMask: copied ? (csr.keyUsageBits ?? 0) : null,
    includeEku: copied ? csr.serverAuth || csr.clientAuth : true,
    serverAuth: copied ? csr.serverAuth : true,
    clientAuth: csr.clientAuth,
    basicCritical: copied ? csr.basicCritical : true,
    keyUsageCritical: copied ? csr.keyUsageCritical : true,
    ekuCritical: csr.ekuCritical,
    sanCritical: csr.sanCritical,
  );
}

PqX509PrivateKey _readPrivateKey(String pem) {
  final blocks = _pemBlocks(pem);
  final block = blocks.firstWhere(
    (block) =>
        block.label == 'PRIVATE KEY' ||
        block.label == 'EC PRIVATE KEY' ||
        block.label == 'RSA PRIVATE KEY',
    orElse: () => throw const FormatException('no PEM private key'),
  );
  final reader = DerReader(block.der);
  if (block.label == 'RSA PRIVATE KEY') return _rsaKey(reader);
  if (block.label == 'EC PRIVATE KEY') return _ecKeyFromSec1(reader, null);
  final outer = reader.nested(_need(reader.tag(0x30)));
  if (!reader.finished) throw const FormatException('PKCS#8 trailing bytes');
  final version = _need(outer.tag(0x02));
  if (version.length != 1 || version.bytes[version.start] != 0) {
    throw const FormatException('PKCS#8 version');
  }
  final algorithm = outer.nested(_need(outer.tag(0x30)));
  final oid = _need(algorithm.tag(0x06)).copy();
  final secret = _need(outer.tag(0x04)).copy();
  if (_oidIs(oid, _ed25519)) {
    final seed = DerReader(secret);
    final raw = _need(seed.tag(0x04)).copy();
    if (!seed.finished || raw.length != 32) {
      throw const FormatException('Ed25519 seed');
    }
    return PqX509PrivateKey._(
      PqX509Algorithm.ed25519,
      PqX509Ed25519Key(PqEd25519.publicKeyFromSeed(raw)),
      (message) => PqEd25519.sign(secretKey: raw, message: message),
    );
  }
  if (!_oidIs(oid, _ecKey)) throw const FormatException('unsupported PKCS#8');
  final curve = _need(algorithm.tag(0x06)).copy();
  return _ecKeyFromSec1(DerReader(secret), curve);
}

PqX509PrivateKey _ecKeyFromSec1(DerReader reader, Uint8List? curve) {
  final body = reader.nested(_need(reader.tag(0x30)));
  if (!reader.finished) throw const FormatException('EC key trailing bytes');
  final version = _need(body.tag(0x02));
  if (version.length != 1 || version.bytes[version.start] != 1) {
    throw const FormatException('EC key version');
  }
  final scalar = _need(body.tag(0x04)).copy();
  Uint8List? named = curve;
  if (!body.finished && body.bytes[body.offset] == 0xa0) {
    final wrapped = body.nested(_need(body.tag(0xa0)));
    named = _need(wrapped.tag(0x06)).copy();
  }
  if (named == null) throw const FormatException('EC key has no curve');
  final p256 = _oidIs(named, _p256);
  final width = p256
      ? 32
      : _oidIs(named, _p384)
      ? 48
      : throw const FormatException('EC key curve');
  final secret = _leftPad(scalar, width);
  if (p256) {
    final public = PqEcdsaP256.publicKeyFromPrivate(secret);
    return PqX509PrivateKey._(
      PqX509Algorithm.ecdsaP256Sha256,
      PqX509EcdsaP256Key(public),
      (message) => PqX509.encodeEcdsaSignature(
        PqEcdsaP256.sign(privateKey: secret, message: message),
      ),
    );
  }
  final public = PqEcdsaP384.publicKeyFromPrivate(secret);
  return PqX509PrivateKey._(
    PqX509Algorithm.ecdsaP384Sha384,
    PqX509EcdsaP384Key(public),
    (message) => PqX509.encodeEcdsaSignature(
      PqEcdsaP384.sign(privateKey: secret, message: message),
    ),
  );
}

PqX509PrivateKey _rsaKey(DerReader reader) {
  final body = reader.nested(_need(reader.tag(0x30)));
  if (!reader.finished) throw const FormatException('RSA key trailing bytes');
  final version = _need(body.tag(0x02));
  if (version.length != 1 || version.bytes[version.start] != 0) {
    throw const FormatException('RSA key version');
  }
  Uint8List number() {
    final value = unsignedInteger(_need(body.tag(0x02)).copy(), maxBytes: 520);
    if (value == null) throw const FormatException('RSA integer');
    return value;
  }

  final modulus = number();
  final publicExponent = number();
  final privateExponent = number();
  final prime1 = number();
  final prime2 = number();
  final key = PqRsaPrivateKey(
    modulus: modulus,
    privateExponent: privateExponent,
    prime1: prime1,
    prime2: prime2,
    publicExponent: publicExponent,
  );
  return PqX509PrivateKey._(
    PqX509Algorithm.rsaPkcs1Sha256,
    PqX509RsaKey(modulus, publicExponent),
    (message) => PqRsa.signPkcs1(
      privateKey: key,
      message: message,
      hash: PqRsaHash.sha256,
    ),
  );
}

Uint8List _leftPad(Uint8List value, int width) {
  if (value.length > width) {
    throw const FormatException('EC scalar is too wide');
  }
  if (value.length == width) return value;
  final out = Uint8List(width);
  out.setRange(width - value.length, width, value);
  return out;
}
