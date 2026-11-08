/// Synchronous Ed448 (RFC 8032). Pure Ed448, not Ed448ph, unless [preHash]
/// is set. DNSSEC algorithm 16 and the usual callers use the empty context.
///
/// The field is twenty-eight 16-bit limbs. A product of two reduced limbs
/// fits in a dart2js-safe integer, which a [BigInt] field multiply does not.
/// [BigInt] is used only to reduce scalars modulo the group order L.
///
/// [verify] returns false and does not throw. The 57-byte secret is a seed.
/// The expanded scalar and prefix are wiped. The [BigInt] scalar is not.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:zeroize/zeroize.dart';

/// Ed448 signatures. Secret keys are 57-byte seeds.
class PqEd448 {
  const PqEd448._();

  static const int publicKeyBytes = 57;
  static const int secretKeyBytes = 57;
  static const int signatureBytes = 114;

  /// SHAKE256 length of an Ed448ph prehash (RFC 8032 §5.2).
  static const int preHashBytes = 64;

  /// L = 2^446 − 13818066809895115352007386748515426880336692474882178609894547503885.
  static final BigInt _order = BigInt.parse(
    '3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3',
    radix: 16,
  );

  static final _Scratch _init = _Scratch();
  static final _Fe _d = _curveD();
  static final _Pt _base = _basePoint(_init);

  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() {
    final secret = Uint8List(secretKeyBytes);
    final random = Random.secure();
    for (var i = 0; i < secret.length; i++) {
      secret[i] = random.nextInt(256);
    }
    return (publicKey: publicKeyFromSeed(secret), secretKey: secret);
  }

  /// Public key for a 57-byte seed.
  static Uint8List publicKeyFromSeed(Uint8List seed) {
    if (seed.length != secretKeyBytes) {
      throw ArgumentError.value(seed.length, 'seed', 'expected 57 bytes');
    }
    final hash = _shake256([seed], signatureBytes);
    try {
      _clamp(hash);
      final scratch = _Scratch();
      final point = _Pt();
      _ptMul(point, _base, _le(Uint8List.sublistView(hash, 0, 57)), scratch);
      return _ptCompress(point, scratch);
    } finally {
      hash.secureZeroize();
    }
  }

  /// Signs [message]. The signature is `R || S`, 114 bytes.
  ///
  /// [context] is the RFC 8032 context, at most 255 bytes. DNSSEC uses the
  /// empty context. [preHash] selects Ed448ph: both sides hash with
  /// SHAKE256 to 64 bytes before the signature.
  static Uint8List sign({
    required Uint8List secretKey,
    required Uint8List message,
    Uint8List? context,
    bool preHash = false,
  }) {
    if (secretKey.length != secretKeyBytes) {
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'expected 57 bytes',
      );
    }
    final ctx = _context(context);
    final hash = _shake256([secretKey], signatureBytes);
    try {
      final scalarBytes = Uint8List.sublistView(hash, 0, 57);
      _clamp(hash);
      final prefix = Uint8List.sublistView(hash, 57, 114);
      final a = _le(scalarBytes);
      final scratch = _Scratch();
      final point = _Pt();
      _ptMul(point, _base, a, scratch);
      final publicKey = _ptCompress(point, scratch);
      final signed = preHash ? _shake256([message], preHashBytes) : message;
      final dom = _dom4(preHash: preHash, context: ctx);

      final r = _le(_shake256([dom, prefix, signed], signatureBytes)) % _order;
      _ptMul(point, _base, r, scratch);
      final rBytes = _ptCompress(point, scratch);

      final k =
          _le(_shake256([dom, rBytes, publicKey, signed], signatureBytes)) %
          _order;
      final s = (r + k * a) % _order;
      final out = Uint8List(signatureBytes);
      out.setRange(0, 57, rBytes);
      out.setRange(57, 114, _leBytes(s, 57));
      return out;
    } finally {
      hash.secureZeroize();
    }
  }

  /// Returns false for a bad length, a non-canonical encoding, `S >= L`, or
  /// a signature that does not check.
  static bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
    Uint8List? context,
    bool preHash = false,
  }) {
    if (publicKey.length != publicKeyBytes ||
        signature.length != signatureBytes) {
      return false;
    }
    if (context != null && context.length > 255) return false;
    final s = _le(Uint8List.sublistView(signature, 57, 114));
    if (s >= _order) return false;
    final scratch = _Scratch();
    final a = _ptDecompress(publicKey, scratch);
    final r = _ptDecompress(Uint8List.sublistView(signature, 0, 57), scratch);
    if (a == null || r == null) return false;
    final ctx = context ?? Uint8List(0);
    final signed = preHash ? _shake256([message], preHashBytes) : message;
    final dom = _dom4(preHash: preHash, context: ctx);
    final k =
        _le(
          _shake256([
            dom,
            Uint8List.sublistView(signature, 0, 57),
            publicKey,
            signed,
          ], signatureBytes),
        ) %
        _order;
    final left = _Pt();
    _ptMul(left, _base, s, scratch);
    final right = _Pt();
    _ptMul(right, a, k, scratch);
    _ptAdd(right, right, r, scratch);
    return _ptEquals(left, right, scratch);
  }
}

_Fe _curveD() {
  final d = _Fe()..setInt(39081);
  _feNeg(d);
  _feFreeze(d);
  return d;
}

_Pt _basePoint(_Scratch scratch) {
  // RFC 8032 / RFC 7748 Goldilocks base, x sign bit clear.
  const gx =
      '4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e';
  const gy =
      '693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14';
  final point = _Pt();
  point.x.copyFrom(_feFromBeHex(gx));
  point.y.copyFrom(_feFromBeHex(gy));
  point.z.setInt(1);
  _feMul(point.t, point.x, point.y, scratch);
  _feFreeze(point.t);
  return point;
}

Uint8List _context(Uint8List? context) {
  final ctx = context ?? Uint8List(0);
  if (ctx.length > 255) {
    throw ArgumentError.value(ctx.length, 'context', 'at most 255 bytes');
  }
  return ctx;
}

/// "SigEd448" || phflag || context length || context.
Uint8List _dom4({required bool preHash, required Uint8List context}) {
  final out = Uint8List(10 + context.length);
  const prefix = <int>[
    0x53, 0x69, 0x67, 0x45, 0x64, 0x34, 0x34, 0x38, // SigEd448
  ];
  out.setRange(0, 8, prefix);
  out[8] = preHash ? 1 : 0;
  out[9] = context.length;
  out.setRange(10, out.length, context);
  return out;
}

final class _Fe {
  final List<int> l = List<int>.filled(28, 0);

  void zero() {
    for (var i = 0; i < 28; i++) {
      l[i] = 0;
    }
  }

  void setInt(int value) {
    zero();
    l[0] = value;
  }

  void copyFrom(_Fe other) {
    for (var i = 0; i < 28; i++) {
      l[i] = other.l[i];
    }
  }
}

final class _Pt {
  final x = _Fe();
  final y = _Fe();
  final z = _Fe();
  final t = _Fe();

  void setIdentity() {
    x.zero();
    y
      ..zero()
      ..l[0] = 1;
    z
      ..zero()
      ..l[0] = 1;
    t.zero();
  }

  void copyFrom(_Pt other) {
    x.copyFrom(other.x);
    y.copyFrom(other.y);
    z.copyFrom(other.z);
    t.copyFrom(other.t);
  }
}

final class _Scratch {
  final limbA = List<int>.filled(28, 0);
  final limbB = List<int>.filled(28, 0);
  final wide = List<int>.filled(60, 0);
  final t = List<_Fe>.generate(10, (_) => _Fe());
  final chain = List<_Fe>.generate(14, (_) => _Fe());
  final sq = _Fe();
  final p1 = _Pt();
}

/// p = 2^448 − 2^224 − 1, as 16-bit limbs.
const List<int> _pLimbs = <int>[
  0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, //
  0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
  0xfffe, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
  0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
];

void _feNeg(_Fe a) {
  for (var i = 0; i < 28; i++) {
    a.l[i] = -a.l[i];
  }
}

void _feAdd(_Fe out, _Fe a, _Fe b) {
  for (var i = 0; i < 28; i++) {
    out.l[i] = a.l[i] + b.l[i];
  }
}

void _feSub(_Fe out, _Fe a, _Fe b) {
  for (var i = 0; i < 28; i++) {
    out.l[i] = a.l[i] - b.l[i];
  }
}

void _feMul(_Fe out, _Fe a, _Fe b, _Scratch scratch) {
  final aa = scratch.limbA;
  final bb = scratch.limbB;
  for (var i = 0; i < 28; i++) {
    aa[i] = a.l[i];
    bb[i] = b.l[i];
  }
  _carry28(aa);
  _carry28(bb);
  final t = scratch.wide;
  for (var i = 0; i < t.length; i++) {
    t[i] = 0;
  }
  for (var i = 0; i < 28; i++) {
    final ai = aa[i];
    for (var j = 0; j < 28; j++) {
      t[i + j] += ai * bb[j];
    }
  }
  _reduceWide(t);
  for (var i = 0; i < 28; i++) {
    out.l[i] = t[i];
  }
  _feFreeze(out);
}

void _reduceWide(List<int> limb) {
  _carryWide(limb);
  for (var round = 0; round < 8; round++) {
    var high = false;
    for (var i = 28; i < limb.length; i++) {
      if (limb[i] != 0) {
        high = true;
        break;
      }
    }
    if (!high) return;
    final hi = List<int>.filled(limb.length - 28, 0);
    for (var i = 0; i < hi.length; i++) {
      hi[i] = limb[28 + i];
      limb[28 + i] = 0;
    }
    // 2^448 ≡ 2^224 + 1, and 224 bits is 14 limbs.
    for (var i = 0; i < hi.length; i++) {
      limb[i] += hi[i];
      final shifted = 14 + i;
      if (shifted >= limb.length) {
        throw StateError('Ed448 reduction overflow');
      }
      limb[shifted] += hi[i];
    }
    _carryWide(limb);
  }
  throw StateError('Ed448 reduction did not converge');
}

void _feFreeze(_Fe a) {
  _carry28(a.l);
  for (var i = 0; i < 4; i++) {
    if (!_geP(a)) return;
    _subP(a);
  }
  if (_geP(a)) throw StateError('Ed448 field did not reduce');
}

bool _geP(_Fe a) {
  for (var i = 27; i >= 0; i--) {
    if (a.l[i] > _pLimbs[i]) return true;
    if (a.l[i] < _pLimbs[i]) return false;
  }
  return true;
}

void _subP(_Fe a) {
  var borrow = 0;
  for (var i = 0; i < 28; i++) {
    final v = a.l[i] - _pLimbs[i] - borrow;
    if (v < 0) {
      a.l[i] = v + 65536;
      borrow = 1;
    } else {
      a.l[i] = v;
      borrow = 0;
    }
  }
}

void _carry28(List<int> limb) {
  for (var pass = 0; pass < 12; pass++) {
    var carry = 0;
    for (var i = 0; i < 28; i++) {
      final reduced = _digit(limb[i] + carry);
      limb[i] = reduced.$1;
      carry = reduced.$2;
    }
    if (carry != 0) {
      // carry * 2^448 ≡ carry + carry * 2^224.
      limb[0] += carry;
      limb[14] += carry;
      continue;
    }
    var done = true;
    for (var i = 0; i < 28; i++) {
      if (limb[i] < 0 || limb[i] > 65535) done = false;
    }
    if (done) return;
  }
  throw StateError('Ed448 field carry did not converge');
}

void _carryWide(List<int> limb) {
  var carry = 0;
  for (var i = 0; i < limb.length; i++) {
    final reduced = _digit(limb[i] + carry);
    limb[i] = reduced.$1;
    carry = reduced.$2;
  }
  if (carry != 0) throw StateError('Ed448 wide carry overflow');
}

(int, int) _digit(int value) {
  var c = value ~/ 65536;
  var r = value - c * 65536;
  if (r < 0) {
    c -= 1;
    r += 65536;
  }
  return (r, c);
}

void _feInvert(_Fe out, _Fe a, _Scratch scratch) {
  // a^(p-2) = (a^((p-3)/4))^4 * a.
  _fePowPminus3div4(scratch.chain[0], a, scratch);
  _feMul(scratch.chain[1], scratch.chain[0], scratch.chain[0], scratch);
  _feMul(scratch.chain[0], scratch.chain[1], scratch.chain[1], scratch);
  _feMul(out, scratch.chain[0], a, scratch);
}

/// x^((p-3)/4) mod p. Addition chain from the Goldilocks square root.
void _fePowPminus3div4(_Fe out, _Fe x, _Scratch s) {
  final b2 = s.chain[2];
  final b3 = s.chain[3];
  final b6 = s.chain[4];
  final b9 = s.chain[5];
  final b11 = s.chain[6];
  final b22 = s.chain[7];
  final b44 = s.chain[8];
  final b88 = s.chain[9];
  final b176 = s.chain[10];
  final b220 = s.chain[11];
  final b222 = s.chain[12];
  final b223 = s.chain[13];
  _feMul(b2, x, x, s);
  _feMul(b2, b2, x, s);
  _feMul(b3, b2, b2, s);
  _feMul(b3, b3, x, s);
  _feSqn(b6, b3, 3, s);
  _feMul(b6, b6, b3, s);
  _feSqn(b9, b6, 3, s);
  _feMul(b9, b9, b3, s);
  _feSqn(b11, b9, 2, s);
  _feMul(b11, b11, b2, s);
  _feSqn(b22, b11, 11, s);
  _feMul(b22, b22, b11, s);
  _feSqn(b44, b22, 22, s);
  _feMul(b44, b44, b22, s);
  _feSqn(b88, b44, 44, s);
  _feMul(b88, b88, b44, s);
  _feSqn(b176, b88, 88, s);
  _feMul(b176, b176, b88, s);
  _feSqn(b220, b176, 44, s);
  _feMul(b220, b220, b44, s);
  _feSqn(b222, b220, 2, s);
  _feMul(b222, b222, b2, s);
  _feSqn(b223, b222, 1, s);
  _feMul(b223, b223, x, s);
  _feSqn(out, b223, 223, s);
  _feMul(out, out, b222, s);
}

void _feSqn(_Fe out, _Fe base, int n, _Scratch scratch) {
  out.copyFrom(base);
  for (var i = 0; i < n; i++) {
    _feMul(scratch.sq, out, out, scratch);
    out.copyFrom(scratch.sq);
  }
}

bool _feIsZero(_Fe a) {
  for (var i = 0; i < 28; i++) {
    if (a.l[i] != 0) return false;
  }
  return true;
}

bool _feEquals(_Fe a, _Fe b, _Scratch scratch) {
  scratch.t[7].copyFrom(a);
  _feFreeze(scratch.t[7]);
  scratch.t[8].copyFrom(b);
  _feFreeze(scratch.t[8]);
  for (var i = 0; i < 28; i++) {
    if (scratch.t[7].l[i] != scratch.t[8].l[i]) return false;
  }
  return true;
}

_Fe _feFromBeHex(String hex) {
  if (hex.length != 112 || hex.length.isOdd) {
    throw StateError('Ed448 coordinate');
  }
  final be = Uint8List(56);
  for (var i = 0; i < 56; i++) {
    be[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  final le = Uint8List(57);
  for (var i = 0; i < 56; i++) {
    le[i] = be[55 - i];
  }
  final out = _Fe();
  _feFromBytes(out, le);
  return out;
}

void _feFromBytes(_Fe out, Uint8List bytes) {
  out.zero();
  for (var i = 0; i < 28; i++) {
    out.l[i] = bytes[i * 2] | (bytes[i * 2 + 1] << 8);
  }
}

Uint8List _feToBytes(_Fe a) {
  final frozen = _Fe()..copyFrom(a);
  _feFreeze(frozen);
  final out = Uint8List(57);
  for (var i = 0; i < 28; i++) {
    out[i * 2] = frozen.l[i] & 0xff;
    out[i * 2 + 1] = (frozen.l[i] >> 8) & 0xff;
  }
  return out;
}

/// RFC 8032 §5.2.3. Fails closed on a non-canonical encoding or a point
/// that is not on the curve. `a = 1`, so `x^2 = (y^2 - 1) / (d y^2 - 1)`.
_Pt? _ptDecompress(Uint8List bytes, _Scratch scratch) {
  if (bytes.length != 57) return null;
  if ((bytes[56] & 0x7f) != 0) return null;
  final sign = (bytes[56] >> 7) & 1;
  final y = _Fe();
  _feFromBytes(y, bytes);
  if (_geP(y)) return null;
  final y2 = scratch.t[0];
  _feMul(y2, y, y, scratch);
  final u = scratch.t[1];
  u.copyFrom(y2);
  u.l[0] -= 1;
  final v = scratch.t[2];
  _feMul(v, PqEd448._d, y2, scratch);
  v.l[0] -= 1;
  // x = u^3 v (u^5 v^3)^((p-3)/4).
  final u2v = scratch.t[3];
  _feMul(u2v, u, u, scratch);
  _feMul(u2v, u2v, v, scratch);
  final u3v = scratch.t[4];
  _feMul(u3v, u2v, u, scratch);
  final u5v3 = scratch.t[5];
  _feMul(u5v3, u3v, u2v, scratch);
  _feMul(u5v3, u5v3, v, scratch);
  final root = scratch.t[6];
  _fePowPminus3div4(root, u5v3, scratch);
  final x = _Fe();
  _feMul(x, u3v, root, scratch);
  _feFreeze(x);
  final x2 = scratch.t[3];
  _feMul(x2, x, x, scratch);
  final check = scratch.t[4];
  _feMul(check, x2, v, scratch);
  if (!_feEquals(check, u, scratch)) return null;
  if (_feIsZero(x) && sign == 1) return null;
  if ((x.l[0] & 1) != sign) {
    _feNeg(x);
    _feFreeze(x);
  }
  final point = _Pt();
  point.x.copyFrom(x);
  point.y.copyFrom(y);
  point.z.setInt(1);
  _feMul(point.t, x, y, scratch);
  return point;
}

Uint8List _ptCompress(_Pt p, _Scratch scratch) {
  final inv = scratch.t[0];
  _feInvert(inv, p.z, scratch);
  final x = scratch.t[1];
  final y = scratch.t[2];
  _feMul(x, p.x, inv, scratch);
  _feMul(y, p.y, inv, scratch);
  _feFreeze(x);
  _feFreeze(y);
  final out = _feToBytes(y);
  if ((x.l[0] & 1) == 1) out[56] |= 0x80;
  return out;
}

/// Extended twisted Edwards, a = 1.
/// https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
void _ptAdd(_Pt out, _Pt p, _Pt q, _Scratch s) {
  final a = s.t[0];
  _feMul(a, p.x, q.x, s);
  final b = s.t[1];
  _feMul(b, p.y, q.y, s);
  final c = s.t[2];
  _feMul(c, p.t, q.t, s);
  _feMul(c, c, PqEd448._d, s);
  final d = s.t[3];
  _feMul(d, p.z, q.z, s);
  _feAdd(s.t[7], p.x, p.y);
  _feAdd(s.t[8], q.x, q.y);
  final e = s.t[4];
  _feMul(e, s.t[7], s.t[8], s);
  _feSub(e, e, a);
  _feSub(e, e, b);
  final f = s.t[5];
  _feSub(f, d, c);
  final g = s.t[6];
  _feAdd(g, d, c);
  final h = s.t[9];
  _feSub(h, b, a);
  _feMul(out.x, e, f, s);
  _feMul(out.y, g, h, s);
  _feMul(out.t, e, h, s);
  _feMul(out.z, f, g, s);
}

/// https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
void _ptDouble(_Pt out, _Pt p, _Scratch s) {
  final a = s.t[0];
  _feMul(a, p.x, p.x, s);
  final b = s.t[1];
  _feMul(b, p.y, p.y, s);
  final c = s.t[2];
  _feMul(c, p.z, p.z, s);
  _feAdd(c, c, c);
  final sum = s.t[3];
  _feAdd(sum, p.x, p.y);
  final e = s.t[4];
  _feMul(e, sum, sum, s);
  _feSub(e, e, a);
  _feSub(e, e, b);
  final g = s.t[5];
  _feAdd(g, a, b);
  final f = s.t[6];
  _feSub(f, g, c);
  final h = s.t[7];
  _feSub(h, a, b);
  _feMul(out.x, e, f, s);
  _feMul(out.y, g, h, s);
  _feMul(out.t, e, h, s);
  _feMul(out.z, f, g, s);
}

void _ptMul(_Pt out, _Pt base, BigInt scalar, _Scratch scratch) {
  out.setIdentity();
  if (scalar.isNegative) {
    throw ArgumentError.value(scalar, 'scalar', 'negative');
  }
  final bits = _leBytes(scalar, 57);
  for (var i = 447; i >= 0; i--) {
    _ptDouble(scratch.p1, out, scratch);
    out.copyFrom(scratch.p1);
    if (((bits[i >> 3] >> (i & 7)) & 1) == 1) {
      _ptAdd(scratch.p1, out, base, scratch);
      out.copyFrom(scratch.p1);
    }
  }
}

bool _ptEquals(_Pt a, _Pt b, _Scratch scratch) {
  final left = scratch.t[0];
  final right = scratch.t[1];
  _feMul(left, a.x, b.z, scratch);
  _feMul(right, b.x, a.z, scratch);
  if (!_feEquals(left, right, scratch)) return false;
  _feMul(left, a.y, b.z, scratch);
  _feMul(right, b.y, a.z, scratch);
  return _feEquals(left, right, scratch);
}

void _clamp(Uint8List hash) {
  hash[0] &= 252;
  hash[55] |= 128;
  hash[56] = 0;
}

BigInt _le(Uint8List bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

Uint8List _leBytes(BigInt value, int length) {
  final out = Uint8List(length);
  var remaining = value;
  final mask = BigInt.from(0xff);
  for (var i = 0; i < length; i++) {
    out[i] = (remaining & mask).toInt();
    remaining >>= 8;
  }
  return out;
}

Uint8List _shake256(List<Uint8List> parts, int outLen) {
  final digest = pc.SHAKEDigest(256);
  for (final part in parts) {
    digest.update(part, 0, part.length);
  }
  final out = Uint8List(outLen);
  digest.doFinalRange(out, 0, outLen);
  return out;
}
