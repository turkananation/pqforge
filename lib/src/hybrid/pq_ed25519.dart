/// Synchronous Ed25519 (RFC 8032).
///
/// The field is sixteen 16-bit limbs. A product of two reduced limbs fits in
/// a dart2js-safe integer, which a [BigInt] field multiply does not. [BigInt]
/// is used only to reduce scalars modulo the group order L.
///
/// This is not [PqClassicalProvider.ed25519Verify]. That method returns a
/// [Future]. [verify] is synchronous and does not call it.
///
/// [verify] returns false and does not throw. The 32-byte secret is a seed.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

/// Ed25519 signatures. Secret keys are 32-byte seeds.
class PqEd25519 {
  const PqEd25519._();

  static const int publicKeyBytes = 32;
  static const int secretKeyBytes = 32;
  static const int signatureBytes = 64;

  /// L = 2^252 + 27742317777372353535851937790883648493.
  static final BigInt _order = BigInt.parse(
    '7237005577332262213973186563042994240857116359379907606001950938285454250989',
  );

  static final _Scratch _init = _Scratch();
  static final _Fe _d = _curveD(_init);
  static final _Fe _d2 = _mulSmall(_d, 2, _init);
  static final _Pt _base = _basePoint(_init);

  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() {
    final secret = Uint8List(secretKeyBytes);
    final random = Random.secure();
    for (var i = 0; i < secret.length; i++) {
      secret[i] = random.nextInt(256);
    }
    return (publicKey: publicKeyFromSeed(secret), secretKey: secret);
  }

  /// Public key for a 32-byte seed.
  static Uint8List publicKeyFromSeed(Uint8List seed) {
    if (seed.length != secretKeyBytes) {
      throw ArgumentError.value(seed.length, 'seed', 'expected 32 bytes');
    }
    final hash = _sha512(seed);
    final scalar = Uint8List.sublistView(hash, 0, 32);
    _clamp(scalar);
    final scratch = _Scratch();
    final point = _Pt();
    _ptMul(point, _base, _le(scalar), scratch);
    return _ptCompress(point, scratch);
  }

  /// Signs [message]. The signature is `R || S`, 64 bytes.
  static Uint8List sign({
    required Uint8List secretKey,
    required Uint8List message,
  }) {
    if (secretKey.length != secretKeyBytes) {
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'expected 32 bytes',
      );
    }
    final hash = _sha512(secretKey);
    final scalar = Uint8List.sublistView(hash, 0, 32);
    _clamp(scalar);
    final prefix = Uint8List.sublistView(hash, 32, 64);
    final a = _le(scalar);
    final scratch = _Scratch();
    final point = _Pt();
    _ptMul(point, _base, a, scratch);
    final publicKey = _ptCompress(point, scratch);

    final rHash = _sha512Parts([prefix, message]);
    final r = _le(rHash) % _order;
    _ptMul(point, _base, r, scratch);
    final rBytes = _ptCompress(point, scratch);

    final k = _le(_sha512Parts([rBytes, publicKey, message])) % _order;
    final s = (r + k * a) % _order;
    final out = Uint8List(signatureBytes);
    out.setRange(0, 32, rBytes);
    out.setRange(32, 64, _leBytes(s));
    return out;
  }

  /// Returns false for a bad length, a non-canonical encoding, `S >= L`, or
  /// a signature that does not check.
  static bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    if (publicKey.length != publicKeyBytes ||
        signature.length != signatureBytes) {
      return false;
    }
    final s = _le(Uint8List.sublistView(signature, 32, 64));
    if (s >= _order) return false;
    final scratch = _Scratch();
    final a = _ptDecompress(publicKey, scratch);
    final r = _ptDecompress(Uint8List.sublistView(signature, 0, 32), scratch);
    if (a == null || r == null) return false;
    final k =
        _le(
          _sha512Parts([
            Uint8List.sublistView(signature, 0, 32),
            publicKey,
            message,
          ]),
        ) %
        _order;
    final left = _Pt();
    _ptMul(left, _base, s, scratch);
    final right = _Pt();
    _ptMul(right, a, k, scratch);
    _ptAdd(right, right, r, scratch);
    return _ptEquals(left, right, scratch);
  }

  static _Fe _curveD(_Scratch scratch) {
    final num = _Fe()..setInt(121665);
    _feNeg(num);
    final den = _Fe()..setInt(121666);
    final inv = _Fe();
    _feInvert(inv, den, scratch);
    final d = _Fe();
    _feMul(d, num, inv, scratch);
    _feFreeze(d);
    return d;
  }

  static _Pt _basePoint(_Scratch scratch) {
    final encoded = Uint8List(32);
    encoded[0] = 0x58;
    for (var i = 1; i < 31; i++) {
      encoded[i] = 0x66;
    }
    encoded[31] = 0x66;
    final point = _ptDecompress(encoded, scratch);
    if (point == null) {
      throw StateError('Ed25519 base point did not decode');
    }
    return point;
  }
}

final class _Fe {
  final List<int> l = List<int>.filled(16, 0);

  void zero() {
    for (var i = 0; i < 16; i++) {
      l[i] = 0;
    }
  }

  void setInt(int value) {
    zero();
    l[0] = value;
  }

  void copyFrom(_Fe other) {
    for (var i = 0; i < 16; i++) {
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
}

final class _Scratch {
  final limbA = List<int>.filled(16, 0);
  final limbB = List<int>.filled(16, 0);
  final prod = List<int>.filled(32, 0);
  final t0 = _Fe();
  final t1 = _Fe();
  final t2 = _Fe();
  final t3 = _Fe();
  final t4 = _Fe();
  final t5 = _Fe();
  final t6 = _Fe();
  final t7 = _Fe();
  final p0 = _Pt();
  final p1 = _Pt();
  final p2 = _Pt();
}

void _feNeg(_Fe a) {
  for (var i = 0; i < 16; i++) {
    a.l[i] = -a.l[i];
  }
}

void _feAdd(_Fe out, _Fe a, _Fe b) {
  for (var i = 0; i < 16; i++) {
    out.l[i] = a.l[i] + b.l[i];
  }
}

void _feSub(_Fe out, _Fe a, _Fe b) {
  for (var i = 0; i < 16; i++) {
    out.l[i] = a.l[i] - b.l[i];
  }
}

_Fe _mulSmall(_Fe a, int m, _Scratch scratch) {
  final b = _Fe()..setInt(m);
  final out = _Fe();
  _feMul(out, a, b, scratch);
  _feFreeze(out);
  return out;
}

void _feMul(_Fe out, _Fe a, _Fe b, _Scratch scratch) {
  final aa = scratch.limbA;
  final bb = scratch.limbB;
  for (var i = 0; i < 16; i++) {
    aa[i] = a.l[i];
    bb[i] = b.l[i];
  }
  _carryLimbs(aa);
  _carryLimbs(bb);
  final t = scratch.prod;
  for (var i = 0; i < 32; i++) {
    t[i] = 0;
  }
  for (var i = 0; i < 16; i++) {
    final ai = aa[i];
    for (var j = 0; j < 16; j++) {
      t[i + j] += ai * bb[j];
    }
  }
  for (var i = 31; i >= 16; i--) {
    t[i - 16] += 38 * t[i];
  }
  for (var i = 0; i < 16; i++) {
    out.l[i] = t[i];
  }
  _feCarry(out);
}

void _feFreeze(_Fe a) {
  _feCarry(a);
  if (_geP(a)) _subP(a);
}

bool _geP(_Fe a) {
  const p = <int>[
    0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, //
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff,
  ];
  for (var i = 15; i >= 0; i--) {
    if (a.l[i] > p[i]) return true;
    if (a.l[i] < p[i]) return false;
  }
  return true;
}

void _subP(_Fe a) {
  const p = <int>[
    0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, //
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff,
  ];
  var borrow = 0;
  for (var i = 0; i < 16; i++) {
    final v = a.l[i] - p[i] - borrow;
    if (v < 0) {
      a.l[i] = v + 65536;
      borrow = 1;
    } else {
      a.l[i] = v;
      borrow = 0;
    }
  }
}

void _feCarry(_Fe a) => _carryLimbs(a.l);

void _carryLimbs(List<int> limb) {
  for (var pass = 0; pass < 8; pass++) {
    var carry = 0;
    for (var i = 0; i < 16; i++) {
      var v = limb[i] + carry;
      var c = v ~/ 65536;
      var r = v - c * 65536;
      if (r < 0) {
        c -= 1;
        r += 65536;
      }
      limb[i] = r;
      carry = c;
    }
    if (carry != 0) limb[0] += 38 * carry;
    var done = carry == 0;
    for (var i = 0; i < 16; i++) {
      if (limb[i] < 0 || limb[i] > 65535) done = false;
    }
    if (done) return;
  }
  throw StateError('Ed25519 field carry did not converge');
}

void _feInvert(_Fe out, _Fe a, _Scratch scratch) {
  _fePow(out, a, _pMinus2, scratch);
}

void _fePow(_Fe out, _Fe base, Uint8List expBe, _Scratch scratch) {
  final square = scratch.t6;
  out.setInt(1);
  var started = false;
  for (final byte in expBe) {
    for (var bit = 7; bit >= 0; bit--) {
      final on = ((byte >> bit) & 1) == 1;
      if (!started) {
        if (!on) continue;
        started = true;
        out.copyFrom(base);
        continue;
      }
      _feMul(square, out, out, scratch);
      out.copyFrom(square);
      if (on) {
        _feMul(square, out, base, scratch);
        out.copyFrom(square);
      }
    }
  }
  _feFreeze(out);
}

/// p - 2 = 2^255 - 21, 32-byte big-endian.
final Uint8List _pMinus2 = Uint8List.fromList(<int>[
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xeb,
]);

/// (p + 3) / 8 = 2^252 - 2.
final Uint8List _pPlus3Over8 = Uint8List.fromList(<int>[
  0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
]);

bool _feEquals(_Fe a, _Fe b, _Scratch scratch) {
  scratch.t7.copyFrom(a);
  _feFreeze(scratch.t7);
  final other = scratch.t5..copyFrom(b);
  _feFreeze(other);
  for (var i = 0; i < 16; i++) {
    if (scratch.t7.l[i] != other.l[i]) return false;
  }
  return true;
}

_Pt? _ptDecompress(Uint8List bytes, _Scratch scratch) {
  if (bytes.length != 32) return null;
  final sign = (bytes[31] >> 7) & 1;
  final y = _Fe();
  _feFromBytes(y, bytes);
  _feCarry(y);
  if (_geP(y)) return null;
  final y2 = scratch.t0;
  _feMul(y2, y, y, scratch);
  final u = scratch.t1..copyFrom(y2);
  u.l[0] -= 1;
  final dy2 = scratch.t2;
  _feMul(dy2, PqEd25519._d, y2, scratch);
  final v = scratch.t3..copyFrom(dy2);
  v.l[0] += 1;
  final inv = scratch.t4;
  _feInvert(inv, v, scratch);
  final x2 = _Fe();
  _feMul(x2, u, inv, scratch);
  _fePow(scratch.t0, x2, _pPlus3Over8, scratch);
  final x = _Fe()..copyFrom(scratch.t0);
  _feFreeze(x);
  final xCheck = scratch.t1;
  _feMul(xCheck, x, x, scratch);
  if (!_feEquals(xCheck, x2, scratch)) {
    // x = x * 2^((p-1)/4) when x^2 == -x2.
    final neg = scratch.t2..copyFrom(x2);
    _feNeg(neg);
    if (!_feEquals(xCheck, neg, scratch)) return null;
    final root = _sqrtNeg1(scratch);
    _feMul(scratch.t0, x, root, scratch);
    x.copyFrom(scratch.t0);
    _feFreeze(x);
  }
  if ((x.l[0] & 1) != sign) {
    _feNeg(x);
    _feFreeze(x);
  }
  final point = _Pt();
  point.x.copyFrom(x);
  point.y.copyFrom(y);
  point.z.setInt(1);
  _feMul(point.t, x, y, scratch);
  _feFreeze(point.x);
  _feFreeze(point.y);
  _feFreeze(point.t);
  return point;
}

_Fe _sqrtNeg1(_Scratch scratch) {
  final two = _Fe()..setInt(2);
  final out = _Fe();
  // 2^((p-1)/4) = 2^(2^253 - 5).
  _fePow(out, two, _sqrtNeg1Exp, scratch);
  return out;
}

final Uint8List _sqrtNeg1Exp = Uint8List.fromList(<int>[
  0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb,
]);

void _feFromBytes(_Fe out, Uint8List bytes) {
  out.zero();
  for (var i = 0; i < 16; i++) {
    var value = bytes[i * 2] | (bytes[i * 2 + 1] << 8);
    if (i == 15) value &= 0x7fff;
    out.l[i] = value;
  }
}

Uint8List _feToBytes(_Fe a) {
  final frozen = _Fe()..copyFrom(a);
  _feFreeze(frozen);
  final out = Uint8List(32);
  for (var i = 0; i < 16; i++) {
    out[i * 2] = frozen.l[i] & 0xff;
    out[i * 2 + 1] = (frozen.l[i] >> 8) & 0xff;
  }
  return out;
}

Uint8List _ptCompress(_Pt p, _Scratch scratch) {
  final inv = scratch.t0;
  _feInvert(inv, p.z, scratch);
  final x = scratch.t1;
  final y = scratch.t2;
  _feMul(x, p.x, inv, scratch);
  _feMul(y, p.y, inv, scratch);
  _feFreeze(x);
  _feFreeze(y);
  final out = _feToBytes(y);
  if ((x.l[0] & 1) == 1) out[31] |= 0x80;
  return out;
}

void _ptAdd(_Pt out, _Pt p, _Pt q, _Scratch scratch) {
  final a = scratch.t0;
  final b = scratch.t1;
  _feSub(a, p.y, p.x);
  _feSub(b, q.y, q.x);
  final aMul = scratch.t2;
  _feMul(aMul, a, b, scratch);
  _feAdd(a, p.y, p.x);
  _feAdd(b, q.y, q.x);
  final bMul = scratch.t3;
  _feMul(bMul, a, b, scratch);
  final c = scratch.t4;
  _feMul(a, p.t, q.t, scratch);
  _feMul(c, a, PqEd25519._d2, scratch);
  final d = scratch.t5;
  _feAdd(a, p.z, p.z);
  _feMul(d, a, q.z, scratch);
  final e = scratch.t6;
  _feSub(e, bMul, aMul);
  final f = scratch.t7;
  _feSub(f, d, c);
  final g = scratch.p0.x;
  _feAdd(g, d, c);
  final h = scratch.p0.y;
  _feAdd(h, bMul, aMul);
  _feMul(out.x, e, f, scratch);
  _feMul(out.y, g, h, scratch);
  _feMul(out.t, e, h, scratch);
  _feMul(out.z, f, g, scratch);
}

void _ptDouble(_Pt out, _Pt p, _Scratch scratch) {
  final a = scratch.t0;
  final b = scratch.t1;
  _feMul(a, p.x, p.x, scratch);
  _feMul(b, p.y, p.y, scratch);
  final c = scratch.t2;
  _feMul(c, p.z, p.z, scratch);
  _feAdd(c, c, c);
  final h = scratch.t3;
  _feAdd(h, a, b);
  final e = scratch.t4;
  _feAdd(scratch.t5, p.x, p.y);
  _feMul(e, scratch.t5, scratch.t5, scratch);
  _feSub(e, h, e);
  final g = scratch.t6;
  _feSub(g, a, b);
  final f = scratch.t7;
  _feAdd(f, c, g);
  _feMul(out.x, e, f, scratch);
  _feMul(out.y, g, h, scratch);
  _feMul(out.t, e, h, scratch);
  _feMul(out.z, f, g, scratch);
}

void _ptMul(_Pt out, _Pt base, BigInt scalar, _Scratch scratch) {
  out.setIdentity();
  final bits = _scalarBits(scalar);
  for (var i = 255; i >= 0; i--) {
    _ptDouble(scratch.p1, out, scratch);
    out.x.copyFrom(scratch.p1.x);
    out.y.copyFrom(scratch.p1.y);
    out.z.copyFrom(scratch.p1.z);
    out.t.copyFrom(scratch.p1.t);
    if (((bits[i >> 3] >> (i & 7)) & 1) == 1) {
      _ptAdd(scratch.p1, out, base, scratch);
      out.x.copyFrom(scratch.p1.x);
      out.y.copyFrom(scratch.p1.y);
      out.z.copyFrom(scratch.p1.z);
      out.t.copyFrom(scratch.p1.t);
    }
  }
}

bool _ptEquals(_Pt a, _Pt b, _Scratch scratch) {
  final left = scratch.t0;
  final right = scratch.t1;
  _feMul(left, a.x, b.z, scratch);
  _feMul(right, b.x, a.z, scratch);
  if (!_feEquals(left, right, scratch)) return false;
  _feMul(left, a.y, b.z, scratch);
  _feMul(right, b.y, a.z, scratch);
  return _feEquals(left, right, scratch);
}

Uint8List _scalarBits(BigInt scalar) => _leBytes(scalar);

void _clamp(Uint8List scalar) {
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
}

BigInt _le(Uint8List bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

Uint8List _leBytes(BigInt value) {
  final out = Uint8List(32);
  var remaining = value;
  final mask = BigInt.from(0xff);
  for (var i = 0; i < 32; i++) {
    out[i] = (remaining & mask).toInt();
    remaining >>= 8;
  }
  return out;
}

Uint8List _sha512(Uint8List data) => pc.SHA512Digest().process(data);

Uint8List _sha512Parts(List<Uint8List> parts) {
  final digest = pc.SHA512Digest();
  for (final part in parts) {
    digest.update(part, 0, part.length);
  }
  final out = Uint8List(64);
  digest.doFinal(out, 0);
  return out;
}
