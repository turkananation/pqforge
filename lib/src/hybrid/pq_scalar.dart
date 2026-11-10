/// Shared scalar encoding and the Fortuna seed used by classical keygens.
///
/// Every seed is drawn from [PqBytes.randomBytes], so [PqRandom.generator]
/// covers these paths. The Fortuna seed buffer is wiped after
/// `FortunaRandom.seed`, which copies it.
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:zeroize/zeroize.dart';

import '../primitives/pq_primitives.dart';

/// Fortuna seeded from [PqRandom]. The 32-byte seed buffer is wiped.
pc.SecureRandom pqSeededFortuna() {
  final fortuna = pc.FortunaRandom();
  final seed = PqBytes.randomBytes(32);
  try {
    fortuna.seed(pc.KeyParameter(seed));
    return fortuna;
  } finally {
    secureZero(seed);
  }
}

/// Big-endian fixed-width encoding. Extra high bytes are dropped, matching
/// the historical curve and RSA helpers. Callers only pass values that fit.
Uint8List pqFixedBigInt(BigInt value, int length) {
  final out = Uint8List(length);
  final mask = BigInt.from(0xff);
  var remaining = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (remaining & mask).toInt();
    remaining >>= 8;
  }
  return out;
}

/// Big-endian integer. The empty list is zero.
BigInt pqBigIntFromBytes(List<int> bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte & 0xff);
  }
  return result;
}
