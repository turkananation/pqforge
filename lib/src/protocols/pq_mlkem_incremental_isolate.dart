/// Runs the braid's ML-KEM split off the caller isolate.
library;

import 'dart:isolate';
import 'dart:typed_data';

import 'pq_mlkem_incremental_core.dart';

Future<List<Uint8List>> mlKem768KeyGenOff(Uint8List seed) =>
    Isolate.run(() => mlKem768KeyGenSync(seed));

Future<List<Uint8List>> mlKem768Encaps1Off(
  Uint8List ekSeed,
  Uint8List hek,
  Uint8List coins,
) => Isolate.run(() => mlKem768Encaps1Sync(ekSeed, hek, coins));

Future<Uint8List> mlKem768Encaps2Off(
  Uint8List encapsSecret,
  Uint8List ekSeed,
  Uint8List ekVector,
) => Isolate.run(() => mlKem768Encaps2Sync(encapsSecret, ekSeed, ekVector));

Future<Uint8List> mlKem768DecapsOff(
  Uint8List decapsulationKey,
  Uint8List ct1,
  Uint8List ct2,
) => Isolate.run(() => mlKem768DecapsSync(decapsulationKey, ct1, ct2));
