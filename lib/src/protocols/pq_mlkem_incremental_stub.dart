/// In-process ML-KEM split. dart2wasm has no `dart:isolate`.
library;

import 'dart:typed_data';

import 'pq_mlkem_incremental_core.dart';

Future<List<Uint8List>> mlKem768KeyGenOff(Uint8List seed) async =>
    mlKem768KeyGenSync(seed);

Future<List<Uint8List>> mlKem768Encaps1Off(
  Uint8List ekSeed,
  Uint8List hek,
  Uint8List coins,
) async => mlKem768Encaps1Sync(ekSeed, hek, coins);

Future<Uint8List> mlKem768Encaps2Off(
  Uint8List encapsSecret,
  Uint8List ekSeed,
  Uint8List ekVector,
) async => mlKem768Encaps2Sync(encapsSecret, ekSeed, ekVector);

Future<Uint8List> mlKem768DecapsOff(
  Uint8List decapsulationKey,
  Uint8List ct1,
  Uint8List ct2,
) async => mlKem768DecapsSync(decapsulationKey, ct1, ct2);
