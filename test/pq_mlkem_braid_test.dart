import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart' as pqc;
import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  tearDown(PqFipsMode.disable);

  test('Reed-Solomon recovers a dropped 32-byte chunk', () {
    final message = Uint8List.fromList(List<int>.generate(64, (i) => i));
    final encoder = BraidErasure.encoder(message);
    final first = encoder.next();
    final second = encoder.next();
    final parity = encoder.next();
    expect(first.index, 0);
    expect(first.bytes, message.sublist(0, 32));
    expect(second.bytes, message.sublist(32));
    expect(
      parity.bytes,
      Uint8List.fromList(
        _hex(
          '7be084e085e17ae187e378e379e286e283e77ce77de682e67fe480e481e57ee5',
        ),
      ),
    );

    final decoder = BraidErasure.decoder(message.length);
    decoder.add(first);
    decoder.add(parity);
    expect(decoder.isComplete, isTrue);
    decoder.add(encoder.next());
    expect(decoder.message(), message);

    final rebuilt = BraidErasure.decoder(message.length);
    rebuilt.add(second);
    rebuilt.add(parity);
    rebuilt.add(BraidChunk(0, first.bytes));
    expect(rebuilt.message(), message);
    rebuilt.add(BraidChunk(0, first.bytes));
    expect(() => rebuilt.add(BraidChunk(0, Uint8List(32))), throwsStateError);
  });

  test('Encaps1 matches Indcpa and not a full encapsulate', () async {
    final seed = _count(64, 1);
    final coins = _count(32, 0xA0);
    final keys = await MlKemIncremental.keyGen(seed: seed);
    final spec = await MlKemIncremental.encaps1(
      ekSeed: keys.ekSeed,
      hek: keys.hek,
      coins: coins,
    );
    final ct2 = await MlKemIncremental.encaps2(
      encapsSecret: spec.encapsSecret,
      ekSeed: keys.ekSeed,
      ekVector: keys.ekVector,
    );
    final raw = await MlKemIncremental.decaps(
      decapsulationKey: keys.decapsulationKey,
      ct1: spec.ct1,
      ct2: ct2,
    );
    expect(raw, spec.sharedSecret);
    expect(spec.ct1.length, MlKemIncremental.ct1Bytes);
    expect(ct2.length, MlKemIncremental.ct2Bytes);

    final pk = Uint8List(1184)
      ..setRange(0, 1152, keys.ekVector)
      ..setRange(1152, 1184, keys.ekSeed);
    final specHek = pqc.sha3256(_join([keys.ekSeed, keys.ekVector]));
    final fipsHek = pqc.sha3256(pk);
    expect(keys.hek, specHek);
    expect(fipsHek, isNot(specHek));

    final fips = await MlKemIncremental.encaps1(
      ekSeed: keys.ekSeed,
      hek: fipsHek,
      coins: coins,
    );
    final fipsCt2 = await MlKemIncremental.encaps2(
      encapsSecret: fips.encapsSecret,
      ekSeed: keys.ekSeed,
      ekVector: keys.ekVector,
    );
    final (ct, ss) = pqc.PqcKem.kyber768.encapsulate(pk, coins);
    expect(_join([fips.ct1, fipsCt2]), ct);
    expect(fips.sharedSecret, ss);
    expect(spec.sharedSecret, isNot(ss));
    expect(pqc.PqcKem.kyber768.decapsulate(keys.decapsulationKey, ct), ss);
    expect(
      pqc.PqcKem.kyber768.decapsulate(
        keys.decapsulationKey,
        _join([spec.ct1, ct2]),
      ),
      isNot(raw),
    );
    keys.wipe();
    spec.wipe();
    fips.wipe();
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a braid epoch matches KDF_OK and survives one lost chunk', () async {
    final secret = _count(32, 4);
    final seed = _count(64, 1);
    final coins = _count(32, 0xA0);
    final alice = MlKemBraid.alice(secret, randomBytes: (_) => seed);
    final bob = MlKemBraid.bob(secret, randomBytes: (_) => coins);
    final keys = await _pump(alice, bob);
    final independent = await _epochSecret(seed, coins);
    expect(keys.$1, independent);
    expect(keys.$2, independent);

    final againA = MlKemBraid.alice(secret, randomBytes: (_) => seed);
    final againB = MlKemBraid.bob(secret, randomBytes: (_) => coins);
    final dropped = await _pump(againA, againB, dropHeaderIndex: 1);
    expect(dropped.$1, independent);
    expect(dropped.$2, independent);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a bad header MAC closes the braid', () async {
    final secret = _count(32, 8);
    final alice = MlKemBraid.alice(secret, randomBytes: (_) => _count(64, 3));
    final bob = MlKemBraid.bob(secret, randomBytes: (_) => _count(32, 5));
    final first = await alice.send();
    final flipped = Uint8List.fromList(first.message.chunk!);
    flipped[0] ^= 1;
    await bob.receive(
      BraidMessage(
        epoch: first.message.epoch,
        type: first.message.type,
        index: first.message.index,
        chunk: flipped,
      ),
    );
    final second = await alice.send();
    await bob.receive(second.message);
    final third = await alice.send();
    await expectLater(
      bob.receive(third.message),
      throwsA(isA<PqForgeException>()),
    );
    expect(bob.isClosed, isTrue);
    await expectLater(bob.send(), throwsA(isA<PqForgeException>()));
  });

  test('old SPQR chain key does not derive the next epoch', () {
    final root = SpqrKdf.chainStart(_count(32, 9));
    final next = SpqrKdf.addEpoch(root: root.root, sckaOutput: _count(32, 2));
    expect(next.root, isNot(root.root));
    final before = SpqrKdf.chainKey(root.sender, counter: 1);
    final after = SpqrKdf.chainKey(next.sender, counter: 1);
    expect(after.message, isNot(before.message));
    final split = SpqrKdf.split(_count(32, 9));
    expect(split.elliptic, isNot(split.braid));
    expect(SpqrKem.values, [SpqrKem.mlKem768]);
  });

  test(
    'Triple Ratchet heals with X25519 and then mixes one braid epoch',
    () async {
      final secret = SharedSecret32(_count(32, 11));
      final parts = SpqrKdf.split(secret.bytes);
      final aliceKey = await RatchetKeyPair.generate(seed: _count(32, 12));
      final bobKey = await RatchetKeyPair.generate(seed: _count(32, 13));
      Uint8List coins(int n) => n == 64 ? _count(64, 1) : _count(n, 0xA0);
      Future<RatchetKeyPair> aliceKeys(int step) =>
          RatchetKeyPair.generate(seed: _count(32, 40 + step));
      Future<RatchetKeyPair> bobKeys(int step) =>
          RatchetKeyPair.generate(seed: _count(32, 90 + step));
      final alice = await TripleRatchet.initiate(
        sharedSecret: secret,
        remoteRatchetKey: bobKey.publicKey,
        ratchetKey: aliceKey,
        randomBytes: coins,
        ratchetKeys: aliceKeys,
      );
      final bob = TripleRatchet.accept(
        sharedSecret: secret,
        ratchetKey: bobKey,
        randomBytes: coins,
        ratchetKeys: bobKeys,
      );
      final fork = TripleRatchet.accept(
        sharedSecret: secret,
        ratchetKey: bobKey,
        randomBytes: coins,
        ratchetKeys: bobKeys,
      );
      final drAlice = await DoubleRatchet.initiate(
        sharedSecret: SharedSecret32(parts.elliptic),
        remoteRatchetKey: bobKey.publicKey,
        info: TripleRatchet.ellipticInfo,
        ratchetKey: aliceKey,
        ratchetKeys: aliceKeys,
      );
      final drBob = DoubleRatchet.accept(
        sharedSecret: SharedSecret32(parts.elliptic),
        ratchetKey: bobKey,
        info: TripleRatchet.ellipticInfo,
        ratchetKeys: bobKeys,
      );

      Future<TripleRatchetMessage> round(
        String text, {
        TripleRatchet? also,
      }) async {
        final plain = utf8.encode(text);
        final message = await alice.seal(Uint8List.fromList(plain));
        final classic = drAlice.seal(Uint8List.fromList(plain));
        expect(message.dh, classic.dh.bytes);
        expect(message.pn, classic.pn);
        expect(message.n, classic.n);
        expect(message.ciphertext, isNot(classic.ciphertext));
        expect(await bob.open(message), plain);
        if (also != null) expect(await also.open(message), plain);
        expect(await drBob.open(classic), plain);
        final reply = utf8.encode('r$text');
        final back = await bob.seal(Uint8List.fromList(reply));
        final classicBack = drBob.seal(Uint8List.fromList(reply));
        expect(back.dh, classicBack.dh.bytes);
        expect(await alice.open(back), reply);
        expect(await drAlice.open(classicBack), reply);
        return message;
      }

      await round('one', also: fork);
      await round('two', also: fork);
      TripleRatchetMessage? last;
      for (var i = 0; i < 80; i++) {
        last = await round('m$i');
      }
      await expectLater(fork.open(last!), throwsA(isA<Exception>()));
      alice.wipe();
      expect(alice.seal(Uint8List(1)), throwsStateError);
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  test('ChaCha works and FIPS mode refuses it', () async {
    final secret = SharedSecret32(_count(32, 15));
    final bobKey = await RatchetKeyPair.generate();
    final alice = await TripleRatchet.initiate(
      sharedSecret: secret,
      remoteRatchetKey: bobKey.publicKey,
      suite: PqForgeCipherSuite.chaCha20Poly1305,
    );
    final bob = TripleRatchet.accept(
      sharedSecret: secret,
      ratchetKey: bobKey,
      suite: PqForgeCipherSuite.chaCha20Poly1305,
    );
    final message = await alice.seal(utf8.encode('chacha'));
    expect(await bob.open(message), utf8.encode('chacha'));
    final tampered = Uint8List.fromList(message.bytes);
    tampered[tampered.length - 1] ^= 1;
    await expectLater(
      bob.open(TripleRatchetMessage.parse(tampered)),
      throwsA(isA<PqForgeAuthTagException>()),
    );

    PqFipsMode.enable();
    expect(
      () => TripleRatchet.initiate(
        sharedSecret: secret,
        remoteRatchetKey: bobKey.publicKey,
        suite: PqForgeCipherSuite.chaCha20Poly1305,
      ),
      throwsA(isA<PqForgeException>()),
    );
  });
}

Future<(Uint8List, Uint8List)> _pump(
  MlKemBraid alice,
  MlKemBraid bob, {
  int? dropHeaderIndex,
}) async {
  Uint8List? aliceKey;
  Uint8List? bobKey;
  var dropped = false;
  for (
    var step = 0;
    step < 250 && (aliceKey == null || bobKey == null);
    step++
  ) {
    final sent = await alice.send();
    if (sent.output != null) aliceKey = Uint8List.fromList(sent.output!.key);
    final drop =
        !dropped &&
        dropHeaderIndex != null &&
        sent.message.type == BraidMessageType.hdr &&
        sent.message.index == dropHeaderIndex;
    if (drop) {
      dropped = true;
    } else {
      final got = await bob.receive(sent.message);
      if (got.output != null) bobKey = Uint8List.fromList(got.output!.key);
    }
    final reply = await bob.send();
    if (reply.output != null) bobKey = Uint8List.fromList(reply.output!.key);
    final back = await alice.receive(reply.message);
    if (back.output != null) aliceKey = Uint8List.fromList(back.output!.key);
  }
  expect(dropped || dropHeaderIndex == null, isTrue);
  expect(aliceKey, isNotNull, reason: '${alice.phase} / ${bob.phase}');
  expect(bobKey, isNotNull, reason: '${alice.phase} / ${bob.phase}');
  return (aliceKey!, bobKey!);
}

Future<Uint8List> _epochSecret(Uint8List seed, Uint8List coins) async {
  final keys = await MlKemIncremental.keyGen(seed: seed);
  final spec = await MlKemIncremental.encaps1(
    ekSeed: keys.ekSeed,
    hek: keys.hek,
    coins: coins,
  );
  final ct2 = await MlKemIncremental.encaps2(
    encapsSecret: spec.encapsSecret,
    ekSeed: keys.ekSeed,
    ekVector: keys.ekVector,
  );
  final raw = await MlKemIncremental.decaps(
    decapsulationKey: keys.decapsulationKey,
    ct1: spec.ct1,
    ct2: ct2,
  );
  expect(raw, spec.sharedSecret);
  final mixed = SpqrKdf.sckaKey(raw, epoch: 1);
  keys.wipe();
  spec.wipe();
  secure(raw);
  return mixed;
}

void secure(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

Uint8List _count(int n, int start) =>
    Uint8List.fromList(List<int>.generate(n, (i) => (start + i) & 0xff));

Uint8List _join(List<Uint8List> parts) {
  final out = Uint8List(parts.fold(0, (n, p) => n + p.length));
  var offset = 0;
  for (final part in parts) {
    out.setRange(offset, offset + part.length, part);
    offset += part.length;
  }
  return out;
}

Uint8List _hex(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);
