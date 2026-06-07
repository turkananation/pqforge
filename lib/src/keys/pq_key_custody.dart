/// Pluggable key custody helpers for wrapped pqforge keys.
library;

import 'dart:async';

import '../algorithms/pq_algorithms.dart';
import '../services/pqforge_service.dart';
import 'pq_keys.dart';

typedef PqKeyCustodyPut =
    FutureOr<void> Function(String storageId, Map<String, Object?> document);
typedef PqKeyCustodyGet =
    FutureOr<Map<String, Object?>?> Function(String storageId);
typedef PqKeyCustodyDelete = FutureOr<void> Function(String storageId);

abstract interface class PqKeyCustodyStore {
  Future<void> put(String storageId, Map<String, Object?> document);
  Future<Map<String, Object?>?> get(String storageId);
  Future<void> delete(String storageId);
}

class PqCallbackKeyCustodyStore implements PqKeyCustodyStore {
  const PqCallbackKeyCustodyStore({
    required this.putDocument,
    required this.getDocument,
    required this.deleteDocument,
  });

  final PqKeyCustodyPut putDocument;
  final PqKeyCustodyGet getDocument;
  final PqKeyCustodyDelete deleteDocument;

  @override
  Future<void> put(String storageId, Map<String, Object?> document) async {
    await putDocument(storageId, Map.unmodifiable(document));
  }

  @override
  Future<Map<String, Object?>?> get(String storageId) async {
    final document = await getDocument(storageId);
    return document == null ? null : Map<String, Object?>.from(document);
  }

  @override
  Future<void> delete(String storageId) async {
    await deleteDocument(storageId);
  }
}

class PqMemoryKeyCustodyStore implements PqKeyCustodyStore {
  final _documents = <String, Map<String, Object?>>{};

  Map<String, Map<String, Object?>> get snapshot {
    final copy = <String, Map<String, Object?>>{};
    for (final entry in _documents.entries) {
      copy[entry.key] = Map<String, Object?>.unmodifiable(entry.value);
    }
    return Map<String, Map<String, Object?>>.unmodifiable(copy);
  }

  @override
  Future<void> put(String storageId, Map<String, Object?> document) async {
    _documents[storageId] = Map<String, Object?>.from(document);
  }

  @override
  Future<Map<String, Object?>?> get(String storageId) async {
    final document = _documents[storageId];
    return document == null ? null : Map<String, Object?>.from(document);
  }

  @override
  Future<void> delete(String storageId) async {
    _documents.remove(storageId);
  }
}

class PqPassphraseKeyCustody {
  const PqPassphraseKeyCustody({required this.forge, required this.store});

  final PqForge forge;
  final PqKeyCustodyStore store;

  Future<PqWrappedKey> wrapAndPut(
    PqExportedKey key,
    String passphrase, {
    String? storageId,
    int iterations = 2,
    int memoryPowerOf2 = 16,
    int lanes = 4,
  }) async {
    final id = _resolveStorageId(storageId, key.keyId);
    final wrapped = forge.wrapKeyWithPassphrase(
      key,
      passphrase,
      iterations: iterations,
      memoryPowerOf2: memoryPowerOf2,
      lanes: lanes,
    );
    await putWrappedKey(wrapped, storageId: id);
    return wrapped;
  }

  Future<void> putWrappedKey(PqWrappedKey wrapped, {String? storageId}) async {
    final id = _resolveStorageId(storageId, wrapped.keyId);
    await store.put(id, wrapped.toJson());
  }

  Future<PqWrappedKey?> getWrappedKey(String storageId) async {
    final document = await store.get(storageId);
    return document == null ? null : PqWrappedKey.fromJson(document);
  }

  Future<PqWrappedKey> requireWrappedKey(String storageId) async {
    final wrapped = await getWrappedKey(storageId);
    if (wrapped == null) {
      throw PqForgeException('Wrapped key not found: $storageId');
    }
    return wrapped;
  }

  Future<PqExportedKey> getAndUnwrap(
    String storageId,
    String passphrase,
  ) async {
    final wrapped = await requireWrappedKey(storageId);
    return forge.unwrapKeyWithPassphrase(wrapped, passphrase);
  }

  Future<void> delete(String storageId) => store.delete(storageId);

  String _resolveStorageId(String? storageId, String? keyId) {
    final id = storageId ?? keyId;
    if (id == null || id.isEmpty) {
      throw const PqForgeException(
        'storageId is required when the key has no keyId',
      );
    }
    return id;
  }
}
