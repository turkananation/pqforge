/// Compatibility entrypoint for the original scaffold service name.
library;

import '../services/pqforge_service.dart';

export '../algorithms/pq_algorithms.dart';
export '../codecs/pq_envelope.dart';
export '../keys/pq_keys.dart';
export '../primitives/pq_primitives.dart';
export '../recipes/pq_recipes.dart';
export '../services/pqforge_service.dart';

@Deprecated('Use PqForge. CryptoService remains as a compatibility alias.')
class CryptoService extends PqForge {
  const CryptoService({super.profile});
}
