/// `dart:io` extensions for pqforge: bounded-memory streaming file encryption.
///
/// Import this instead of `package:pqforge/pqforge.dart` on native, server, and
/// mobile targets that need to encrypt or decrypt large files without holding
/// them in memory:
///
/// ```dart
/// import 'package:pqforge/pqforge_io.dart';
///
/// final cipher = PqForgeStreamCipher();
/// await cipher.encryptFile(
///   recipientPublicKey: recipientKemPublicKey,
///   input: File('movie.mp4'),
///   output: File('movie.mp4.pqf'),
///   profile: PqForgeProfile.maximum,
/// );
/// ```
///
/// It re-exports the full core API, so a single import is enough. The core
/// `package:pqforge/pqforge.dart` library stays free of `dart:io` and therefore
/// web-compatible; everything that touches the filesystem lives here.
library;

export 'pqforge.dart';
export 'src/codecs/pq_streaming_envelope.dart';
export 'src/services/pqforge_pack_service.dart';
export 'src/services/pqforge_stream_service.dart';
