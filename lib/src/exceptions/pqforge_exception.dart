class PqForgeException implements Exception {
  const PqForgeException(this.message);

  final String message;

  @override
  String toString() => 'PqForgeException: $message';
}
