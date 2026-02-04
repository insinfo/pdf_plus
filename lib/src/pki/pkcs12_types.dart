class Pkcs12Bundle {
  Pkcs12Bundle({
    required this.privateKeyPem,
    required this.certificatePem,
    this.chainPem = const <String>[],
  });

  final String privateKeyPem;
  final String certificatePem;
  final List<String> chainPem;
}

abstract class Pkcs12Decoder {
  Future<Pkcs12Bundle> decode(
    List<int> bytes, {
    required String password,
  });
}
