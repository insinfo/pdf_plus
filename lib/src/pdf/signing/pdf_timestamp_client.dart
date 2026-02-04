//C:\MyDartProjects\pdf_plus\lib\src\pdf\signing\pdf_timestamp_client.dart
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/crypto/sha1.dart';
import 'package:pdf_plus/src/crypto/sha256.dart';
import 'package:pdf_plus/src/crypto/sha512.dart';

/// Provider that returns a timestamp token for a given signature.
typedef PdfTimestampProvider = Future<Uint8List> Function(Uint8List signature);

/// Supported hash algorithms for TSA requests.
enum PdfTimestampHashAlgorithm {
  sha1,
  sha256,
  sha512,
}

/// Validation options for TSA responses.
class PdfTimestampValidationOptions {
  /// Creates TSA validation options.
  const PdfTimestampValidationOptions({
    this.trustedRootsPem,
    this.trustedRootsProvider,
    this.trustedRootsProviders,
    this.certificateFetcher,
    this.requireTrustedChain = true,
    this.throwOnFailure = true,
  });

  /// PEM-encoded trusted roots.
  final List<String>? trustedRootsPem;
  /// Trusted roots provider.
  final TrustedRootsProvider? trustedRootsProvider;
  /// Multiple trusted roots providers.
  final List<TrustedRootsProvider>? trustedRootsProviders;
  /// Optional certificate fetcher (AIA).
  final PdfHttpFetcherBase? certificateFetcher;
  /// Whether a trusted chain is required.
  final bool requireTrustedChain;
  /// Whether to throw when validation fails.
  final bool throwOnFailure;
}

/// RFC 3161 TSA client.
class PdfTimestampClient {
  /// Creates a TSA client.
  PdfTimestampClient({
    required this.endpoint,
    this.hashAlgorithm = PdfTimestampHashAlgorithm.sha256,
    this.validationOptions,
    PdfHttpFetcherBase? httpClient,
  }) : _httpClient = httpClient ?? PdfHttpFetcher();

  /// Creates a client configured for FreeTSA.
  factory PdfTimestampClient.freetsa({
    PdfTimestampHashAlgorithm hashAlgorithm = PdfTimestampHashAlgorithm.sha256,
    PdfTimestampValidationOptions? validationOptions,
  }) {
    return PdfTimestampClient(
      endpoint: Uri.parse('https://freetsa.org/tsr'),
      hashAlgorithm: hashAlgorithm,
      validationOptions: validationOptions,
    );
  }

  /// TSA endpoint.
  final Uri endpoint;
  /// Hash algorithm for timestamp requests.
  final PdfTimestampHashAlgorithm hashAlgorithm;
  /// Optional validation options.
  final PdfTimestampValidationOptions? validationOptions;

  final PdfHttpFetcherBase _httpClient;

  /// Requests a timestamp token for [signature].
  Future<Uint8List> timestampSignature(
    Uint8List signature, {
    PdfTimestampValidationOptions? validationOptions,
  }) async {
    final digest = _computeDigest(signature, hashAlgorithm);
    final requestBytes = _buildRequest(digest, hashAlgorithm);
    final responseBytes = await _postRequest(requestBytes);
    final token = _parseResponse(responseBytes);

    final options = validationOptions ?? this.validationOptions;
    if (options != null) {
      final result = await _validateToken(token, options);
      if (options.throwOnFailure) {
        if (!result.cmsValid) {
          throw StateError('Timestamp TSA com assinatura invalida.');
        }
        if (options.requireTrustedChain && result.chainTrusted != true) {
          throw StateError('Timestamp TSA com cadeia nao confiavel.');
        }
      }
    }

    return token;
  }

  Uint8List _buildRequest(
    Uint8List digest,
    PdfTimestampHashAlgorithm algorithm,
  ) {
    final oid = _hashAlgorithmOid(algorithm);
    final hashAlg = ASN1Sequence();
    hashAlg.add(ASN1ObjectIdentifier.fromComponentString(oid));
    hashAlg.add(ASN1Null());

    final imprint = ASN1Sequence();
    imprint.add(hashAlg);
    imprint.add(ASN1OctetString(digest));

    final req = ASN1Sequence();
    req.add(ASN1Integer(BigInt.one)); // version
    req.add(imprint);
    req.add(ASN1Boolean(true)); // certReq

    return req.encodedBytes;
  }

  Future<Uint8List> _postRequest(Uint8List requestBytes) async {
    final response = await _httpClient.postBytes(
      endpoint,
      headers: const <String, String>{
        'Content-Type': 'application/timestamp-query',
      },
      body: requestBytes,
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw StateError(
        'TSA respondeu com status ${response.statusCode}.',
      );
    }

    if (response.body.isEmpty) {
      throw StateError('TSA respondeu vazio.');
    }

    return response.body;
  }

  Uint8List _parseResponse(Uint8List responseBytes) {
    final resp = ASN1Parser(responseBytes).nextObject() as ASN1Sequence;
    if (resp.elements.isEmpty) {
      throw StateError('Resposta TSA inválida.');
    }

    final statusSeq = resp.elements.first as ASN1Sequence;
    final status = statusSeq.elements.first as ASN1Integer;
    final statusValue = status.valueAsBigInteger.toInt();
    if (statusValue != 0 && statusValue != 1) {
      throw StateError('TSA retornou erro (status=$statusValue).');
    }

    if (resp.elements.length < 2) {
      throw StateError('TimeStampToken ausente na resposta TSA.');
    }

    final token = resp.elements[1];
    final tokenBytes = Uint8List.fromList(token.encodedBytes);

    return tokenBytes;
  }

  Uint8List _computeDigest(
    Uint8List data,
    PdfTimestampHashAlgorithm algorithm,
  ) {
    switch (algorithm) {
      case PdfTimestampHashAlgorithm.sha1:
        return Uint8List.fromList(sha1.convert(data).bytes);
      case PdfTimestampHashAlgorithm.sha512:
        return Uint8List.fromList(sha512.convert(data).bytes);
      case PdfTimestampHashAlgorithm.sha256:
        return Uint8List.fromList(sha256.convert(data).bytes);
    }
  }

  String _hashAlgorithmOid(PdfTimestampHashAlgorithm algorithm) {
    switch (algorithm) {
      case PdfTimestampHashAlgorithm.sha1:
        return '1.3.14.3.2.26';
      case PdfTimestampHashAlgorithm.sha512:
        return '2.16.840.1.101.3.4.2.3';
      case PdfTimestampHashAlgorithm.sha256:
        return '2.16.840.1.101.3.4.2.1';
    }
  }

  Future<PdfCmsValidationResult> _validateToken(
    Uint8List tokenBytes,
    PdfTimestampValidationOptions options,
  ) async {
    final validator = PdfCmsValidator();
    return validator.validate(
      tokenBytes,
      trustedRootsPem: options.trustedRootsPem,
      trustedRootsProvider: options.trustedRootsProvider,
      trustedRootsProviders: options.trustedRootsProviders,
      certificateFetcher: options.certificateFetcher,
      requireTrustedChain: options.requireTrustedChain,
    );
  }
}
