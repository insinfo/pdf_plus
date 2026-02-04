//C:\MyDartProjects\pdf_plus\lib\src\pdf\signing\pdf_timestamp_client.dart
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/crypto/sha1.dart';
import 'package:pdf_plus/src/crypto/sha256.dart';
import 'package:pdf_plus/src/crypto/sha512.dart';

typedef PdfTimestampProvider = Future<Uint8List> Function(Uint8List signature);

enum PdfTimestampHashAlgorithm {
  sha1,
  sha256,
  sha512,
}

class PdfTimestampValidationOptions {
  const PdfTimestampValidationOptions({
    this.trustedRootsPem,
    this.trustedRootsProvider,
    this.trustedRootsProviders,
    this.certificateFetcher,
    this.requireTrustedChain = true,
    this.throwOnFailure = true,
  });

  final List<String>? trustedRootsPem;
  final TrustedRootsProvider? trustedRootsProvider;
  final List<TrustedRootsProvider>? trustedRootsProviders;
  final PdfHttpFetcherBase? certificateFetcher;
  final bool requireTrustedChain;
  final bool throwOnFailure;
}

class PdfTimestampClient {
  PdfTimestampClient({
    required this.endpoint,
    this.hashAlgorithm = PdfTimestampHashAlgorithm.sha256,
    this.validationOptions,
    this.logTimings = false,
    PdfHttpFetcherBase? httpClient,
  }) : _httpClient = httpClient ?? PdfHttpFetcher();

  factory PdfTimestampClient.freetsa({
    PdfTimestampHashAlgorithm hashAlgorithm = PdfTimestampHashAlgorithm.sha256,
    PdfTimestampValidationOptions? validationOptions,
    bool logTimings = false,
  }) {
    return PdfTimestampClient(
      endpoint: Uri.parse('https://freetsa.org/tsr'),
      hashAlgorithm: hashAlgorithm,
      validationOptions: validationOptions,
      logTimings: logTimings,
    );
  }

  final Uri endpoint;
  final PdfTimestampHashAlgorithm hashAlgorithm;
  final PdfTimestampValidationOptions? validationOptions;
  final bool logTimings;
  final PdfHttpFetcherBase _httpClient;

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
    if (logTimings) {
      print('TSA request size: ${requestBytes.length} bytes');
    }
    final response = await _httpClient.postBytes(
      endpoint,
      headers: const <String, String>{
        'Content-Type': 'application/timestamp-query',
      },
      body: requestBytes,
    );

    if (logTimings) {
      if (response.requestTime != null) {
        print('TSA request time: ${_formatElapsed(response.requestTime!)}');
      }
      if (response.responseTime != null) {
        print('TSA response time: ${_formatElapsed(response.responseTime!)}');
      }
      if (response.totalTime != null) {
        print('TSA total time: ${_formatElapsed(response.totalTime!)}');
      }
      print('TSA response size: ${response.body.length} bytes');
    }

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
    if (logTimings) {
      print('TSA token size: ${tokenBytes.length} bytes');
    }
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

String _formatElapsed(Duration duration) {
  final ms = duration.inMilliseconds;
  final seconds = (ms / 1000).toStringAsFixed(2);
  return '${seconds}s';
}
