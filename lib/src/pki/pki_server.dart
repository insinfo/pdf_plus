import 'dart:async';
import 'dart:io';

import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart';

import 'pki_builder.dart';


/// A simple PKI Server (Simulating OCSP, CRL, Timestamp)
class PkiServer {
  HttpServer? _server;
  final int port;
  final Map<int, bool> revokedSerials; // serial -> isRevoked
  final Uint8List crlDer; // Pre-generated CRL
  final AsymmetricKeyPair<PublicKey, PrivateKey> tsaKeyPair;
  final List<AsymmetricKeyPair<PublicKey, PrivateKey>> tsaCertChain; // Leaf first

  PkiServer({
    required this.port,
    required this.revokedSerials,
    required this.crlDer,
    required this.tsaKeyPair,
    required this.tsaCertChain,
  });

  Future<void> start() async {
    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
    // print('PKI Server listening on port $port');
    _server!.listen(_handleRequest);
  }

  Future<void> stop() async {
    await _server?.close();
    _server = null;
  }

  void _handleRequest(HttpRequest request) async {
    try {
      if (request.uri.path == '/ocsp') {
        await _handleOcsp(request);
      } else if (request.uri.path == '/crl') {
        await _handleCrl(request);
      } else if (request.uri.path == '/timestamp') {
        await _handleTimestamp(request);
      } else {
        request.response.statusCode = HttpStatus.notFound;
        request.response.close();
      }
    } catch (e, st) {
      print('Server Error: $e\n$st');
      request.response.statusCode = HttpStatus.internalServerError;
      request.response.close();
    }
  }

  Future<void> _handleCrl(HttpRequest request) async {
    request.response.headers.contentType = ContentType('application', 'pkix-crl');
    request.response.add(crlDer);
    await request.response.close();
  }

  Future<void> _handleOcsp(HttpRequest request) async {
    final responseSeq = ASN1Sequence();
    responseSeq.add(ASN1Integer(BigInt.zero)); // successful
    
    final responseBytes = ASN1Sequence();
    responseBytes.add(ASN1ObjectIdentifier.fromComponentString('1.3.6.1.5.5.7.48.1.1')); // id-pkix-ocsp-basic
    
    // BasicOCSPResponse
    final basicResponse = ASN1Sequence();
    
    // tbsResponseData
    final tbsResp = ASN1Sequence();
    tbsResp.add(ASN1ObjectIdentifier.fromComponentString('1.3.6.1.5.5.7.48.1.1')); 

    // ResponderID [1] Name (Tag A1)
    final byName = ASN1Sequence(tag: 0xA1);
    final nameSeq = ASN1Sequence(); // Empty name sequence (Root) for demo
    byName.elements.addAll(nameSeq.elements); // Should be empty
    tbsResp.add(byName);
    
    tbsResp.add(ASN1GeneralizedTime(DateTime.now())); // producedAt
    
    final responses = ASN1Sequence();
    // SingleResponse
    final singleResp = ASN1Sequence();
    
    // CertID (We fake it)
    final certId = ASN1Sequence();
    certId.add(PkiBuilder.createAlgorithmIdentifier('1.3.14.3.2.26')); // SHA1
    certId.add(ASN1OctetString(Uint8List(20))); // Dummy hash
    certId.add(ASN1OctetString(Uint8List(20))); // Dummy hash
    certId.add(ASN1Integer(BigInt.from(1234))); // Dummy serial
    singleResp.add(certId);
    
    // CertStatus (Good = implicit [0] NULL)
    singleResp.add(ASN1Null(tag: 0x80)); // [0] Good
    
    singleResp.add(ASN1GeneralizedTime(DateTime.now())); // thisUpdate
    
    responses.add(singleResp);
    tbsResp.add(responses);
    
    basicResponse.add(tbsResp);
    
    // signatureAlgorithm
    basicResponse.add(PkiBuilder.createAlgorithmIdentifier('1.2.840.113549.1.1.11')); // sha256WithRSA
    
    // signature
    // We sign tbsResp.encodedBytes
    final sig = PkiBuilder.signData(tbsResp.encodedBytes, tsaKeyPair.privateKey as RSAPrivateKey);
    basicResponse.add(ASN1BitString(sig));
    
    // Wrap responseBytes in [0] EXPLICIT (Tag A0)
    final octetStr = ASN1OctetString(basicResponse.encodedBytes);
    final respBytesObj = ASN1Sequence(tag: 0xA0);
    respBytesObj.add(octetStr);
    
    responseBytes.add(respBytesObj); // No, wait. 
    // responseBytes is the content of "responseBytes" field in OCSPResponse.
    // OCSPResponse ::= SEQUENCE { responseStatus, responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
    // ResponseBytes ::= SEQUENCE { responseType, response }
    // So 'responseBytes' var in my code IS the ResponseBytes sequence (30).
    // It must be wrapped in [0] EXPLICIT (A0).
    
    final ocspResponseBytesField = ASN1Sequence(tag: 0xA0);
    ocspResponseBytesField.add(responseBytes);
    
    responseSeq.add(ocspResponseBytesField);
    
    request.response.headers.contentType = ContentType('application', 'ocsp-response');
    request.response.add(responseSeq.encodedBytes);
    await request.response.close();
  }

  Future<void> _handleTimestamp(HttpRequest request) async {
    // ignore: unused_local_variable
    final content = await request.fold<List<int>>([], (p, e) => p..addAll(e));

    // Construct TimeStampResp
    final resp = ASN1Sequence();
    
    // PKIStatusInfo
    final status = ASN1Sequence();
    status.add(ASN1Integer(BigInt.zero)); // granted
    resp.add(status);
    
    // TimeStampToken -> ContentInfo (PKCS#7)
    final contentInfo = ASN1Sequence();
    contentInfo.add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.7.2')); // signedData
    
    // SignedData
    final signedData = ASN1Sequence();
    signedData.add(ASN1Integer(BigInt.from(3))); // version
    signedData.add(ASN1Set()); // digestAlgorithms
    
    // EncapsulatedContentInfo
    final encap = ASN1Sequence();
    encap.add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.9.16.1.4')); // id-ct-TSTInfo
    
    // TSTInfo
    final tstInfo = ASN1Sequence();
    tstInfo.add(ASN1Integer(BigInt.one)); // version 1
    tstInfo.add(ASN1ObjectIdentifier.fromComponentString('1.2.3.4')); // policy
    
    final messageImprint = ASN1Sequence();
    messageImprint.add(PkiBuilder.createAlgorithmIdentifier('2.16.840.1.101.3.4.2.1')); // sha-256
    messageImprint.add(ASN1OctetString(Uint8List(32))); // Dummy hash
    tstInfo.add(messageImprint);
    
    tstInfo.add(ASN1Integer(BigInt.from(1))); // serial
    tstInfo.add(ASN1GeneralizedTime(DateTime.now())); // genTime
    
    // TSTInfo as OctetString
    final tstInfoOctet = ASN1OctetString(tstInfo.encodedBytes);
    encap.add(tstInfoOctet); // eContent
    
    signedData.add(encap);
    
    // Certificates [0] IMPLICIT SET OF Certificate
    final certs = ASN1Set(tag: 0xA0); 
    signedData.add(certs);
    
    // SignerInfos
    final signerInfos = ASN1Set();
    signedData.add(signerInfos);

    // signedData is wrapped in [0] EXPLICIT (Tag A0) in ContentInfo? No.
    // ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
    final signedDataObj = ASN1Sequence(tag: 0xA0); 
    signedDataObj.add(signedData);
    contentInfo.add(signedDataObj);
    
    resp.add(contentInfo);

    request.response.headers.contentType = ContentType('application', 'timestamp-reply');
    request.response.add(resp.encodedBytes);
    await request.response.close();
  }
}

