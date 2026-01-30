import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

class FileCertificateFetcher implements PdfCertificateFetcher {
  FileCertificateFetcher(this._fileMap);

  final Map<String, String> _fileMap;

  @override
  Future<Uint8List?> fetchBytes(Uri url) async {
    final path = _fileMap[url.toString()];
    if (path == null) return null;
    return File(path).readAsBytesSync();
  }
}

class MapCertificateFetcher implements PdfCertificateFetcher {
  MapCertificateFetcher(this._map);

  final Map<String, Uint8List> _map;

  @override
  Future<Uint8List?> fetchBytes(Uri url) async {
    return _map[url.toString()];
  }
}

void main() {
  test('AIA fetcher is optional and does not break validation', () async {
    final file = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf');
    final bytes = file.readAsBytesSync();

    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: AssetTrustedRootsProvider(
        AssetTrustedRootsProvider.loadDefaultRoots(),
      ),
      includeCertificates: true,
      includeSignatureFields: true,
      certificateFetcher: FileCertificateFetcher(const {}),
      fetchCrls: false,
    );

    expect(report.signatures.length, 2);
  });

  test('AIA caIssuers fetcher resolves chain with mock', () async {
    final trustDirs = <Directory>[
      Directory('test/assets/truststore/gov.br'),
      Directory('test/assets/truststore/cadeia_icp_brasil'),
    ];

    final pdfDir = Directory('test/assets/pdfs');
    final pdfFiles = pdfDir
        .listSync()
        .whereType<File>()
        .where((f) => f.path.toLowerCase().endsWith('.pdf'))
        .toList();

    _Candidate? candidate;
    PdfSignatureValidationReport? reportWithoutFetcher;

    for (final file in pdfFiles) {
      final bytes = file.readAsBytesSync();
      final baseReport = await PdfSignatureValidator().validateAllSignatures(
        bytes,
        includeSignatureFields: true,
        includeCertificates: true,
      );

      for (final sig in baseReport.signatures) {
        final range = sig.signatureField?.byteRange;
        if (range == null || range.length != 4) continue;
        final cms = _extractContentsFromByteRange(bytes, range);
        if (cms == null) continue;
        final certs = _extractCmsCertificates(cms);
        if (certs.isEmpty) continue;
        for (final signerCert in certs) {
          final aiaUrls = _extractAiaCaIssuersUrls(signerCert);
          if (aiaUrls.isEmpty) continue;

          final issuerCert = _findIssuerCertInCms(signerCert, certs);
          if (issuerCert == null) continue;

          for (final dir in trustDirs) {
            final rootCert = _findIssuerCertInDir(issuerCert, dir);
            if (rootCert == null) continue;

            final report = await PdfSignatureValidator().validateAllSignatures(
              bytes,
              trustedRootsProvider: AssetTrustedRootsProvider([rootCert]),
              includeSignatureFields: true,
              includeCertificates: true,
            );

            if (report.signatures[sig.signatureIndex].chainTrusted == true) {
              continue;
            }

            candidate = _Candidate(
              signatureIndex: sig.signatureIndex,
              aiaUrl: aiaUrls.first,
              issuerCert: issuerCert,
              rootCert: rootCert,
              pdfBytes: bytes,
              fileName: file.path,
            );
            reportWithoutFetcher = report;
            break;
          }
          if (candidate != null) break;
        }
        if (candidate != null) break;
      }
      if (candidate != null) break;
    }

    if (candidate == null) {
      return;
    }
    final chosen = candidate;
    final withoutFetcher = reportWithoutFetcher;
    if (withoutFetcher == null) {
      fail('Relatório sem fetcher não foi gerado.');
    }

    expect(
      withoutFetcher.signatures[chosen.signatureIndex].chainTrusted,
      isFalse,
    );

    final reportWithFetcher = await PdfSignatureValidator()
        .validateAllSignatures(
      chosen.pdfBytes,
      trustedRootsProvider: AssetTrustedRootsProvider([chosen.rootCert]),
      includeSignatureFields: true,
      includeCertificates: true,
      certificateFetcher: MapCertificateFetcher({
        chosen.aiaUrl.toString(): chosen.issuerCert,
      }),
    );

    expect(
      reportWithFetcher.signatures[chosen.signatureIndex].chainTrusted,
      isTrue,
    );
  });
}

class _Candidate {
  _Candidate({
    required this.signatureIndex,
    required this.aiaUrl,
    required this.issuerCert,
    required this.rootCert,
    required this.pdfBytes,
    required this.fileName,
  });

  final int signatureIndex;
  final Uri aiaUrl;
  final Uint8List issuerCert;
  final Uint8List rootCert;
  final Uint8List pdfBytes;
  final String fileName;
}

Uint8List? _extractContentsFromByteRange(
  Uint8List bytes,
  List<int> range,
) {
  final gapStart = range[0] + range[1];
  final gapEnd = range[2];
  if (gapStart < 0 || gapEnd <= gapStart || gapEnd > bytes.length) {
    return null;
  }

  int lt = -1;
  for (int i = gapStart; i < gapEnd; i++) {
    if (bytes[i] == 0x3C) {
      lt = i;
      break;
    }
  }
  if (lt == -1) return null;
  int gt = -1;
  for (int i = lt + 1; i < gapEnd; i++) {
    if (bytes[i] == 0x3E) {
      gt = i;
      break;
    }
  }
  if (gt == -1 || gt <= lt) return null;

  final hex = bytes.sublist(lt + 1, gt);
  final cleaned = <int>[];
  for (final b in hex) {
    if (b == 0x20 || b == 0x0A || b == 0x0D || b == 0x09) continue;
    cleaned.add(b);
  }
  if (cleaned.length.isOdd) return null;
  final decoded = _hexToBytes(cleaned);
  return _trimCmsPadding(decoded);
}

Uint8List _hexToBytes(List<int> hexBytes) {
  final out = Uint8List(hexBytes.length ~/ 2);
  for (int i = 0; i < hexBytes.length; i += 2) {
    final hi = _hexValue(hexBytes[i]);
    final lo = _hexValue(hexBytes[i + 1]);
    out[i ~/ 2] = (hi << 4) | lo;
  }
  return out;
}

int _hexValue(int b) {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x41 && b <= 0x46) return b - 0x41 + 10;
  if (b >= 0x61 && b <= 0x66) return b - 0x61 + 10;
  return 0;
}

Uint8List _trimCmsPadding(Uint8List bytes) {
  var start = 0;
  var end = bytes.length;
  while (start < end && bytes[start] == 0x00) {
    start++;
  }
  while (end > start && bytes[end - 1] == 0x00) {
    end--;
  }
  if (start == 0 && end == bytes.length) return bytes;
  return bytes.sublist(start, end);
}

List<Uint8List> _extractCmsCertificates(Uint8List cmsBytes) {
  try {
    final contentInfo = ASN1Parser(cmsBytes).nextObject();
    if (contentInfo is! ASN1Sequence || contentInfo.elements.length < 2) {
      return const <Uint8List>[];
    }
    final signedDataObj = _unwrapTagged(contentInfo.elements[1]);
    if (signedDataObj is! ASN1Sequence) return const <Uint8List>[];

    ASN1Object? certsTag;
    for (final element in signedDataObj.elements) {
      if (_isTagged(element, 0)) {
        certsTag = element;
        break;
      }
    }
    if (certsTag == null) return const <Uint8List>[];
    return _parseCmsCertificates(certsTag);
  } catch (_) {
    return const <Uint8List>[];
  }
}

List<Uint8List> _parseCmsCertificates(ASN1Object certsTag) {
  final out = <Uint8List>[];
  ASN1Object? certsObj = _unwrapTagged(certsTag);
  final raw = _readTaggedValueBytes(certsTag);
  if (certsObj is! ASN1Set && certsObj is! ASN1Sequence) {
    if (raw != null && raw.isNotEmpty) {
      certsObj = ASN1Parser(_wrapSet(raw)).nextObject();
    }
  }

  void addIfCertificate(ASN1Object el) {
    if (el is ASN1Sequence && el.elements.length >= 3) {
      final tbs = _asAsn1Sequence(el.elements.first);
      final sig = el.elements[2];
      if (tbs != null && sig is ASN1BitString) {
        out.add(el.encodedBytes);
      }
    }
  }

  if (certsObj is ASN1Sequence) {
    if (_looksLikeCertificateSeq(certsObj)) {
      addIfCertificate(certsObj);
      return out;
    }
    for (final el in certsObj.elements) {
      addIfCertificate(el);
    }
    return out;
  }

  if (certsObj is ASN1Set) {
    for (final el in certsObj.elements) {
      addIfCertificate(el);
    }
  }
  return out;
}

List<Uri> _extractAiaCaIssuersUrls(Uint8List certDer) {
  const oidAia = '1.3.6.1.5.5.7.1.1';
  const oidCaIssuers = '1.3.6.1.5.5.7.48.2';
  final extBytes = _findExtensionValue(certDer, oidAia);
  if (extBytes == null) return <Uri>[];
  try {
    final seq = ASN1Parser(extBytes).nextObject();
    if (seq is! ASN1Sequence) return <Uri>[];
    final urls = <Uri>[];
    for (final el in seq.elements) {
      if (el is! ASN1Sequence || el.elements.length < 2) continue;
      final method = el.elements.first;
      if (method is! ASN1ObjectIdentifier) continue;
      if (_oidToString(method) != oidCaIssuers) continue;
      final location = el.elements[1];
      urls.addAll(_extractUrisFromGeneralNames(location));
    }
    return urls;
  } catch (_) {
    return <Uri>[];
  }
}

Uint8List? _findExtensionValue(Uint8List certDer, String oid) {
  try {
    final certSeqObj = ASN1Parser(certDer).nextObject();
    final certSeq = certSeqObj is ASN1Sequence ? certSeqObj : null;
    if (certSeq == null || certSeq.elements.isEmpty) return null;
    final tbs = _asAsn1Sequence(certSeq.elements.first);
    if (tbs == null) return null;
    for (final el in tbs.elements) {
      if (!_isTagged(el, 3)) continue;
      final extSeqObj = _unwrapTagged(el);
      if (extSeqObj is! ASN1Sequence) continue;
      for (final ext in extSeqObj.elements) {
        if (ext is! ASN1Sequence || ext.elements.isEmpty) continue;
        final oidObj = ext.elements.first;
        if (oidObj is! ASN1ObjectIdentifier) continue;
        if (_oidToString(oidObj) != oid) continue;
        final extValue = ext.elements.last;
        if (extValue is! ASN1OctetString) continue;
        return extValue.valueBytes();
      }
    }
  } catch (_) {
    return null;
  }
  return null;
}

Uint8List? _findIssuerCertInDir(Uint8List signerCert, Directory dir) {
  final signerTbs = _readTbsCertificate(signerCert);
  if (signerTbs == null) return null;
  final issuerDer = signerTbs.issuer;

  if (!dir.existsSync()) return null;
  for (final entity in dir.listSync(recursive: true)) {
    if (entity is! File) continue;
    final certs = _loadCertsFromFile(entity);
    for (final cert in certs) {
      final tbs = _readTbsCertificate(cert);
      if (tbs == null) continue;
      if (_listEquals(issuerDer, tbs.subject)) {
        return cert;
      }
    }
  }
  return null;
}

Uint8List? _findIssuerCertInCms(
  Uint8List signerCert,
  List<Uint8List> certs,
) {
  final signerTbs = _readTbsCertificate(signerCert);
  if (signerTbs == null) return null;
  final issuerDer = signerTbs.issuer;

  for (final cert in certs) {
    final tbs = _readTbsCertificate(cert);
    if (tbs == null) continue;
    if (_listEquals(issuerDer, tbs.subject)) return cert;
  }
  return null;
}

List<Uint8List> _loadCertsFromFile(File file) {
  final bytes = file.readAsBytesSync();
  final text = utf8.decode(bytes, allowMalformed: true);
  if (text.contains('-----BEGIN CERTIFICATE-----')) {
    return _pemBlocksToDer(text);
  }
  final lower = file.path.toLowerCase();
  if (lower.endsWith('.p7b') || lower.endsWith('.p7c')) {
    return _extractCmsCertificates(bytes);
  }
  return <Uint8List>[bytes];
}

List<Uint8List> _pemBlocksToDer(String pem) {
  final re = RegExp(
    '-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----',
    multiLine: true,
  );
  final matches = re.allMatches(pem);
  final out = <Uint8List>[];
  for (final m in matches) {
    final body = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
    if (body.isEmpty) continue;
    out.add(Uint8List.fromList(base64.decode(body)));
  }
  return out;
}

class _TbsInfo {
  _TbsInfo({required this.issuer, required this.subject});

  final Uint8List issuer;
  final Uint8List subject;
}

_TbsInfo? _readTbsCertificate(Uint8List certDer) {
  try {
    final certSeqObj = ASN1Parser(certDer).nextObject();
    final certSeq = certSeqObj is ASN1Sequence ? certSeqObj : null;
    if (certSeq == null || certSeq.elements.isEmpty) return null;
    final tbs = _asAsn1Sequence(certSeq.elements.first);
    if (tbs == null) return null;

    int idx = 0;
    if (_readTagNumber(tbs.elements.first) == 0) {
      idx = 1;
    }
    final issuerSeq = _asAsn1Sequence(tbs.elements[idx + 2]);
    final subjectSeq = _asAsn1Sequence(tbs.elements[idx + 4]);
    if (issuerSeq == null || subjectSeq == null) return null;
    return _TbsInfo(
      issuer: issuerSeq.encodedBytes,
      subject: subjectSeq.encodedBytes,
    );
  } catch (_) {
    return null;
  }
}

ASN1Sequence? _asAsn1Sequence(ASN1Object obj) {
  if (obj is ASN1Sequence) return obj;
  try {
    final parsed = ASN1Parser(obj.encodedBytes).nextObject();
    if (parsed is ASN1Sequence) return parsed;
  } catch (_) {}
  return null;
}

List<Uri> _extractUrisFromGeneralNames(ASN1Object obj) {
  final urls = <Uri>[];
  void walk(ASN1Object node) {
    final tag = _readTagNumber(node);
    if (tag == 6) {
      final bytes = _readTaggedValueBytes(node);
      if (bytes != null) {
        final url = Uri.tryParse(String.fromCharCodes(bytes));
        if (url != null) urls.add(url);
      }
      return;
    }
    if (node is ASN1Sequence || node is ASN1Set) {
      final elements =
          node is ASN1Sequence ? node.elements : (node as ASN1Set).elements;
      for (final el in elements) {
        walk(el);
      }
    }
  }

  walk(obj);
  return urls;
}

bool _looksLikeCertificateSeq(ASN1Sequence seq) {
  if (seq.elements.length < 3) return false;
  final sigVal = seq.elements[2];
  final algo = seq.elements[1];
  return sigVal is ASN1BitString && algo is ASN1Sequence;
}

Uint8List _wrapSet(Uint8List content) {
  final lengthBytes = _encodeLength(content.length);
  final out = Uint8List(1 + lengthBytes.length + content.length);
  out[0] = 0x31;
  out.setRange(1, 1 + lengthBytes.length, lengthBytes);
  out.setRange(1 + lengthBytes.length, out.length, content);
  return out;
}

Uint8List _encodeLength(int length) {
  if (length < 128) {
    return Uint8List.fromList([length]);
  }
  final bytes = <int>[];
  var n = length;
  while (n > 0) {
    bytes.insert(0, n & 0xFF);
    n >>= 8;
  }
  return Uint8List.fromList([0x80 | bytes.length, ...bytes]);
}

ASN1Object _unwrapTagged(ASN1Object obj) {
  final tag = _readTagNumber(obj);
  if (tag == null) return obj;
  final dynamic dyn = obj;
  try {
    final value = dyn.value;
    if (value is ASN1Object) return value;
  } catch (_) {}

  final bytes = _readTaggedValueBytes(obj);
  if (bytes != null && bytes.isNotEmpty) {
    return ASN1Parser(bytes).nextObject();
  }
  return obj;
}

bool _isTagged(ASN1Object obj, int tag) {
  final t = _readTagNumber(obj);
  return t == tag;
}

Uint8List? _readTaggedValueBytes(ASN1Object obj) {
  final dynamic dyn = obj;
  try {
    final bytes = dyn.valueBytes;
    if (bytes is Uint8List) return bytes;
    if (bytes is List<int>) return Uint8List.fromList(bytes);
    if (bytes is Function) {
      final result = bytes();
      if (result is Uint8List) return result;
      if (result is List<int>) return Uint8List.fromList(result);
    }
  } catch (_) {}
  return null;
}

int? _readTagNumber(ASN1Object obj) {
  final dynamic dyn = obj;
  try {
    final tag = dyn.tag;
    if (tag is int) {
      if (tag >= 0xA0 && tag <= 0xBF) return tag & 0x1F;
      if (tag >= 0x80 && tag <= 0x9F) return tag & 0x1F;
      return tag;
    }
  } catch (_) {}
  return null;
}

String? _oidToString(ASN1ObjectIdentifier oid) {
  final dynamic dyn = oid;
  try {
    final v = dyn.objectIdentifierAsString;
    return v?.toString();
  } catch (_) {}
  try {
    final v = dyn.oidName;
    return v?.toString();
  } catch (_) {}
  return null;
}

bool _listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
