import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:pdf_plus/src/pki/pki_jks_utils.dart';

class AssetTrustedRootsProvider implements pdf.TrustedRootsProvider {
  AssetTrustedRootsProvider(this._roots);

  final List<Uint8List> _roots;

  @override
  Future<List<Uint8List>> getTrustedRootsDer() async => _roots;

  static List<Uint8List> loadDefaultRoots() {
    return TruststoreAssetsLoader().loadTrustedRoots();
  }
}

class TruststoreAssetsLoader {
  TruststoreAssetsLoader({String? basePath})
      : _baseDir = Directory(basePath ?? 'test/assets/truststore');

  final Directory _baseDir;

  List<Uint8List> loadTrustedRoots() {
    if (!_baseDir.existsSync()) return <Uint8List>[];

    final roots = <Uint8List>[];
    for (final entity in _baseDir.listSync(recursive: true)) {
      if (entity is! File) continue;
      roots.addAll(_loadRootsFromFile(entity));
    }
    return _dedupe(roots);
  }

  List<Uint8List> _loadRootsFromFile(File file) {
    final path = file.path.toLowerCase();
    final bytes = file.readAsBytesSync();
    if (path.endsWith('.bks')) {
      return <Uint8List>[];
    }
    if (path.endsWith('.jks')) {
      final result = parseJksCertificates(bytes, password: '12345678');
      return result.certificates;
    }
    if (_looksLikePem(bytes)) {
      final pemText = utf8.decode(bytes, allowMalformed: true);
      final parsed = _pemBlocksToDer(pemText);
      if (parsed.isNotEmpty) return parsed;
      return <Uint8List>[bytes];
    }
    if (path.endsWith('.p7b') || path.endsWith('.p7c')) {
      return _extractPkcs7Certificates(bytes);
    }
    if (path.endsWith('.crt') ||
        path.endsWith('.cer') ||
        path.endsWith('.der') ||
        path.endsWith('.pem')) {
      return <Uint8List>[bytes];
    }
    return <Uint8List>[];
  }

  bool _looksLikePem(Uint8List bytes) {
    const marker = '-----BEGIN CERTIFICATE-----';
    final text = utf8.decode(bytes, allowMalformed: true);
    return text.contains(marker);
  }

  List<Uint8List> _pemBlocksToDer(String pem) {
    final re = RegExp(
      '-----BEGIN CERTIFICATE-----([\\s\\S]*?)-----END CERTIFICATE-----',
      multiLine: true,
    );
    final matches = re.allMatches(pem);
    final out = <Uint8List>[];
    for (final m in matches) {
      final body = (m.group(1) ?? '').replaceAll(RegExp(r'\\s+'), '');
      if (body.isEmpty) continue;
      try {
        out.add(Uint8List.fromList(base64.decode(body)));
      } on FormatException {
        continue;
      }
    }
    return out;
  }

  List<Uint8List> _extractPkcs7Certificates(Uint8List cmsBytes) {
    try {
      final contentInfo = ASN1Parser(cmsBytes).nextObject();
      if (contentInfo is! ASN1Sequence || contentInfo.elements.length < 2) {
        return <Uint8List>[];
      }

      final signedDataObj = _unwrapTagged(contentInfo.elements[1]);
      if (signedDataObj is! ASN1Sequence) return <Uint8List>[];

      ASN1Object? certsTag;
      for (final element in signedDataObj.elements) {
        if (_isTagged(element, 0)) {
          certsTag = element;
          break;
        }
      }
      if (certsTag == null) return <Uint8List>[];
      ASN1Object? certsObj = _unwrapTagged(certsTag);
      final raw = _readTaggedValueBytes(certsTag);
      if (certsObj is! ASN1Set && certsObj is! ASN1Sequence) {
        if (raw != null && raw.isNotEmpty) {
          certsObj = ASN1Parser(_wrapSet(raw)).nextObject();
        }
      }
      if (certsObj is! ASN1Set && certsObj is! ASN1Sequence) {
        return <Uint8List>[];
      }
      final out = <Uint8List>[];
      void addIfCertificate(ASN1Object el) {
        if (el is ASN1Sequence && el.elements.length >= 3) {
          final tbs = _asAsn1Sequence(el.elements.first);
          final sig = el.elements[2];
          if (tbs != null && sig is ASN1BitString) {
            out.add(el.encodedBytes);
          }
        }
      }

      if (certsObj is ASN1Sequence && _looksLikeCertificateSeq(certsObj)) {
        if (raw != null && raw.isNotEmpty) {
          try {
            final wrapped = ASN1Parser(_wrapSet(raw)).nextObject();
            if (wrapped is ASN1Set) {
              for (final el in wrapped.elements) {
                addIfCertificate(el);
              }
              return out;
            }
          } catch (_) {}
        }
        addIfCertificate(certsObj);
        return out;
      }

      final certList =
          certsObj is ASN1Set ? certsObj.elements : (certsObj as ASN1Sequence).elements;
      for (final el in certList) {
        addIfCertificate(el);
      }
      return out;
    } catch (_) {
      return <Uint8List>[];
    }
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

  bool _looksLikeCertificateSeq(ASN1Sequence seq) {
    if (seq.elements.length < 3) return false;
    final sigVal = seq.elements[2];
    final algo = seq.elements[1];
    return sigVal is ASN1BitString && algo is ASN1Sequence;
  }

  ASN1Sequence? _asAsn1Sequence(ASN1Object obj) {
    if (obj is ASN1Sequence) return obj;
    try {
      final parsed = ASN1Parser(obj.encodedBytes).nextObject();
      if (parsed is ASN1Sequence) return parsed;
    } catch (_) {}
    return null;
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

  List<Uint8List> _dedupe(List<Uint8List> roots) {
    final seen = <String>{};
    final out = <Uint8List>[];
    for (final cert in roots) {
      final hash = crypto.sha256.convert(cert).toString();
      if (seen.add(hash)) {
        out.add(cert);
      }
    }
    return out;
  }
}

class PolicyAssetsLoader {
  PolicyAssetsLoader({String? basePath})
      : _baseDir = Directory(basePath ?? 'test/assets/policy/engine/artifacts');

  final Directory _baseDir;

  Map<String, Uint8List> loadPolicies() {
    if (!_baseDir.existsSync()) return <String, Uint8List>{};
    final policies = <String, Uint8List>{};
    for (final entity in _baseDir.listSync(recursive: true)) {
      if (entity is! File) continue;
      final name = entity.path.replaceAll('\\', '/');
      policies[name] = entity.readAsBytesSync();
    }
    return policies;
  }
}
