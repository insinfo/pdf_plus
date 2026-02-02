import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/signing.dart';

void main() {
  final bytes = File('test/assets/policy/engine/artifacts/LPA_CAdES.der')
      .readAsBytesSync();
  final parser = ASN1Parser(Uint8List.fromList(bytes));
  final obj = parser.nextObject();
  print('top=${obj.runtimeType}');
  if (obj is ASN1Sequence) {
    print('top elements=${obj.elements.length}');
    if (obj.elements.isNotEmpty) {
      final first = obj.elements.first;
      print('first=${first.runtimeType}');
      if (first is ASN1Sequence) {
        print('first elements=${first.elements.length}');
        if (first.elements.isNotEmpty) {
          final policy0 = first.elements.first;
          print('policy0=${policy0.runtimeType}');
          if (policy0 is ASN1Sequence) {
            print('policy0 elements=${policy0.elements.length}');
            for (var i = 0; i < policy0.elements.length; i++) {
              final el = policy0.elements[i];
              print('  [$i] ${el.runtimeType} ${el.toString()}');
            }
          }
        }
      }
    }
  }
  final lpa = PdfLpa.parse(Uint8List.fromList(bytes));
  print('policies=${lpa.policies.length} nextUpdate=${lpa.nextUpdate}');
}
