# pdf_plus

[![Dart CI](https://github.com/insinfo/pdf_plus/actions/workflows/ci.yml/badge.svg)](https://github.com/insinfo/pdf_plus/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/insinfo/pdf_plus/branch/main/graph/badge.svg)](https://codecov.io/gh/insinfo/pdf_plus)

A Dart library for PDF generation and manipulation, based on `dart_pdf`, with additional focus on digital signatures and PKI workflows.

fork from https://github.com/DavBfr/dart_pdf

- **New Signing Features**: Implemented PAdES signature support (including B-B, B-T) and an external signing interface for A3/Token/HSM integration.
- **Signature Validation**: Added a robust validator for checking document integrity, certificate chains, and revocation status (CRL/OCSP).

## Requirements

- Dart SDK `^3.6.0`

## Installation

In your project's `pubspec.yaml`:

```yaml
dependencies:
  pdf_plus: ^3.14.0
```

Then run:

```bash
dart pub get
```

## Common imports

```dart
import 'package:pdf_plus/widgets.dart' as pw; // high-level PDF widgets
import 'package:pdf_plus/pdf.dart';           // low-level PDF APIs
import 'package:pdf_plus/signing.dart';       // signing and validation
import 'package:pdf_plus/pki.dart';           // PKI helpers
```

## Quick start: generate a PDF

```dart
import 'dart:io';
import 'package:pdf_plus/widgets.dart' as pw;

Future<void> main() async {
  final pdf = pw.Document();

  pdf.addPage(
    pw.Page(
      build: (context) => pw.Center(
        child: pw.Text('Hello World!'),
      ),
    ),
  );

  await File('example.pdf').writeAsBytes(await pdf.save());
}
```

## Basic example: sign an existing PDF

```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

Future<void> main() async {
  final inputBytes = await File('input.pdf').readAsBytes();
  final p12Bytes = await File('certificate.p12').readAsBytes();

  final signer = await PdfSignatureSigner.fromPkcs12Bytes(
    pkcs12Bytes: p12Bytes,
    password: 'your-certificate-password',
  );

  final doc = PdfLoadedDocument.fromBytes(inputBytes);
  await doc.addSignature(
    PdfSignatureRequest(
      pageNumber: 1,
      fieldName: 'Signature1',
      signer: signer,
      bounds: PdfSignatureBounds.topLeft(
        left: 40,
        top: 80,
        width: 220,
        height: 70,
      ),
      reason: 'Approval',
      location: 'Brazil',
    ),
  );

  final signedBytes = await doc.save();
  await File('signed.pdf').writeAsBytes(signedBytes);
  doc.dispose();
}
```

## Basic example: validate signatures

```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

Future<void> main() async {
  final bytes = await File('signed.pdf').readAsBytes();

  final report = await PdfSignatureValidator().validateAllSignatures(
    bytes,
    includeCertificates: true,
    includeSignatureFields: true,
  );

  for (final sig in report.signatures) {
    print(
      'Signature #${sig.signatureIndex}: '
      'status=${sig.validationStatus} '
      'cms=${sig.cmsValid} digest=${sig.digestValid} intact=${sig.intact}',
    );
  }
}
```

## Useful repository scripts

- `dart tool/pdf_info.dart <file.pdf>`
- `dart tool/iti_report.dart <file.pdf>`
- `dart tool/setup_certs_and_sign.dart`

## Run tests

```bash
dart test
```

## License

This project is distributed under Apache-2.0. See `LICENSE`.