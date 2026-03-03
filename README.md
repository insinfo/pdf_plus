# pdf_plus

[![Dart CI](https://github.com/insinfo/pdf_plus/actions/workflows/ci.yml/badge.svg)](https://github.com/insinfo/pdf_plus/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/insinfo/pdf_plus/branch/main/graph/badge.svg)](https://codecov.io/gh/insinfo/pdf_plus)

A Dart library for PDF generation and manipulation, based on `dart_pdf`, with additional focus on digital signatures, validation, and PKI workflows.

fork from https://github.com/DavBfr/dart_pdf

## What this package provides

- High-level PDF creation API (`widgets.dart`) and low-level PDF object model (`pdf.dart`)
- Incremental digital signing (PAdES/CMS) with visible signature support
- External signing flow for tokens, HSM, and custom signers
- Signature validation with integrity checks, certificate-chain validation, and revocation support (CRL/OCSP)
- PKI utilities for certificates, keystores, and PKCS#12 handling

## Requirements

- Dart SDK `^3.6.0`

## Installation

In your project's `pubspec.yaml`:

```yaml
dependencies:
  pdf_plus: ^3.16.0
```

Then run:

```bash
dart pub get
```

## Package entry points

- `package:pdf_plus/widgets.dart` — high-level document composition
- `package:pdf_plus/pdf.dart` — low-level PDF API
- `package:pdf_plus/signing.dart` — signing, validation, parsing, and security inspection
- `package:pdf_plus/pki.dart` — PKI and keystore helpers

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

## Basic example: sign an existing PDF (PAdES)

```dart
import 'dart:io';
import 'dart:typed_data';
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

## Example: external signing flow (HSM/token friendly)

Use this flow when the private key must stay outside your Dart process.

```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

Future<void> main() async {
  final inputBytes = await File('input.pdf').readAsBytes();

  final prepared = await PdfSignatureTools.prepareExternalSignature(
    inputBytes: inputBytes,
    pageNumber: 1,
    fieldName: 'Signature1',
    bounds: PdfRect(40, 80, 220, 70),
  );

  // Send prepared.hashBase64 to your external signer (token/HSM/service)
  // and receive detached CMS (PKCS#7 DER bytes).
  final pkcs7Bytes = await signExternally(prepared.hashBase64);

  final signedBytes = PdfSignatureTools.embedExternalSignature(
    preparedPdfBytes: prepared.preparedPdfBytes,
    pkcs7Bytes: pkcs7Bytes,
  );

  await File('signed_external.pdf').writeAsBytes(signedBytes);
}

Future<Uint8List> signExternally(String hashBase64) async {
  throw UnimplementedError('Integrate with your external signer.');
}
```

## Example: prepared context for faster repeated validation

When you need multiple validation/report operations for the same PDF,
reuse parsing work with `PdfSignaturePreparedContext`.

```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

Future<void> main() async {
  final bytes = await File('signed.pdf').readAsBytes();

  final validator = PdfSignatureValidator(enableInMemoryParseCache: true);
  final prepared = validator.prepareContext(
    bytes,
    includeSignatureFields: true,
    includeSignatureContents: true,
  );

  final report = await validator.validateAllSignatures(
    bytes,
    includeSignatureFields: true,
    includeCertificates: true,
    preparedContext: prepared,
  );

  final api = PdfValidationApi();
  final preflight = await api.preflightSignaturesFast(
    bytes,
    preparedContext: prepared,
  );

  print('signatures=${report.signatures.length} quick=${preflight.signatures.length}');
}
```

## Example: trust profiles (multiple trust stores)

```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

Future<void> main() async {
  final bytes = await File('signed.pdf').readAsBytes();

  final rootsA = PdfPemUtils.decodePemBlocks(
    await File('roots_a.pem').readAsString(),
    'CERTIFICATE',
    lenient: true,
  );
  final rootsB = PdfPemUtils.decodePemBlocks(
    await File('roots_b.pem').readAsString(),
    'CERTIFICATE',
    lenient: true,
  );

  final result = await PdfValidationApi().validateWithTrustProfiles(
    bytes,
    trustProfiles: [
      PdfTrustProfile(
        id: 'profile-a',
        provider: PdfInMemoryTrustedRootsProvider(rootsA),
      ),
      PdfTrustProfile(
        id: 'profile-b',
        provider: PdfInMemoryTrustedRootsProvider(rootsB),
      ),
    ],
    includeCertificates: true,
    includeSignatureFields: true,
  );

  for (final trust in result.trustResolutionBySignature) {
    print('signature=${trust.signatureIndex} profile=${trust.winningProfile} trusted=${trust.trusted}');
  }
}
```

## Example: inspect signature fields and contents quickly

```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

Future<void> main() async {
  final bytes = await File('signed.pdf').readAsBytes();

  final ranges = PdfSignatureValidator.findAllSignatureByteRanges(bytes);
  final contents = PdfSignatureValidator.extractAllSignatureContents(bytes);
  final refs = PdfSignatureValidator.findSignatureValueRefs(bytes);

  print('byteRanges=${ranges.length} cmsContents=${contents.length} refs=${refs.length}');
}
```

## Example: Base64 helpers (`package:pdf_plus/crypto.dart`)

```dart
import 'dart:typed_data';
import 'package:pdf_plus/crypto.dart';

void main() {
  final encodedText = base64EncodeUtf8('pdf_plus');
  final decodedText = base64DecodeUtf8(encodedText);

  final raw = Uint8List.fromList([1, 2, 3, 4]);
  final encodedBytes = base64EncodeBytes(raw);
  final decodedBytes = base64DecodeToBytes(encodedBytes);

  print(decodedText);
  print(decodedBytes);
}
```

## Example: text utilities for signature metadata

```dart
import 'package:pdf_plus/signing.dart';

void main() {
  final cn = PdfSignatureTextUtils.extractCommonName('CN=John Doe, O=Example');
  final normalized = PdfSignatureTextUtils.sanitizeSignerName('John Doe - 123.456.789-10');
  final localBr = PdfSignatureTextUtils.formatPdfDateBr("D:20260227214208-03'00");

  print(cn);         // John Doe
  print(normalized); // John Doe
  print(localBr);    // 27/02/2026 21:42:08 (example)
}
```

## Example: lenient PEM block decoding

Use lenient mode when you want to skip malformed blocks instead of failing fast.

```dart
import 'package:pdf_plus/signing.dart';

void main() {
  const pemBundle = '''
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
INVALID
-----END CERTIFICATE-----
''';

  final certs = PdfPemUtils.decodePemBlocks(
    pemBundle,
    'CERTIFICATE',
    lenient: true,
  );

  print('decoded cert blocks: ${certs.length}');
}
```

## Validation options

`PdfSignatureValidator().validateAllSignatures(...)` supports common verification scenarios:

- Trusted roots from PEM or custom providers
- Optional online chain completion (`certificateFetcher`)
- Optional revocation checks (`fetchCrls`, `fetchOcsp`, `strictRevocation`)
- Temporal validation options (`validateTemporal`, `validationTime`, signing-time mode)
- Certificate and signature-field extraction in reports

## Signing workflow summary

1. Load or generate PDF bytes.
2. Create a signer (`fromPkcs12Bytes`, PEM, or external signer).
3. Add signature fields and metadata (`reason`, `location`, timestamp, DocMDP).
4. Save signed bytes incrementally.
5. Validate signed output and inspect reports.


## Additional project documentation

- `fonts-management.md`

## Run tests

```bash
dart test
```

## License

This project is distributed under Apache-2.0. See `LICENSE`.