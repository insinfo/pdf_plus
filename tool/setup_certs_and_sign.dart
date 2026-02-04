//C:\MyDartProjects\pdf_plus\tool\setup_certs_and_sign.dart
import 'dart:io';
import 'dart:typed_data';
import 'dart:math' as math;
import 'dart:isolate';
import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/pdf.dart' as pdf;
import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/widgets.dart' as pw;
import 'package:pdf_plus/src/pdf/validation/pdf_signature_validator.dart'
    as sigval;

Future<void> main() async {
  final totalWatch = Stopwatch()..start();
  await _analyzeReferencePdf(
    r'test/assets/pdfs/3 ass leonardo e stefan e mauricio.pdf',
  );
  print('Generating certificates...');

  const rsaCertainty = 32;
  final keyPairs = await Future.wait([
    _timeAsync(
      'RSA root key',
      () => Isolate.run(
        () => PkiUtils.generateRsaKeyPair(
          bitStrength: 4096,
          certainty: rsaCertainty,
        ),
      ),
    ),
    _timeAsync(
      'RSA intermediate key',
      () => Isolate.run(
        () => PkiUtils.generateRsaKeyPair(
          bitStrength: 4096,
          certainty: rsaCertainty,
        ),
      ),
    ),
    _timeAsync(
      'RSA user key',
      () => Isolate.run(
        () => PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: rsaCertainty,
        ),
      ),
    ),
    _timeAsync(
      'RSA user2 key',
      () => Isolate.run(
        () => PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: rsaCertainty,
        ),
      ),
    ),
    _timeAsync(
      'RSA user3 key',
      () => Isolate.run(
        () => PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: rsaCertainty,
        ),
      ),
    ),
  ]);
  final rootKeyPair = keyPairs[0];
  final interKeyPair = keyPairs[1];
  final userKeyPair = keyPairs[2];
  final user2KeyPair = keyPairs[3];
  final user3KeyPair = keyPairs[4];

  final rootCert = _timeSync(
    'Root cert',
    () => PkiBuilder.createRootCertificate(
      keyPair: rootKeyPair,
      dn: 'CN=Test Root CA',
    ),
  );
  final interCert = _timeSync(
    'Intermediate cert',
    () => PkiBuilder.createIntermediateCertificate(
      keyPair: interKeyPair,
      issuerKeyPair: rootKeyPair,
      subjectDn: 'CN=Test Intermediate CA',
      issuerDn: 'CN=Test Root CA',
      serialNumber: 2,
    ),
  );
  final userCert = _timeSync(
    'User cert',
    () => PkiBuilder.createUserCertificate(
      keyPair: userKeyPair,
      issuerKeyPair: interKeyPair,
      subjectDn: 'CN=Test User',
      issuerDn: 'CN=Test Intermediate CA',
      serialNumber: 3,
    ),
  );
  final user2Cert = _timeSync(
    'User2 cert',
    () => PkiBuilder.createUserCertificate(
      keyPair: user2KeyPair,
      issuerKeyPair: interKeyPair,
      subjectDn: 'CN=Stefan Augusto Beloti Pizetta',
      issuerDn: 'CN=Test Intermediate CA',
      serialNumber: 4,
    ),
  );
  final user3Cert = _timeSync(
    'User3 cert',
    () => PkiBuilder.createUserCertificate(
      keyPair: user3KeyPair,
      issuerKeyPair: interKeyPair,
      subjectDn: 'CN=Leonardo Calheiros Oliveira',
      issuerDn: 'CN=Test Intermediate CA',
      serialNumber: 5,
    ),
  );

  final userKeyPem = PkiPemUtils.rsaPrivateKeyToPem(
    userKeyPair.privateKey as RSAPrivateKey,
  );
  final user2KeyPem = PkiPemUtils.rsaPrivateKeyToPem(
    user2KeyPair.privateKey as RSAPrivateKey,
  );
  final user3KeyPem = PkiPemUtils.rsaPrivateKeyToPem(
    user3KeyPair.privateKey as RSAPrivateKey,
  );
  final userCertPem = userCert;
  final user2CertPem = user2Cert;
  final user3CertPem = user3Cert;
  final interCertPem = interCert;
  final rootCertPem = rootCert;

  print('Certificates generated.');

  print('Creating and signing PDF...');

  final pdf = _timeSync('PDF document', () => pw.Document());

  _timeSync('Add page', () {
    pdf.addPage(
      pw.Page(
        build: (context) => pw.Column(
          crossAxisAlignment: pw.CrossAxisAlignment.start,
          children: [
            pw.Text('Hello, Signed World!'),
            pw.SizedBox(height: 12),
            pw.Text('Assinaturas incrementais abaixo:'),
          ],
        ),
      ),
    );
  });

  var pdfBytes = await _timeAsync('Save base PDF', pdf.save);
  pdfBytes = await _timeAsync(
    'Pre-create signature fields',
    () => _prepareBaseSignatureFields(pdfBytes),
  );
  final timestampClient = PdfTimestampClient.freetsa();
  final urlValidacao = 'https://exemplo.com/assinaturas/validar';
  final logoPath = 'test/assets/images/brasao_editado_1.png';
  final logoBytes = File(logoPath).readAsBytesSync();

  final signer1 = PdfSignatureSigner.pem(
    privateKeyPem: userKeyPem,
    certificate: userCertPem,
    chain: [
      interCertPem,
      rootCertPem,
    ],
  );
  final signer2 = PdfSignatureSigner.pem(
    privateKeyPem: user2KeyPem,
    certificate: user2CertPem,
    chain: [
      interCertPem,
      rootCertPem,
    ],
  );
  final signer3 = PdfSignatureSigner.pem(
    privateKeyPem: user3KeyPem,
    certificate: user3CertPem,
    chain: [
      interCertPem,
      rootCertPem,
    ],
  );

  pdfBytes = await _timeAsync(
    'Signature 1',
    () => _signAsPerson(
      inputBytes: pdfBytes,
      signer: signer1,
      fieldName: 'Signature1',
      reason: 'Assinatura 1',
      location: 'OpenSSL Tool',
      bounds: PdfSignatureBounds.topLeft(
        left: 80,
        top: 160,
        width: 320,
        height: 95,
      ),
      dadosUsuario: _DadosUsuarioAssinatura(
        nome: 'MAURICIO SOARES DOS ANJOS',
        cpf: '02094890732',
      ),
      urlValidacao: urlValidacao,
      logoBytes: logoBytes,
      timestampClient: timestampClient,
    ),
  );

  pdfBytes = await _timeAsync(
    'Signature 2',
    () => _signAsPerson(
      inputBytes: pdfBytes,
      signer: signer2,
      fieldName: 'Signature2',
      reason: 'Assinatura 2',
      location: 'OpenSSL Tool',
      bounds: PdfSignatureBounds.topLeft(
        left: 80,
        top: 270,
        width: 320,
        height: 95,
      ),
      dadosUsuario: _DadosUsuarioAssinatura(
        nome: 'STEFAN AUGUSTO BELOTI PIZETTA',
        cpf: '11243700000',
      ),
      urlValidacao: urlValidacao,
      logoBytes: logoBytes,
      timestampClient: timestampClient,
    ),
  );

  pdfBytes = await _timeAsync(
    'Signature 3',
    () => _signAsPerson(
      inputBytes: pdfBytes,
      signer: signer3,
      fieldName: 'Signature3',
      reason: 'Assinatura 3',
      location: 'OpenSSL Tool',
      bounds: PdfSignatureBounds.topLeft(
        left: 80,
        top: 380,
        width: 320,
        height: 95,
      ),
      dadosUsuario: _DadosUsuarioAssinatura(
        nome: 'LEONARDO CALHEIROS OLIVEIRA',
        cpf: '10901000000',
      ),
      urlValidacao: urlValidacao,
      logoBytes: logoBytes,
      timestampClient: timestampClient,
    ),
  );

  final output = File('signed_output.pdf');
  final finalBytes = pdfBytes;
  _timeSync('Write output', () => output.writeAsBytesSync(finalBytes));

  print('PDF signed and saved to signed_output.pdf');
  await _timeAsync(
    'Validate signatures',
    () => _validateSignatures(finalBytes),
  );
  _printSignatureInternals(finalBytes);
  totalWatch.stop();
  print('Total time: ${_formatElapsed(totalWatch)}');
  exit(0);
}

class _DadosUsuarioAssinatura {
  _DadosUsuarioAssinatura({required this.nome, required this.cpf});

  final String nome;
  final String cpf;
}

Future<Uint8List> _signAsPerson({
  required Uint8List inputBytes,
  required PdfSignatureSigner signer,
  required String fieldName,
  required String reason,
  required String location,
  required PdfSignatureBounds bounds,
  required _DadosUsuarioAssinatura dadosUsuario,
  required String urlValidacao,
  required PdfTimestampClient timestampClient,
  Uint8List? logoBytes,
  int? docMdpPermissionP,
}) async {
  final document = PdfLoadedDocument.fromBytes(inputBytes);
  await document.addSignature(
    PdfSignatureRequest(
      pageNumber: 1,
      signer: signer,
      fieldName: fieldName,
      bounds: bounds,
      reason: reason,
      location: location,
      docMdpPermissionP: docMdpPermissionP,
      timestampProvider: timestampClient.timestampSignature,
      drawAppearance: (graphics, rect, doc) {
        _drawAssinaturaVisual(
          document: doc,
          graphics: graphics,
          bounds: rect,
          dadosUsuario: dadosUsuario,
          dataAssinatura: DateTime.now(),
          urlValidacao: urlValidacao,
          logoBytes: logoBytes,
        );
      },
    ),
  );
  return document.save();
}

Future<Uint8List> _prepareBaseSignatureFields(Uint8List inputBytes) async {
  final document = pdf.PdfDocument.parseFromBytes(inputBytes);
  document.addSignatureFieldTopLeft(
    pageNumber: 1,
    left: 80,
    top: 160,
    width: 320,
    height: 95,
    fieldName: 'Signature1',
  );
  document.addSignatureFieldTopLeft(
    pageNumber: 1,
    left: 80,
    top: 270,
    width: 320,
    height: 95,
    fieldName: 'Signature2',
  );
  document.addSignatureFieldTopLeft(
    pageNumber: 1,
    left: 80,
    top: 380,
    width: 320,
    height: 95,
    fieldName: 'Signature3',
  );
  return document.save(useIsolate: false);
}

void _drawAssinaturaVisual({
  required pdf.PdfDocument document,
  required pdf.PdfGraphics graphics,
  required pdf.PdfRect bounds,
  required _DadosUsuarioAssinatura dadosUsuario,
  required DateTime dataAssinatura,
  required String urlValidacao,
  Uint8List? logoBytes,
}) {
  final font = graphics.defaultFont;
  if (font == null) return;

  const padding = 8.0;
  final logoBoxWidth = 72.0;
  final textStartX = padding + logoBoxWidth + 4.0;
  final contentWidth = math.max(0.0, bounds.width - textStartX - padding);

  graphics.saveContext();
  graphics.setStrokeColor(pdf.PdfColors.grey700);
  graphics.setLineWidth(0.8);
  graphics.drawRect(0, 0, bounds.width, bounds.height);
  graphics.strokePath();

  if (logoBytes != null) {
    try {
      final image = pdf.PdfImage.file(document, bytes: logoBytes);
      final logoBoxHeight = bounds.height - (padding * 2);
      final maxLogoWidth = logoBoxWidth - 10;
      final maxLogoHeight = logoBoxHeight - 10;
      final aspect = image.width / image.height;
      var drawW = maxLogoWidth;
      var drawH = drawW / aspect;
      if (drawH > maxLogoHeight) {
        drawH = maxLogoHeight;
        drawW = drawH * aspect;
      }
      final left = padding + (logoBoxWidth - drawW) / 2;
      final top = padding + 2;
      final bottom = bounds.height - top - drawH;
      graphics.drawImage(image, left, bottom, drawW, drawH);
    } catch (_) {
      _drawLogoFallback(
        graphics: graphics,
        font: font,
        left: padding,
        top: padding,
        width: logoBoxWidth,
        height: bounds.height - (padding * 2),
        boundsHeight: bounds.height,
      );
    }
  } else {
    _drawLogoFallback(
      graphics: graphics,
      font: font,
      left: padding,
      top: padding,
      width: logoBoxWidth,
      height: bounds.height - (padding * 2),
      boundsHeight: bounds.height,
    );
  }

  final small = 7.0;
  final regular = 8.0;
  final bold = 9.0;
  const gap = 2.0;

  var y = bounds.height - padding - _fontAscent(font, small);
  _drawLine(
    graphics: graphics,
    font: font,
    size: small,
    text: 'Documento assinado digitalmente pelo SALI',
    x: textStartX,
    y: y,
    color: pdf.PdfColor.fromRgbInt(80, 80, 80),
  );
  y -= _lineHeight(font, small) + gap;

  _drawLine(
    graphics: graphics,
    font: font,
    size: bold,
    text: dadosUsuario.nome.toUpperCase(),
    x: textStartX,
    y: y,
  );
  y -= _lineHeight(font, bold) + gap;

  _drawLine(
    graphics: graphics,
    font: font,
    size: regular,
    text: 'CPF: ${_maskCpf(dadosUsuario.cpf)}',
    x: textStartX,
    y: y,
  );
  y -= _lineHeight(font, regular) + gap;

  _drawLine(
    graphics: graphics,
    font: font,
    size: regular,
    text: 'Data: ${_formatDateTimeBrazil(dataAssinatura)}',
    x: textStartX,
    y: y,
  );
  y -= _lineHeight(font, regular) + gap;

  _drawLine(
    graphics: graphics,
    font: font,
    size: small,
    text: 'Verifique em:',
    x: textStartX,
    y: y,
    color: pdf.PdfColor.fromRgbInt(60, 60, 60),
  );
  y -= _lineHeight(font, small) + 1;

  final urlLines = _splitUrlToLines(font, urlValidacao, contentWidth, small);
  for (final line in urlLines) {
    _drawLine(
      graphics: graphics,
      font: font,
      size: small,
      text: line,
      x: textStartX,
      y: y,
      color: pdf.PdfColor.fromRgbInt(0, 102, 204),
    );
    y -= _lineHeight(font, small) + 1;
  }

  graphics.restoreContext();
}

void _drawLogoFallback({
  required pdf.PdfGraphics graphics,
  required pdf.PdfFont font,
  required double left,
  required double top,
  required double width,
  required double height,
  required double boundsHeight,
}) {
  graphics.setFillColor(pdf.PdfColor.fromRgbInt(240, 240, 245));
  graphics.drawRect(left, boundsHeight - top - height, width, height);
  graphics.fillPath();
  final size = 10.0;
  final x = left + 8;
  final y = boundsHeight - top - (height / 2) - _fontAscent(font, size) / 2;
  _drawLine(
    graphics: graphics,
    font: font,
    size: size,
    text: 'SALI',
    x: x,
    y: y,
    color: pdf.PdfColor.fromRgbInt(134, 15, 239),
  );
}

void _drawLine({
  required pdf.PdfGraphics graphics,
  required pdf.PdfFont font,
  required double size,
  required String text,
  required double x,
  required double y,
  pdf.PdfColor? color,
}) {
  if (color != null) {
    graphics.setFillColor(color);
  }
  graphics.drawString(font, size, text, x, y);
}

double _lineHeight(pdf.PdfFont font, double size) {
  return (font.ascent - font.descent) * size;
}

double _fontAscent(pdf.PdfFont font, double size) {
  return font.ascent * size;
}

List<String> _splitUrlToLines(
  pdf.PdfFont font,
  String url,
  double maxWidth,
  double size,
) {
  if (maxWidth <= 0) return [url];
  if (_textWidth(font, size, url) <= maxWidth) return [url];

  final lines = <String>[];
  var remaining = url;
  for (var lineIndex = 0; lineIndex < 1; lineIndex++) {
    if (_textWidth(font, size, remaining) <= maxWidth) {
      break;
    }
    var splitIndex = -1;
    for (var i = remaining.length - 1; i > 0; i--) {
      final candidate = remaining.substring(0, i);
      if (_textWidth(font, size, candidate) <= maxWidth) {
        final prev = remaining[i - 1];
        if (prev == '/' || prev == '?' || prev == '&' || prev == '-') {
          splitIndex = i;
          break;
        }
      }
    }
    if (splitIndex == -1) {
      for (var i = remaining.length - 1; i > 0; i--) {
        final candidate = remaining.substring(0, i);
        if (_textWidth(font, size, candidate) <= maxWidth) {
          splitIndex = i;
          break;
        }
      }
    }
    if (splitIndex <= 0) break;
    lines.add(remaining.substring(0, splitIndex));
    remaining = remaining.substring(splitIndex);
  }

  lines.add(remaining);
  return lines;
}

double _textWidth(pdf.PdfFont font, double size, String text) {
  final metrics = font.stringMetrics(text);
  return metrics.width * (size / font.unitsPerEm);
}

String _maskCpf(String cpf) {
  final digits = cpf.replaceAll(RegExp(r'\\D'), '');
  if (digits.length != 11) return cpf;
  return '${digits.substring(0, 3)}.${digits.substring(3, 6)}.'
      '${digits.substring(6, 9)}-${digits.substring(9)}';
}

String _formatDateTimeBrazil(DateTime dt) {
  final two = (int v) => v.toString().padLeft(2, '0');
  return '${two(dt.day)}/${two(dt.month)}/${dt.year} ${two(dt.hour)}:${two(dt.minute)}';
}

Future<void> _analyzeReferencePdf(String path) async {
  final file = File(path);
  if (!file.existsSync()) {
    print('Reference PDF not found: $path');
    return;
  }
  final bytes = file.readAsBytesSync();
  final report = await PdfSignatureValidator().validateAllSignatures(
    bytes,
    includeCertificates: true,
    includeSignatureFields: true,
  );
  print('Reference PDF: $path');
  print('Reference signatures: ${report.signatures.length}');
  for (final sig in report.signatures) {
    final field = sig.signatureField?.fieldName ?? 'campo_desconhecido';
    final page = sig.signatureField?.pageIndex;
    final pageText = page == null ? '' : ' page=${page + 1}';
    final docMdp = sig.docMdp.permissionP;
    print(
      ' - #${sig.signatureIndex} field=$field$pageText docMdpP=${docMdp ?? '-'}',
    );
  }
}

Future<void> _validateSignatures(Uint8List pdfBytes) async {
  final report = await PdfSignatureValidator().validateAllSignatures(
    pdfBytes,
    includeCertificates: true,
    includeSignatureFields: true,
  );

  print('Validation report: ${report.signatures.length} assinatura(s)');
  for (final sig in report.signatures) {
    print(
      ' - #${sig.signatureIndex} cmsValid=${sig.cmsValid} digestValid=${sig.digestValid} intact=${sig.intact}',
    );
    if (sig.message != null) {
      print('message=${sig.message}');
    }
    if (sig.signingTime != null) {
      print('signingTime=${sig.signingTime}');
    }
    if (sig.signaturePolicyOid != null) {
      print('policyOid=${sig.signaturePolicyOid}');
    }
    if (sig.docMdp.permissionP != null) {
      print(
        'docMdp permissionP=${sig.docMdp.permissionP} cert=${sig.docMdp.isCertificationSignature}',
      );
    }
  }
}

void _printSignatureInternals(Uint8List pdfBytes) {
  final ranges = sigval.findAllSignatureByteRanges(pdfBytes);
  print('ByteRange details: ${ranges.length} assinatura(s)');
  for (var i = 0; i < ranges.length; i++) {
    final range = ranges[i];
    print(
      ' - #$i ByteRange=[${range.join(' ')}]',
    );
  }

  final values = sigval.findSignatureValueRefs(pdfBytes);
  if (values.isNotEmpty) {
    print('Field /V references:');
    for (final entry in values.entries) {
      print(' - ${entry.key}: ${entry.value}');
    }
  }
}

T _timeSync<T>(String label, T Function() action) {
  final watch = Stopwatch()..start();
  try {
    return action();
  } finally {
    watch.stop();
    print('$label: ${_formatElapsed(watch)}');
  }
}

Future<T> _timeAsync<T>(String label, Future<T> Function() action) async {
  final watch = Stopwatch()..start();
  try {
    return await action();
  } finally {
    watch.stop();
    print('$label: ${_formatElapsed(watch)}');
  }
}

String _formatElapsed(Stopwatch watch) {
  final ms = watch.elapsedMilliseconds;
  final seconds = (ms / 1000).toStringAsFixed(2);
  return '${seconds}s';
}
