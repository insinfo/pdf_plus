
# Documentação Detalhada do pdf_plus

## Visão Geral
O `pdf_plus` é uma biblioteca Dart para criação, manipulação, assinatura e validação de arquivos PDF, além de prover widgets e utilitários para gráficos, tabelas, PKI e mais.

---

## Exemplos de Uso

### 1. Criando um PDF Simples
```dart
import 'dart:io';
import 'package:pdf_plus/widgets.dart' as pw;

void main() async {
	final pdf = pw.Document();
	pdf.addPage(
		pw.Page(
			build: (pw.Context context) => pw.Center(
				child: pw.Text('Hello World!'),
			),
		),
	);
	final file = File('example.pdf');
	await file.writeAsBytes(await pdf.save());
}
```

### 2. Usando Widgets Avançados
```dart
pdf.addPage(
	pw.Page(
		build: (context) => pw.Column(
			children: [
				pw.Text('Título', style: pw.TextStyle(fontSize: 24)),
				pw.Table(
					border: pw.TableBorder.all(),
					children: [
						pw.TableRow(children: [pw.Text('A'), pw.Text('B')]),
						pw.TableRow(children: [pw.Text('1'), pw.Text('2')]),
					],
				),
				pw.BarcodeWidget(
					barcode: pw.Barcode.qrCode(),
					data: 'https://exemplo.com',
				),
			],
		),
	),
);
```

### 3. Assinando um PDF Digitalmente
```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

final inputBytes = File('documento.pdf').readAsBytesSync();
final document = PdfLoadedDocument.fromBytes(inputBytes);

final cert = X509Certificate.fromPem(userCertPem);
final inter = X509Certificate.fromPem(interCertPem);
final root = X509Certificate.fromPem(rootCertPem);

final signer = PdfSignatureSigner.pem(
	privateKeyPem: userKeyPem,
	certificate: cert,
	chain: [inter, root],
);

// PKCS#12 (.pfx/.p12) com decoder em Dart
// final signer = await PdfSignatureSigner.fromPkcs12Bytes(
// 	pkcs12Bytes: File('certificado.pfx').readAsBytesSync(),
// 	password: 'senha123',
// 	decoder: MeuPkcs12Decoder(),
// );

await document.addSignature(
	PdfSignatureRequest(
		pageNumber: 1,
		signer: signer,
		fieldName: 'AssinaturaDigital',
		bounds: PdfSignatureBounds.topLeft(
			left: 50,
			top: 50,
			width: 200,
			height: 100,
		),
		reason: 'Aprovacao de documento',
		location: 'Brasil',
		contactInfo: 'suporte@empresa.com',
		appearance: PdfSignatureAppearance(
			title: 'Assinatura Digital',
			reason: 'Aprovacao de documento',
			location: 'Brasil',
		),
	),
);

final outputBytes = await document.save();
File('output_signed.pdf').writeAsBytesSync(outputBytes);
document.dispose();
```

### 3.2 Aparência personalizada com logo (drawAppearance)
Use `drawAppearance` para desenhar um visual personalizado. Para imagens,
crie a `PdfImage` usando o `document` associado ao `PdfGraphics`.
```dart
import 'dart:io';
import 'package:pdf_plus/pdf.dart' as pdf;
import 'package:pdf_plus/signing.dart';

final inputBytes = File('documento.pdf').readAsBytesSync();
final document = PdfLoadedDocument.fromBytes(inputBytes);

final signer = PdfSignatureSigner.pem(
  privateKeyPem: userKeyPem,
  certificate: X509Certificate.fromPem(userCertPem),
  chain: [
    X509Certificate.fromPem(interCertPem),
    X509Certificate.fromPem(rootCertPem),
  ],
);

final logoBytes = File('logo.png').readAsBytesSync();

await document.addSignature(
  PdfSignatureRequest(
    pageNumber: 1,
    signer: signer,
    fieldName: 'AssinaturaVisual',
    bounds: PdfSignatureBounds.topLeft(
      left: 50,
      top: 50,
      width: 240,
      height: 90,
    ),
    drawAppearance: (graphics, rect) {
      final font = graphics.defaultFont;
      if (font == null) return;

      // Use o documento correto associado ao graphics.
      final logo = pdf.PdfImage.file(graphics.document, bytes: logoBytes);

      graphics.drawRect(0, 0, rect.width, rect.height);
      graphics.strokePath();
      graphics.drawImage(logo, 8, 8, 48, 48);
      graphics.drawString(font, 10, 'Assinado digitalmente', 64, 28);
    },
  ),
);

final outputBytes = await document.save();
File('output_signed.pdf').writeAsBytesSync(outputBytes);
document.dispose();
```

### 3.1 Timestamp RFC 3161 (FreeTSA opcional)
```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

final inputBytes = File('documento.pdf').readAsBytesSync();
final document = PdfLoadedDocument.fromBytes(inputBytes);

final signer = PdfSignatureSigner.pem(
	privateKeyPem: userKeyPem,
	certificate: X509Certificate.fromPem(userCertPem),
	chain: [
		X509Certificate.fromPem(interCertPem),
		X509Certificate.fromPem(rootCertPem),
	],
);

final tsa = PdfTimestampClient.freetsa(
	hashAlgorithm: PdfTimestampHashAlgorithm.sha512,
	validationOptions: PdfTimestampValidationOptions(
		// Baixe o cacert.pem da FreeTSA e passe como raiz confiavel.
		trustedRootsPem: [File('cacert.pem').readAsStringSync()],
		requireTrustedChain: true,
	),
);

await document.addSignature(
	PdfSignatureRequest(
		pageNumber: 1,
		signer: signer,
		fieldName: 'AssinaturaDigital',
		bounds: PdfSignatureBounds.topLeft(
			left: 50,
			top: 50,
			width: 200,
			height: 100,
		),
		reason: 'Aprovacao de documento',
		location: 'Brasil',
		timestampProvider: tsa.timestampSignature,
	),
);
```

### 3.3 APIs de assinatura eletrônica (visão geral)
Esta biblioteca oferece três níveis de API para assinatura:
- **Alto nível**: `PdfLoadedDocument` + `PdfSignatureRequest`
- **Serviço**: `PdfSignatureService` + `PdfSignatureField`
- **Ferramentas**: `PdfSignatureTools` (prepare/embed)

Use o nível que melhor se encaixa no seu fluxo.

### 3.4 Alto nível (PdfLoadedDocument)
```dart
final document = PdfLoadedDocument.fromBytes(File('documento.pdf').readAsBytesSync());
final signer = PdfSignatureSigner.pem(
  privateKeyPem: userKeyPem,
  certificate: X509Certificate.fromPem(userCertPem),
  chain: [X509Certificate.fromPem(interCertPem), X509Certificate.fromPem(rootCertPem)],
);

await document.addSignature(
  PdfSignatureRequest(
    pageNumber: 1,
    signer: signer,
    fieldName: 'Assinatura1',
    bounds: PdfSignatureBounds.topLeft(left: 50, top: 50, width: 220, height: 90),
    reason: 'Aprovação',
    location: 'Brasil',
  ),
);
final outputBytes = await document.save();
File('output_signed.pdf').writeAsBytesSync(outputBytes);
document.dispose();
```

### 3.5 Serviço (PdfSignatureService)
```dart
final service = PdfSignatureService();
final signedBytes = await service.signBytes(
  inputBytes: File('documento.pdf').readAsBytesSync(),
  externalSigner: PdfPemSigner(
    privateKeyPem: userKeyPem,
    certificatePem: userCertPem,
    chainPem: [interCertPem, rootCertPem],
  ),
  field: PdfSignatureField.pageTopLeft(
    pageNumber: 1,
    fieldName: 'Assinatura1',
    left: 50,
    top: 50,
    width: 220,
    height: 90,
  ),
  signature: PdfSignatureConfig(
    reason: 'Aprovação',
    location: 'Brasil',
    signingTime: DateTime.now(),
  ),
);
File('output_signed.pdf').writeAsBytesSync(signedBytes);
```

### 3.6 Fluxo externo (prepare/embed)
```dart
final prepared = await PdfSignatureTools.prepareExternalSignature(
  inputBytes: File('documento.pdf').readAsBytesSync(),
  pageNumber: 1,
  bounds: PdfRect(50, 50, 220, 90),
  fieldName: 'Assinatura1',
);

// Enviar prepared.hashBase64 para assinar externamente (HSM/A3).
final pkcs7 = await meuAssinadorExterno(prepared.hashBase64);

final signed = PdfSignatureTools.embedExternalSignature(
  preparedPdfBytes: prepared.preparedPdfBytes,
  pkcs7Bytes: pkcs7,
);
File('output_signed.pdf').writeAsBytesSync(signed);
```

### 3.7 Assinatura visível personalizada (drawAppearance)
```dart
import 'package:pdf_plus/pdf.dart' as pdf;

final logoBytes = File('logo.png').readAsBytesSync();
await document.addSignature(
  PdfSignatureRequest(
    pageNumber: 1,
    signer: signer,
    fieldName: 'AssinaturaVisual',
    bounds: PdfSignatureBounds.topLeft(left: 50, top: 50, width: 240, height: 90),
    drawAppearance: (graphics, rect) {
      final font = graphics.defaultFont;
      if (font == null) return;
      final logo = pdf.PdfImage.file(graphics.document, bytes: logoBytes);
      graphics.drawRect(0, 0, rect.width, rect.height);
      graphics.strokePath();
      graphics.drawImage(logo, 8, 8, 48, 48);
      graphics.drawString(font, 10, 'Assinado digitalmente', 64, 28);
    },
  ),
);
```

### 4. Gerando Certificados X.509 (PKI)
```dart
import 'package:pdf_plus/pki.dart';
import 'package:pointycastle/export.dart';

final keyPair = PkiUtils.generateRsaKeyPair();
final rootCert = PkiBuilder.createRootCertificate(
	keyPair: keyPair,
	dn: 'CN=Minha CA, O=Empresa, C=BR',
);
final rootPem = rootCert.toPem();
```

---

## Principais Classes e Funções

### PdfDocument
Classe base para geração e manipulação de PDFs.
- Permite adicionar páginas, objetos, anotações, assinaturas, outlines, etc.
- Suporta compressão, criptografia, modos de visualização e metadados.

#### Exemplo:
```dart
final doc = PdfDocument();
// ... adicionar páginas e conteúdo ...
final bytes = doc.save();
```

### Document (Widgets)
Classe de alto nível para construção de PDFs com widgets.
- Permite adicionar páginas, definir tema, metadados e conteúdo visual.

#### Exemplo:
```dart
final doc = pw.Document();
doc.addPage(pw.Page(build: (ctx) => pw.Text('Exemplo')));
```

### PdfCmsSigner
Classe utilitária para assinatura digital de PDFs (CMS/PKCS#7).
- Permite assinar um digest SHA-256 com chave privada RSA e certificado PEM.

#### Exemplo:
```dart
final cms = PdfCmsSigner.signDetachedSha256RsaFromPem(
	contentDigest: digest,
	privateKeyPem: chavePrivada,
	certificatePem: certificado,
);
```

### PkiBuilder e PkiUtils
Utilitários para geração de chaves, números seriais e certificados X.509.

#### Exemplo:
```dart
final keyPair = PkiUtils.generateRsaKeyPair();
final cert = PkiBuilder.createUserCertificate(
	keyPair: keyPair,
	issuerKeyPair: caKeyPair,
	subjectDn: 'CN=Usuário',
	issuerDn: 'CN=CA',
	serialNumber: 123,
);
final certDer = cert.der;
```

---

## Widgets Comuns

- **Text**: Adiciona texto ao PDF.
	```dart
	pw.Text('Texto simples', style: pw.TextStyle(fontSize: 18))
	```
- **Table**: Cria tabelas.
- **BarcodeWidget**: Gera códigos de barras e QR codes.
- **Image**: Insere imagens.
- **Chart**: Gráficos diversos.

Consulte a pasta `lib/src/widgets/` para mais widgets e exemplos.

---

## Observações
- O código é modular, com separação clara entre PDF, widgets, assinatura e PKI.
- Para detalhes de cada widget, consulte os arquivos em `lib/src/widgets/`.
- Para detalhes de PKI, consulte `lib/src/pki/`.

---

*Documentação detalhada gerada automaticamente por GitHub Copilot em 30/01/2026.*
