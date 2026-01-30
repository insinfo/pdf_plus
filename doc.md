
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
import 'package:pdf_plus/signing.dart';

final signedPdf = PdfCmsSigner.signDetachedSha256RsaFromPem(
	contentDigest: /* digest do conteúdo do PDF */,
	privateKeyPem: '-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----',
	certificatePem: '-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----',
);
// O resultado é um CMS (PKCS#7) que pode ser embutido no PDF
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
