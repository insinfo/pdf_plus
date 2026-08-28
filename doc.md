
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

### 3.8 Novidades da versão 3.16.0 (validação e performance)

#### Contexto preparado e cache de parse (evita retrabalho)
Use `prepareContext` para reaproveitar parse entre preflight, extração e validação.

```dart
import 'dart:io';
import 'package:pdf_plus/signing.dart';

final bytes = File('documento.pdf').readAsBytesSync();

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
```

#### Métodos estáticos para inspeção rápida de assinatura
```dart
final ranges = PdfSignatureValidator.findAllSignatureByteRanges(bytes);
final cmsList = PdfSignatureValidator.extractAllSignatureContents(
	bytes,
	preparedContext: prepared,
);
final refs = PdfSignatureValidator.findSignatureValueRefs(bytes);
```

#### Extração de metadados de assinatura mais robusta
A extração de `fieldName`, `pageIndex`, `reason`, `location` e `name` foi reforçada
para PDFs com revisões incrementais e assinaturas em objeto indireto.

```dart
final report = await PdfSignatureValidator().validateAllSignatures(
	bytes,
	includeSignatureFields: true,
);

for (final sig in report.signatures) {
	print('campo=${sig.signatureField?.fieldName} '
			'pagina=${sig.signatureField?.pageIndex} '
			'motivo=${sig.signatureField?.reason}');
}
```

#### Utilitários de texto para assinaturas
```dart
final cn = PdfSignatureTextUtils.extractCommonName(certSubject);
final nomeLimpo = PdfSignatureTextUtils.sanitizeSignerName(cn);
final dataBr = PdfSignatureTextUtils.formatPdfDateBr('D:20260227214208-03\'00');
```

#### Novo módulo público Base64 (crypto)
```dart
import 'dart:typed_data';
import 'package:pdf_plus/crypto.dart';

final encoded = base64EncodeUtf8('pdf_plus');
final decoded = base64DecodeUtf8(encoded);

final bytesB64 = base64EncodeBytes(Uint8List.fromList([1, 2, 3]));
final bytesRaw = base64DecodeToBytes(bytesB64);
```

#### Decodificação PEM em modo tolerante
Quando necessário, ignore blocos inválidos sem interromper o processamento inteiro.

```dart
final certs = PdfPemUtils.decodePemBlocks(
	pemBundle,
	'CERTIFICATE',
	lenient: true,
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

### 5. Mesclando PDFs (merge)

`PdfDocument.merge` junta N arquivos em um documento novo. Cada entrada é lida
por um `PdfDocumentParser` com reparo habilitado, todos os objetos alcançáveis a
partir das páginas são materializados no destino com numeração nova, e as
referências são remapeadas.

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:pdf_plus/pdf.dart';

final bytes = await PdfDocument.merge(<Uint8List>[
	File('processo.pdf').readAsBytesSync(),
	File('anexo.pdf').readAsBytesSync(),
]);
await File('merged.pdf').writeAsBytes(bytes);
```

#### Controle fino com PdfDocumentMerger

`PdfDocumentMerger` dá acesso a cada origem individualmente e expõe os avisos.
O destino precisa ser um `PdfDocument` novo: mesclar dentro de um documento
carregado de arquivo produziria um incremental update com objetos de outro
arquivo dentro, o que não é um PDF válido (lança `PdfMergeException`).

```dart
final destino = PdfDocument();
final merger = PdfDocumentMerger(destino);

// Documento inteiro.
merger.append(PdfDocumentParser(bytesA, allowRepair: true), label: 'processo');

// Intervalo de páginas, inclusive nas duas pontas (índice base zero).
merger.importPageRange(
	PdfDocumentParser(bytesB, allowRepair: true),
	0,
	2,
	label: 'anexo',
);

// Uma única página.
merger.importPage(PdfDocumentParser(bytesC, allowRepair: true), 0);

merger.finish();                // idempotente
for (final aviso in merger.warnings) {
	print(aviso);                 // '[processo] assinatura digital invalidada...'
}
final saida = await destino.save();
```

Atalhos equivalentes existem em `PdfDocument`: `appendDocument`, `importPage` e
`importPageRange`.

#### Os dois modos

| Modo | O que faz | Fidelidade |
|---|---|---|
| `PdfMergeMode.objectImport` (padrão) | Importa o grafo de objetos da página | Conteúdo, recursos, anotações, links, campos de formulário, bookmarks, camadas e page labels |
| `PdfMergeMode.flatten` | Envolve o conteúdo da página em um Form XObject e o desenha na página nova | Somente o conteúdo gráfico |

No modo `objectImport` o content stream é copiado verbatim (com o `/Filter`
original preservado), os atributos herdados do nó `/Pages` da origem
(`/Resources`, `/MediaBox`, `/CropBox`, `/Rotate`) são materializados na página,
e os destinos nomeados de links e bookmarks são resolvidos para destinos
explícitos.

No modo `flatten` a página de origem vira um XObject desenhado na página nova.
É o modo previsível para documentos exóticos, ao custo de perder tudo que não
seja pintura: anotações, links e campos ficam pelo caminho.

```dart
final bytes = await PdfDocument.merge(
	documentos,
	options: const PdfMergeOptions(mode: PdfMergeMode.flatten),
);
```

#### Assinaturas digitais: as três chaves

Mesclar invalida **toda** assinatura digital existente. A assinatura cobre os
bytes exatos do documento em que foi aplicada, e a mesclagem reescreve o arquivo
inteiro; não há como contornar. Nenhuma ferramenta de mercado (PDF24, iLovePDF,
PDFsam, Acrobat, PDFBox, iText) recusa documentos assinados, e o `pdf_plus`
segue o mesmo comportamento, com três chaves independentes:

| Opção | Padrão | Efeito |
|---|---|---|
| `rejectSignedSources` | `false` | `true` lança `PdfMergeException` ao encontrar uma origem assinada |
| `keepInvalidSignatures` | `false` | `true` mantém os campos `/FT /Sig` com o CMS e os certificados; o visualizador reporta assinatura inválida |
| `removeSignatureAppearance` | `false` | `true` remove também o carimbo visual. Sem efeito quando `keepInvalidSignatures` está ligado |

A precedência é nessa ordem: `rejectSignedSources` > `keepInvalidSignatures` >
`removeSignatureAppearance`.

No padrão (as três em `false`) o campo de assinatura é removido e o carimbo
visual é mantido como anotação `/Subtype /Stamp` somente-leitura: a página
continua parecendo assinada e nenhum validador acusa assinatura quebrada,
porque não sobrou assinatura para conferir. Toda perda entra em
`PdfDocumentMerger.warnings`.

```dart
// Mantém os campos de assinatura, aceitando que apareçam como inválidos.
final bytes = await PdfDocument.merge(
	documentos,
	options: const PdfMergeOptions(keepInvalidSignatures: true),
);
```

Assinar **depois** de mesclar funciona normalmente: o documento mesclado é um
arquivo novo, sem revisão anterior, e o fluxo de assinatura opera sobre os bytes
salvos.

#### Demais opções

`PdfMergeOptions` também controla:

- `importAnnotations`, `importFormFields`, `importBookmarks`,
	`importNamedDestinations`, `importLayers`, `importPageLabels` — ligam e
	desligam cada subsistema (todos `true` por padrão).
- `fieldNameConflict` — `renameSuffix` (padrão, gera `nome`, `nome_2`, …),
	`keepFirst` ou `throwError` quando dois formulários têm campos homônimos.
- `importAttachments` (`false` por padrão) — anexos em `/Names /EmbeddedFiles`.
- `dropStructureTree` (`true` por padrão) — descarta a árvore de marcação
	(tagged PDF) e registra um aviso.
- `copyDocumentInfoFromFirst` (`false`) e `groupBookmarksPerDocument` (`false`).
- `deduplicateResources` (`true`) — reaproveita um único objeto para streams
	idênticos vindos de origens diferentes (fontes embutidas, logotipos).

#### Limites conhecidos

- **Origem criptografada não é suportada**: não há handler de segurança de
	leitura, e a mesclagem falha com `PdfMergeException` em vez de produzir saída
	corrompida em silêncio.
- A árvore de marcação estrutural (`/StructTreeRoot`) é descartada.
- Metadados XMP e `/ViewerPreferences` são os do destino.
- Uma faixa de `/PageLabels` cuja página inicial ficou fora do intervalo
	importado é descartada, e não recortada.

Exemplo executável completo em `example/merge_documents.dart`.

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

### PdfSignatureValidator (3.16+)
Validação de assinaturas com suporte a contexto preparado e cache opcional.

- `prepareContext(...)`: pré-parse para reuso entre chamadas.
- `validateAllSignatures(..., preparedContext: ...)`: validação reutilizando parse.
- `findAllSignatureByteRanges(...)`, `extractAllSignatureContents(...)`,
  `findSignatureValueRefs(...)`: helpers estáticos de inspeção.

### PdfValidationApi (3.16+)
As principais rotas aceitam `preparedContext` para reduzir custo total de validação.

- `preflightSignaturesFast(..., preparedContext: ...)`
- `validateWithTrustProfiles(..., preparedContext: ...)`

### PdfSignatureTextUtils (3.16+)
Utilitários para normalização de texto/metadados de assinatura.

- `extractCommonName(subject)`
- `sanitizeSignerName(raw)`
- `formatDateTimeBr(dt)` e `formatPdfDateBr(raw)`

### Crypto Base64 (3.16+)
Novo conjunto público em `package:pdf_plus/crypto.dart`:

- `base64EncodeBytes` / `base64DecodeToBytes`
- `base64EncodeUtf8` / `base64DecodeUtf8`

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


