# roteiro focado em recursos para assinatura digital e edicao de PDF

Objetivo

O mais importante nao e replicar nomes de APIs do `dart_pdf`, e sim garantir que
`pdf_plus` ofereca os recursos necessarios para:

1) criacao visual de assinatura eletronica (desenho em PDF com textos/imagens)
2) edicao de PDF (anotacoes, campos, incremental update)
3) assinatura digital (preparar, embutir e validar PKCS#7)
4) LTV / revogacao (DSS/CRL/OCSP)
5) Timestamp (TSA / DocTimeStamp)
6) PKI/keystore (JKS/BKS/PKCS12 para cadeias ICP-Brasil)

Uso real no SALI (modulo de assinatura)

- Visual: gera bloco grafico com fontes, cores, logo e links (sali_signature_visual.dart / govbr_signature_visual.dart).
- Edicao: insere campos de assinatura, anota links e salva incremental.
- Assinatura: prepara placeholder (ByteRange), calcula hash e embute PKCS#7.
- Validacao: extrai dados e valida cadeia/DocMDP/byteRange.

Roadmap por recursos (prioridade)

1) Visual de assinatura (alto impacto)
   - Desenhar texto dentro de retangulos (bounds) com alinhamento simples.
   - Desenhar imagens a partir de bytes, com width/height detectados.
   - Fontes padrao e TTF, com metricas (height/measureString).
   - Helpers para coordenadas top-left (como o frontend envia).

2) Edicao de PDF (suporte a assinatura)
   - Inserir anotacoes (URI link).
   - Inserir campo de assinatura e aparencia (annotation + appearance).
   - Suportar salvar incremental (appendOnly).

3) Assinatura digital (externa/interna)
   - Prepare PDF (ByteRange, placeholder /Contents).
   - Embed PKCS#7 no placeholder.
   - Suporte a DocMDP quando aplicavel.
   - Helper para assinar digest (CMS) com PEM.

4) Validacao e inspecao
   - Extrair dados basicos (signingTime, policyOid, docMdp, byteRange).
   - Validar CMS + digest + integridade.
   - Expor resultado de forma simples para o backend.

5) LTV / Revogacao
   - Inserir CRL/OCSP/certificados no DSS (incremental).
   - Futuro: busca automatica de CRL/OCSP.

Estado atual no pdf_plus (resumo)

- Assinatura externa e CMS: existe (PdfExternalSigning + PdfCmsSigner).
  - Prepare/Embed com placeholder /Contents e ByteRange.
  - Parsers de ByteRange/Contents com fallback (fast e interno) e verificacoes.
- Validacao: existe (PdfSignatureValidator + report).
  - Helpers publicos: extractAllSignatureContents, extractSignatureContentsAt,
    findAllSignatureByteRanges, findSignatureValueRefs.
- LTV: existe (PdfLtvService.applyLtv).
- Incremental update: implementado no PdfDocument.save (append do PDF anterior + /Prev).
- Timestamp: suporte a DocTimeStamp via PdfTimestampClient + PdfExternalSigning.
- PKI: parser PKCS12, keystores JKS/BKS e loader ICP-Brasil.
- Crypto interno: SHA1/SHA256/SHA512, HMAC, 3DES/CBC/PKCS7, sem dependencia externa.
- Visual: existe PdfGraphics, mas faltam helpers para uso direto (texto com bounds,
  imagem a partir de bytes e metricas de fonte).

Implementado agora (primeiros passos)

- PdfColor.fromRgbInt(r,g,b[,a]) para cores 0..255.
- Novo toolkit visual em `lib/src/pdf/visual/visual.dart`:
  - PdfVisualFont (standard/ttf + metricas + tamanho).
  - PdfVisualImage (bytes + width/height + conversao para PdfImage).
  - rectFromTopLeft(...) para converter coordenadas.
  - extensoes em PdfGraphics:
    - drawTextBox(text, font, bounds, color)
    - drawImageBox(image, bounds)
- Toolkit de edicao em `lib/src/pdf/editing/pdf_edit_tools.dart`:
  - addUriAnnotation(...) e addUriAnnotationTopLeft(...)
  - addSignatureField(...) e addSignatureFieldTopLeft(...)
- Toolkit de assinatura em `lib/src/pdf/signing/pdf_signature_tools.dart`:
  - prepareExternalSignature(...) e prepareExternalSignatureTopLeft(...)
  - embedExternalSignature(...)
- Testes de incremental update e multi-assinatura:
  - `test/pdf/parsing/pdf_incremental_update_test.dart`
  - `test/signing/pdf_signature_validator_multi_test.dart`
- Teste robusto de multi-assinaturas + openssl verify:
  - `test/signing/pdf_signature_openssl_chain_test.dart`
- DocTimeStamp (TSA) com parse e verify via openssl:
  - `test/signing/pdf_signature_openssl_chain_test.dart` (ts -reply + ts -verify)
- Testes de keystore ICP-Brasil (JKS/BKS) + roundtrip:
  - `test/pki/icp_brasil_keystore_test.dart`

Refatoracao do parser (organizado sem `part`)

- Parser dividido em arquivos menores (mantendo robustez/performance):
  - `lib/src/pdf/parsing/pdf_document_parser.dart` (orquestracao e API publica).
  - `lib/src/pdf/parsing/pdf_parser_types.dart` (tipos auxiliares antes internos).
- Tipos antes privados viraram publicos para evitar `part`.
- Constantes centralizadas em `lib/src/pdf/pdf_names.dart` via `PdfNameTokens`.

Proximos passos sugeridos (nao implementados ainda)

1) API de edicao de campos
   - Helper para criar campos de assinatura e aparencia com bounds top-left.
   - Wrapper para adicionar PdfUriAnnotation com top-left.

2) API de assinatura digital mais simples
   - Funcoes de alto nivel: prepareSignature + embedSignature.
   - Suporte explicito a DocMDP e flags appendOnly.

3) Visual e layout
   - Line wrapping simples + truncamento.
   - Alinhamento vertical/central.

4) Validacao/LTV avancado
   - Expor objetos de validacao simplificados.
   - Opcional: fetch CRL/OCSP.
5) TSA mais robusto
   - Validacao de token com truststore configuravel (CAfile + chain).
   - Politicas/oid e validacao de nonce.
6) PKI/keystore
   - Decodificacao completa de PrivateKeyEntry em JKS/JCEKS.
   - Melhorar deduplicacao/normalizacao de certificados ICP-Brasil.


Profissionalizar e organizar o parser sem perder robustez/perf:

1) Quebra por responsabilidade (sem alterar lógica)

`pdf_document_parser.dart` vira orquestrador + API pública. Extrair para
arquivos internos:
- `parser_xref.dart`: `_parseXrefChain`, `_parseXrefAtOffset*`, `_parseXrefTable*`,
  `_parseXrefStream*`, `_XrefEntry`, `_TrailerInfo`.
- `parser_objects.dart`: `_getObject*`, `_readIndirectObject*`,
  `_ParsedIndirectObject`, `_indexObjectStreams`.
- `parser_tokens.dart`: `_readInt`, `_readHexString`, `_readLiteralString`,
  `_skipPdfWsAndComments`, `_matchToken`, `_indexOfSequence`,
  `_lastIndexOfSequence`, `_readIdArray`.
- `parser_fields.dart`: `extractSignatureFields`,
  `extractSignatureFieldEditContext`, `_collectSignatureFieldObjects`,
  `_collectSignatureFields`, `_tryRead*FromObject`.
- `parser_pages.dart`: `_collectPages`, `_collectPageRefs`,
  `_buildPageFromDict`, `_pageFormatFromBox`, `_pageRotationFromValue`.

Resultado: arquivos menores, teste e debug mais simples.

2) Centralizar nomes PDF em constantes

Concluido. Criado `lib/src/pdf/pdf_names.dart` com `PdfNameTokens` (consts
`String`) e substituido o uso de literais `'/...'` em `lib/src/pdf` e
`lib/src/widgets`. Mantive `String` para evitar impacto de performance e
comportamento. Em casos de palavra reservada, usei nome seguro
(`nullName` para `'/Null'`).

3) Agrupar estruturas auxiliares

Mover `class _ParsedIndirectObject`, `_PdfRef`, `_ImageScanInfo` para
`parser_types.dart`. Ajuda leitura e reduz ruído no arquivo principal.

4) Isolar “robustez vs. performance”

Separar paths críticos:
- `fast_path`: quando xref/trailer OK.
- `repair_path`: fallback por scan.

Isso deixa claro quando custa mais CPU/IO e evita regressões.

5) Evitar dependências cíclicas se possivel

Separar em arquivos e usar classes com métodos estáticos publicos, para controlar
visibilidade no export da lib pode usar show ou hide no export se necessario 

6) Manter testes como “red flag”

Qualquer refactor deve rodar pelo menos:
`dart test test/pki`
`dart test test/signing`
`dart test test/pdf/parsing`

Isso pega regressões de parsing e assinatura.

7) Inspiração do iText

Eles separam parsing: `PdfTokenizer`, `PdfXref`, `PdfDocument`.
A ideia aqui: tokenização isolada, xref isolado, parser orquestra.
Você já tem isso misturado em um arquivo; separar ajuda clareza e manutenção.
