# Roteiro de Implementação — Merge (Mesclagem) de PDFs

> Alvo: **`pdf_plus`** (`c:\MyDartProjects\pdf_plus`), versão atual 3.17.4.
> Inspirado em `insinfo_dart_pdf/doc/roteiro_merge_pdf.md`, onde o merge foi
> implementado e entregue na v31.2.0.
> **Status: implementado.** As seções 1 a 11 são o plano original, escrito antes
> da implementação; ficam aqui porque documentam *por que* cada decisão foi
> tomada. A **§12** descreve o que efetivamente foi entregue, onde o plano mudou
> e os bugs de parser que a implementação obrigou a corrigir.

---

## 0. Resumo executivo

`pdf_plus` não expõe nenhuma API de merge. Diferente da lib irmã, **também não
tem a infraestrutura pronta**: lá existia um motor de clonagem profunda entre
cross-tables (`IPdfPrimitive.cloneObject`) que só precisava ser destravado; aqui
não existe equivalente. O que existe é um parser completo e um serializador
completo — mas nenhuma ponte entre "objeto lido de um arquivo" e "objeto
gravável em outro documento".

A diferença que define o projeto inteiro está no modelo de edição:

| | `insinfo_dart_pdf` (dart_pdf) | `pdf_plus` (dart_pdf) |
|---|---|---|
| Carregar um PDF | Materializa o grafo de objetos em memória (`PdfCrossTable`) | Cria só `PdfCatalog` + `PdfPage`; o resto continua **apenas nos bytes do arquivo** |
| Salvar um PDF carregado | Reserializa o documento inteiro | Copia os bytes originais e **anexa um incremental update** |
| Editar | Mexe no grafo | Emite objetos novos que substituem os antigos por número |

Ou seja: hoje `pdf_plus` sabe editar **um** arquivo preservando seus bytes —
exatamente o que a assinatura digital exige, e por isso o modelo é esse. Merge é
a operação oposta: **N** arquivos entram, nenhum conjunto de bytes pode ser
preservado como base, e todo objeto precisa ser reescrito com numeração nova.

Consequência prática, e é o desvio mais importante em relação ao roteiro irmão:
**lá o modo `flatten` saía de graça (1 dia, sem tocar na lib) e por isso era a
fase F1. Aqui não sai.** Desenhar uma página de origem como XObject exige copiar
as fontes, imagens e demais recursos dela para o documento de destino — que é
exatamente o importador de objetos. Os dois modos partem da mesma fundação, e a
ordem das fases muda: o importador vem primeiro.

Duas entregas previstas, na mesma divisão da lib irmã:

| Nível | O que é | Fidelidade |
|---|---|---|
| **`objectImport`** (padrão) | Importa o grafo de objetos da página | Conteúdo, recursos, anotações, links, campos, bookmarks, camadas, page labels |
| **`flatten`** | Envolve o conteúdo da página em um Form XObject e desenha | Só conteúdo gráfico |

Estimativa total: **14 a 20 dias** de trabalho, F0–F11.

---

## 1. Estado atual da base de código

### 1.1 O que já existe e será reaproveitado

| Recurso | Local | Papel no merge |
|---|---|---|
| `PdfDocumentParser` | [pdf_document_parser.dart](../lib/src/pdf/parsing/pdf_document_parser.dart) | Lê xref (clássico, stream, object streams), repara arquivo danificado, resolve objetos |
| `PdfParserObjects.toPdfDataType` | [parser_objects.dart:492](../lib/src/pdf/parsing/parser_objects.dart#L492) | **Ponte token → modelo gravável.** Já converte dict, array, nome, string, num, ref |
| `PdfParserObjects.readIndirectObjectAt` | [parser_objects.dart:48](../lib/src/pdf/parsing/parser_objects.dart#L48) | Lê objeto indireto com `streamData` **bruto** (filtros não decodificados) |
| `PdfParserObjects.resolveLength` | [parser_objects.dart:72](../lib/src/pdf/parsing/parser_objects.dart#L72) | Resolve `/Length` indireto e cai para varredura de `endstream` |
| `PdfDictStream` | [dict_stream.dart:61](../lib/src/pdf/format/dict_stream.dart#L61) | **Grava stream já filtrado verbatim** quando `/Filter` está no dicionário — é o que permite copiar streams sem decodificar |
| `PdfObject<T>` | [object.dart](../lib/src/pdf/obj/object.dart) | Objeto indireto do destino; `PdfObject(doc, params: …)` aloca número novo sozinho |
| `PdfDocument.genSerial()` | [document.dart:250](../lib/src/pdf/document.dart#L250) | Alocador de números de objeto do destino |
| `PdfXrefTable` | [xref.dart:97](../lib/src/pdf/format/xref.dart#L97) | Serializa xref clássico **e** comprimido (PDF 1.5) |
| `PdfPage` / `PdfPageList` | [page.dart:47](../lib/src/pdf/obj/page.dart#L47), [page_list.dart](../lib/src/pdf/obj/page_list.dart) | Modelo de página e árvore `/Pages` do destino |
| `_buildPageFromDict` | [pdf_document_parser.dart:1823](../lib/src/pdf/parsing/pdf_document_parser.dart#L1823) | **Precedente exato** de "dicionário de página lido vira `PdfPage`", incluindo o filtro de chaves |
| `_resolvePageResources` / `_resolvePageMediaBox` | [pdf_document_parser.dart:570](../lib/src/pdf/parsing/pdf_document_parser.dart#L570), [:615](../lib/src/pdf/parsing/pdf_document_parser.dart#L615) | **Já resolvem herança da árvore `/Pages`** — hoje privados, usados só por `extractInfo` |
| `ZLibDecoder` (`package:archive`) | [parser_objects.dart:249](../lib/src/pdf/parsing/parser_objects.dart#L249) | Inflate disponível para leitura, quando for preciso inspecionar conteúdo |
| `PdfAcroForm` | [pdf_acroform.dart](../lib/src/pdf/acroform/pdf_acroform.dart) | Modelo de campos sobre dicionários crus — passa a funcionar de verdade num documento mesclado (§1.3, B6) |
| `extractSignatureFields` | [pdf_document_parser.dart:401](../lib/src/pdf/parsing/pdf_document_parser.dart#L401) | Já enumera campos `/Sig` de um documento — insumo pronto para a política de assinaturas (F9) |
| Corpus de teste | `test/assets/pdfs/` (63 PDFs) | Varredura de robustez sem inventar fixture |

### 1.2 O modelo de carregamento atual, em detalhe

```
PdfDocument.parseFromBytes(bytes)
  └─ PdfDocument.load(parser)                    document.dart:135
       ├─ _objser = parser.size                  (numeração continua de onde o arquivo parou)
       └─ parser.mergeDocument(this)             pdf_document_parser.dart:1664
            ├─ catalog  = PdfCatalog(objser: <nº do /Root de origem>)
            ├─ pageList = PdfPageList(objser: <nº do /Pages de origem>)
            └─ para cada página: PdfPage(objser: <nº da página de origem>)
                 └─ params recebem o dicionário convertido, MENOS /Parent /Type /MediaBox /Rotate

document.save()                                  document.dart:390
  ├─ os.putBytes(prev.bytes)                     ← o arquivo original inteiro
  └─ output(os)                                  ← só os objetos de `document.objects`
```

Três fatos decorrem daí, e todos machucam o merge:

1. **`/Contents`, `/Resources`, fontes e imagens nunca viram objetos.** Ficam
   como `PdfIndirect(n, g)` apontando para números que só existem nos bytes
   originais. Funciona porque os bytes originais estão no arquivo de saída.
2. **Só um documento pode ser a base.** `prev` é um campo único e `save()`
   concatena `prev.bytes`. Não há onde encaixar um segundo arquivo.
3. **Os números de objeto de origem são preservados de propósito.** Dois
   documentos diferentes têm objetos `12 0 obj` distintos: qualquer merge
   precisa renumerar, e renumerar significa reescrever toda referência.

### 1.3 Os bloqueios concretos

**B1 — Não existe materialização de objetos.**
O bloqueio central. Para mesclar, cada objeto alcançável a partir de uma página
de origem precisa virar um `PdfObject` do destino com número novo. Nada na lib
faz isso hoje. É a fase F1 e é o coração do trabalho.

**B2 — `readStreamData` devolve `null` para streams grandes.** *(verificado)*
[`readIndirectObjectAtFromReader`](../lib/src/pdf/parsing/parser_objects.dart#L115)
lê uma janela de 8 KB e **retorna na primeira janela cujo cabeçalho fizer
parse** — a escalada de janelas (`8K → 32K → 128K → 512K → 2M`) só acontece
quando o *cabeçalho* falha, nunca quando o *stream* não cabe. Aí
[`extractStream`](../lib/src/pdf/parsing/parser_objects.dart#L23) não encontra
`endstream` dentro da janela e devolve `null`, silenciosamente.

Medido em `test/assets/pdfs/10 assinaturas.pdf`, objeto 17 (JPEG 1269×305,
13 955 bytes):

| Como o parser foi criado | `readStreamData` |
|---|---|
| `PdfDocumentParser.fromReader(arquivo)`, `enableCache: true` | **NULL** |
| `PdfDocumentParser.fromReader(arquivo)`, `enableCache: false` | **NULL** |
| `PdfDocumentParser(bytes)`, `enableCache: true` — **o padrão** | **NULL** |
| `PdfDocumentParser(bytes)`, `enableCache: false` | 13 955 bytes ✔ |

O caminho rápido `reader is PdfMemoryRandomAccessReader` não dispara no padrão
porque o reader vem embrulhado em `PdfCachedRandomAccessReader`
([document_parser.dart:29](../lib/src/pdf/document_parser.dart#L29)).
Sem corrigir isto, **todo merge sai sem imagens e sem conteúdo**. É pré-requisito
de F1, e conserta de quebra o `extractImages` para qualquer consumidor externo.

Correção: em `readIndirectObjectAtFromReader`, depois do parse do dicionário,
conferir se `dictEnd + /Length + len('endstream')` cabe na janela; se não couber,
reler exatamente `dictEnd..dictEnd+Length+ε` (ou escalar a janela) antes de
desistir. E tratar `PdfCachedRandomAccessReader` que embrulha memória como
memória.

**B3 — Não há API pública de acesso a objetos.**
`_getObject`, `_xrefEntries` e `_trailerInfo` são privados
([:1709](../lib/src/pdf/parsing/pdf_document_parser.dart#L1709)). O importador
precisa de: resolver objeto por número, enumerar ids, ler o `/Root`, e resolver
uma referência a partir de um valor. Hoje só `readStreamData(PdfIndirectRef)` é
público.

**B4 — `toPdfDataType` copia o número de objeto de origem.**
[parser_objects.dart:502](../lib/src/pdf/parsing/parser_objects.dart#L502):
`PdfRefToken(obj, gen) → PdfIndirect(obj, gen)`. Correto no modelo incremental,
fatal no merge. O importador precisa da mesma conversão **com um remapeador
injetado** — não dá para reusar a função como está; ou se acrescenta um callback
opcional, ou se escreve uma variante no importador.

**B5 — `PdfPage.prepare()` sobrescreve `/MediaBox` e `/Parent`.**
[page.dart:100-111](../lib/src/pdf/obj/page.dart#L100-L111):

```dart
params[PdfNameTokens.parent] = pdfDocument.pdfPageList.ref();
params[PdfNameTokens.mediaBox] =
    PdfArray.fromNum(<double>[0, 0, pageFormat.width, pageFormat.height]);
```

`/Parent` sendo reescrito é ótimo — resolve o religamento à árvore do destino de
graça. `/MediaBox` é problema: `PdfPageFormat` só guarda largura e altura
([page_format.dart:83](../lib/src/pdf/page_format.dart#L83)) e
`pageFormatFromBox` calcula `width = box[2] - box[0]`
([parser_pages.dart:6](../lib/src/pdf/parsing/parser_pages.dart#L6)), então
**uma página com `MediaBox [20 30 615 872]` é regravada como `[0 0 595 842]` e o
conteúdo sai deslocado em 20×30 pontos.** Precisa de um `mediaBoxOverride` (ou
equivalente) em `PdfPage` respeitado por `prepare()`.

**B6 — Objetos-modelo reescrevem chaves na hora de salvar.**
Três lugares onde o modelo é dono da chave e sobrescreve o que o importador
escrever:

| Onde | O que reescreve |
|---|---|
| [`PdfCatalog.prepare`](../lib/src/pdf/obj/catalog.dart#L158) | Monta `/AcroForm /Fields` a partir de `page.annotations` — **só enxerga anotações que sejam objetos-modelo `PdfAnnot`**, nunca dicionários crus importados |
| [`PdfNames.prepare`](../lib/src/pdf/obj/names.dart#L59) | Sobrescreve `/Dests` inteiro com o mapa interno `_dests` |
| [`PdfPageLabels.prepare`](../lib/src/pdf/obj/page_label.dart#L189) | Idem para `/Nums` |

É a mesma armadilha que na lib irmã custou a reescrita do importador de
bookmarks (desvio #3 lá). Regra a seguir aqui: **para cada estrutura de nível de
documento, escolher explicitamente entre "escrever no `params` cru" e "alimentar
o modelo"** — e nunca os dois. Bookmarks e page labels: alimentar o modelo.
AcroForm: escrever no `params`, porque o modelo só sabe lidar com widgets
próprios.

**B7 — `/Resources` indireto é clobberado se algo carimbar a página.**
[graphic_stream.dart:151-161](../lib/src/pdf/obj/graphic_stream.dart#L151-L161):
o merge de recursos só acontece se `params['/Resources']` for um `PdfDict`. Se a
página importada trouxer `/Resources 12 0 R` e alguém desenhar por cima (carimbo,
numeração de página), o ramo final substitui a referência pelo dicionário novo e
**a página perde todas as fontes e imagens**. Mitigação: o importador
materializa `/Resources` como dicionário direto na página (não como referência),
ou o `prepare` passa a resolver a referência antes de decidir.

**B8 — Sem descriptografia na leitura.**
O parser só detecta `/Encrypt`
([parser_fields.dart:115](../lib/src/pdf/parsing/parser_fields.dart#L115)); não
há handler de segurança padrão para *ler*. `PdfEncryption`
([obj/encryption.dart](../lib/src/pdf/obj/encryption.dart)) é só de escrita.
Origem criptografada, portanto, **não é suportada** — e precisa falhar com
mensagem clara em vez de produzir lixo (F8).

**B9 — Atributos herdados da árvore `/Pages`.**
`/Resources`, `/MediaBox`, `/CropBox` e `/Rotate` podem morar em um nó ancestral.
Ao destacar a página da árvore de origem eles precisam ser materializados. A lib
já sabe fazer isso em `_resolvePageResources` / `_resolvePageMediaBox` — falta
expor e cobrir também `/CropBox` e `/Rotate`.

---

## 2. Estratégia

### 2.1 Por que `flatten` não é de graça aqui

Na lib irmã, `flatten` era um protótipo de 30 linhas sobre `PdfTemplate`, porque
`cloneResources` já importava fontes e imagens entre documentos. Em `pdf_plus`
não existe `PdfTemplate`, `PdfGraphics` só sabe desenhar XObject por dentro de
`drawImage` ([graphics.dart:326](../lib/src/pdf/graphics.dart#L326)), e — o que
decide a questão — **os recursos da página de origem continuariam morando no
arquivo de origem**. Um Form XObject cujo `/Resources` aponta para `12 0 R` de
outro arquivo é lixo.

Então `flatten` aqui é: importar o grafo de recursos (F1), montar um
`PdfFormXObject` com o conteúdo bruto da origem e desenhá-lo. Ganha-se
previsibilidade, não velocidade de implementação.

### 2.2 O que cada modo faz

**`objectImport` (padrão).** Copia o dicionário da página e tudo que ele alcança,
remapeando referências; a página de destino é um `PdfPage` cujo `params` é o
dicionário importado. Preserva conteúdo, recursos, anotações, links, campos e —
via passes seguintes — bookmarks, camadas e page labels.

**`flatten`.** Cria `PdfFormXObject` com:

- `data` = `/Contents` da origem, **bruto** (concatenado quando for array, com
  `\n` entre streams; se os filtros divergirem entre os pedaços, decodificar via
  `ZLibDecoder` e reemitir sem filtro);
- `/BBox` = MediaBox da origem, `/Matrix` = identidade (ou translação quando a
  origem do MediaBox não for (0,0) — resolve B5 nesse modo);
- `/Resources` = recursos importados.

Depois desenha na página nova com `q <matrix> cm /Xn Do Q`. Precisa de um
`PdfGraphics.drawFormXObject(PdfXObject, {Matrix4? transform})` público —
extração trivial do que `drawImage` já faz.

---

## 3. API pública proposta

Diretório novo: `lib/src/pdf/merging/`.

```dart
// pdf_merge_options.dart

enum PdfMergeMode { objectImport, flatten }

enum PdfFieldNameConflictPolicy { renameSuffix, keepFirst, throwError }

class PdfMergeOptions {
  const PdfMergeOptions({
    this.mode = PdfMergeMode.objectImport,
    this.importAnnotations = true,
    this.importFormFields = true,
    this.fieldNameConflict = PdfFieldNameConflictPolicy.renameSuffix,
    this.importBookmarks = true,
    this.importNamedDestinations = true,
    this.importLayers = true,
    this.importPageLabels = true,
    this.importAttachments = false,
    this.dropStructureTree = true,
    this.copyDocumentInfoFromFirst = false,
    this.groupBookmarksPerDocument = false,
    // assinaturas — três chaves independentes, precedência nesta ordem
    this.rejectSignedSources = false,
    this.keepInvalidSignatures = false,
    this.removeSignatureAppearance = false,
    this.deduplicateResources = true,
  });
  // ... campos
}

class PdfMergeException implements Exception { /* ... */ }
```

```dart
// pdf_document_merger.dart

class PdfDocumentMerger {
  PdfDocumentMerger(PdfDocument destination, {PdfMergeOptions? options});

  /// Fonte de páginas: um parser já aberto (arquivo ou memória).
  PdfPage importPage(PdfDocumentParser source, int pageIndex);
  List<PdfPage> importPageRange(PdfDocumentParser source, int start, int end);
  List<PdfPage> append(PdfDocumentParser source);

  /// Resolve pendências (destinos, AcroForm, catálogo). Idempotente.
  /// Chamado automaticamente antes de salvar.
  void finish();

  List<String> get warnings;
}
```

Atalhos em `PdfDocument`:

```dart
List<PdfPage> appendDocument(PdfDocumentParser source, {PdfMergeOptions? options});
PdfPage       importPage(PdfDocumentParser source, int pageIndex, {PdfMergeOptions? options});
List<PdfPage> importPageRange(PdfDocumentParser source, int start, int end,
    {PdfMergeOptions? options});

/// Atalho de mais alto nível.
static Future<Uint8List> merge(
  List<Uint8List> documents, {
  PdfMergeOptions? options,
  bool compress = true,
});
```

Notas de design, todas decorrentes de §1:

1. **A fonte é o `PdfDocumentParser`, não um `PdfDocument`.** Um `PdfDocument`
   carregado não materializa objetos (§1.2), então não serve como fonte. Aceitar
   `PdfDocument` na API só criaria a ilusão de que serve.
2. **A construção é síncrona; só `save()` é assíncrono.** Não existe `saveSync`
   nesta lib, então o `merge` estático devolve `Future<Uint8List>` e o resto é
   síncrono.
3. **O destino nunca pode ter `prev`.** Mesclar dentro de um documento carregado
   produziria um incremental update com objetos de outro arquivo dentro —
   inválido. `PdfDocumentMerger` deve lançar `PdfMergeException` se
   `destination.prev != null`.

---

## 4. Arquitetura interna

```
lib/src/pdf/merging/
  pdf_merge_options.dart        # enums + opções + exceção
  pdf_import_context.dart       # estado de uma sessão: memo, pageMap, warnings
  pdf_object_importer.dart      # F1 — materialização + remapeamento (o coração)
  pdf_page_importer.dart        # F2 — página, atributos herdados, geometria
  pdf_flatten_importer.dart     # F3 — Form XObject
  pdf_annotation_importer.dart  # F4 — anotações, links, destinos
  pdf_form_importer.dart        # F5 — AcroForm
  pdf_outline_importer.dart     # F6 — bookmarks
  pdf_catalog_merger.dart       # F7 — OCG, PageLabels, Info, versão
  pdf_document_merger.dart      # fachada pública
```

Mudanças cirúrgicas em arquivos existentes:

| Arquivo | Mudança | Fase |
|---|---|---|
| `parsing/parser_objects.dart` | Corrigir janela de leitura de stream (B2) | F0 |
| `parsing/pdf_document_parser.dart` | API pública: `getObject(int)`, `resolve(dynamic)`, `objectIds`, `rootDict`, `pageRefs`, resolução de herdados (B3, B9) | F0 |
| `parsing/parser_objects.dart` | `toPdfDataType` com remapeador opcional de referência (B4) | F1 |
| `obj/page.dart` | `mediaBoxOverride` respeitado em `prepare()` (B5) | F2 |
| `obj/graphic_stream.dart` | Resolver `/Resources` indireto antes de substituir (B7) | F2 |
| `graphics.dart` | `drawFormXObject(...)` público | F3 |
| `lib/pdf.dart` | Exports do namespace de merge | F10 |

### `PdfImportContext`

```dart
class PdfImportContext {
  PdfImportContext(this.destination, this.options);

  final PdfDocument destination;
  final PdfMergeOptions options;

  /// Parser da origem em andamento.
  late PdfDocumentParser source;

  /// Memo por origem: nº de objeto na ORIGEM -> objeto criado no DESTINO.
  /// Zerado a cada troca de `source` — números colidem entre documentos.
  final Map<int, PdfObject> imported = <int, PdfObject>{};

  /// Nº do objeto da página na ORIGEM -> página criada no DESTINO.
  final Map<int, PdfPage> pageMap = <int, PdfPage>{};

  /// Campos renomeados por colisão: nome original -> nome final.
  final Map<String, String> renamedFields = <String, String>{};

  final List<String> warnings = <String>[];
}
```

### O algoritmo do importador (F1)

```
PdfIndirect? importRef(int srcObjId)
  1. se imported[srcObjId] existe -> devolve .ref()
  2. parsed = source.getObject(srcObjId); se null -> warning, devolve null
  3. se o dict tem /Type /Page ou /Pages -> NÃO importa:
       devolve pageMap[srcObjId]?.ref()   (corta a aresta; null vira warning)
  4. ALOCA o objeto de destino AGORA, com params vazio, e grava no memo
       (é isto que fecha ciclos: o segundo encontro já acha o memo)
  5. converte o valor, recursivamente, trocando cada PdfRefToken por importRef()
  6. preenche o params do objeto alocado:
       - com streamData  -> PdfDictStream(values: dict, data: bruto,
                              compress: false)   // /Filter original preservado
       - sem streamData  -> PdfDict
  7. devolve .ref()
```

Dois pontos merecem destaque porque são exatamente onde a lib irmã sangrou:

- **Alocar antes de converter** fecha ciclos sem heurística. Na lib irmã o guard
  anti-recursão era uma pilha linear e o segundo encontro com um objeto
  compartilhado (uma fonte usada por duas páginas) "adotava" o objeto de origem
  dentro do destino — bug que só apareceu como duplicação de tamanho. Aqui o
  memo é o próprio mecanismo de ciclo, então o bug não tem como existir.
- **Cortar em `/Type /Page`** substitui o *bypass* que lá precisou ser enxertado
  no meio de `PdfReferenceHolder.cloneObject`, com risco de regressão em três
  outros subsistemas. Aqui o importador é código novo: nenhum comportamento
  existente muda.

Chaves cortadas na importação da página: `/Parent` (senão arrasta a árvore
inteira), `/StructParents` e `/B` quando `dropStructureTree`, `/Annots`
(reimportado em F4, para poder religar `/P`).

Streams copiados verbatim implicam `/Length` recalculado por `PdfDictStream`
([dict_stream.dart:86](../lib/src/pdf/format/dict_stream.dart#L86)) — remover
`/Length` do dicionário convertido para não gravar duplicado. Objetos
estruturais da origem (`/Type /ObjStm`, `/Type /XRef`) nunca são alcançados a
partir de uma página; se aparecerem, ignorar.

---

## 5. Fases

### F0 — Destravar o parser — *1–2 dias*

Pré-requisito de tudo. Sem isto o merge sai sem conteúdo (B2).

- Corrigir `readIndirectObjectAtFromReader` para garantir o stream completo;
  tratar `PdfCachedRandomAccessReader` sobre memória como memória.
- Publicar em `PdfDocumentParser`: `getObject(int)`, `resolve(dynamic)`,
  `rootDict`, `pageRefs`, `objectIds`, resolução de atributos herdados.
- Criar `test/merging/` e `test/assets/merge/`; helpers `reopen(bytes)`,
  `pageDictOf(doc, i)`, `objectCountOf(bytes)`.

**Aceite:** `readStreamData` devolve os 13 955 bytes do objeto 17 de
`10 assinaturas.pdf` nos quatro modos de construção do parser da tabela em B2;
teste de regressão fixando isso.

### F1 — Importador de objetos — *3–4 dias*

- `PdfImportContext` + `PdfObjectImporter` conforme §4.
- Remapeador de referência em `toPdfDataType` (ou variante local).
- Deduplicação por memo (grátis) e, com `deduplicateResources`, também por hash
  SHA-1 do par (dicionário normalizado, dados brutos) — pega o mesmo logo
  repetido em N documentos distintos.

**Aceite (unitário, ainda sem página):** importar um subgrafo com ciclo
`A → B → A` produz exatamente 2 objetos no destino e o ciclo é preservado;
importar duas vezes o mesmo objeto compartilhado gera **um** objeto; um stream
Flate importado sai byte a byte idêntico ao da origem.

### F2 — Importação da página — *1–2 dias*

1. Materializar herdados (`/Resources`, `/MediaBox`, `/CropBox`, `/Rotate`).
2. Importar o dicionário da página cortando `/Parent`, `/Type`, `/Annots`.
3. Criar `PdfPage(destination, pageFormat: <tamanho da origem>, rotate: <origem>)`
   e mesclar o dicionário importado em `params`.
4. `mediaBoxOverride` quando a origem não começa em (0,0) — B5.
5. Registrar `pageMap[srcObjId] = página`.

**Aceite:** content stream da página importada byte-idêntico ao da origem;
fontes e imagens presentes na saída; tamanho, rotação e `CropBox` preservados;
página com `MediaBox` deslocado renderiza no lugar certo.

### F3 — Modo `flatten` — *1 dia*

Conforme §2.2, sobre F1. `PdfGraphics.drawFormXObject` público.

**Aceite:** merge de 3 fixtures gráficas; contagem e tamanho de páginas conferem;
nenhuma anotação sobrevive (é o contrato do modo); `/Rotate` propagado.

### F4 — Anotações e links — *1–2 dias*

- Importar `/Annots` item a item, pulando `/Subtype /Widget` (F5).
- Religar `/P` à página de destino; remover `/Parent` órfão.
- Remapear destinos: `/Dest` array `[pageRef …]`; `/Dest` nome ou string →
  resolver na árvore `/Names /Dests` da origem e **reemitir como destino
  explícito**; `/A << /S /GoTo /D … >>` idem; `/URI`, `/Launch`, `/GoToR` passam
  intactos.
- Destino fora do intervalo importado: remover o link e registrar warning.
- **Duas passagens**: todas as páginas primeiro, anotações depois — assim o
  `pageMap` já está completo e nenhuma referência precisa de mecanismo de
  pendência. (É a lição #1 da lib irmã: o `PendingReference` planejado lá nunca
  foi necessário por causa disso.)
- Leitura de destino tolerante a falha: árvore de nomes malformada vira warning,
  não derruba o merge.

**Aceite:** fixture com link interno mesclada duas vezes; cada cópia navega para
a página certa *dentro da própria cópia*; link URI intacto; contagem de
anotações preservada.

### F5 — AcroForm — *2 dias*

- Escrever `/AcroForm` direto em `catalog.params` (B6), mesclando com o que já
  houver: `/Fields` concatenado, `/DR` mesclado, `/DA` e `/Q` herdados,
  `/NeedAppearances` em OR lógico, `/SigFlags` conforme F9.
- **Achatar a hierarquia de campos**: cada campo terminal entra no topo de
  `/Fields` com o nome totalmente qualificado em `/T`. Campos multi-widget
  (rádio, campo que atravessa páginas) continuam agrupados por `/Kids`.
- Colisão de nomes conforme `fieldNameConflict`; padrão `nome`, `nome_2`, …
  (o SEI usa `dummyFieldName<N>`, que perde o nome original — não copiar).
- **Varrer campos sem widget** ao fim de cada origem e importar os que nenhum
  widget alcançou. Não é caso raro: é a forma que documentos exportados pelo SEI
  têm, e na lib irmã custou uma de duas assinaturas até ser descoberto.

**Aceite:** dois formulários mesclados; 2× o número de campos; nomes
desambiguados; valores preservados ao reabrir; campo sem widget presente na
saída.

### F6 — Bookmarks e destinos nomeados — *1–2 dias*

- Percorrer `/Outlines` da origem e **recriar** cada nó com o modelo `PdfOutline`
  ([outline.dart:54](../lib/src/pdf/obj/outline.dart#L54)) — não clonar
  dicionário, porque `prepare()` reescreve `/First`, `/Last`, `/Count` e o
  destino (B6).
- `groupBookmarksPerDocument` cria um nó-pai por documento (padrão desligado).
- Destinos nomeados resolvidos para explícitos no momento do import; nada de
  reconstruir `/Names /Dests` no destino.

**Aceite:** fixture com outline de 2 níveis + fixture simples; todo bookmark
navega para a página certa; documento reabre sem erro.

### F7 — Recursos de nível de documento — *1–2 dias*

| Chave | Tratamento |
|---|---|
| `/OCProperties` | Merge de `/OCGs` e de `/D` (`/Order`, `/ON`, `/OFF`) |
| `/PageLabels` | Concatenar faixas com offset do índice inicial, via `PdfPageLabels` |
| `/StructTreeRoot`, `/MarkInfo` | **v1: descartar**, removendo `/StructParents` e emitindo warning |
| `/Metadata` (XMP) | Manter o do destino |
| `/Info` | `copyDocumentInfoFromFirst` |
| `/ViewerPreferences`, `/PageMode`, `/PageLayout`, `/OpenAction` | Do destino |
| `/Names /EmbeddedFiles` | `importAttachments` (padrão `false`) |
| `/Lang`, `/Extensions` | Copiar se ausente no destino |
| Versão | `max(versões)`; lembrar que `PdfCatalog.prepare` grava `/Version` sempre ([catalog.dart:85](../lib/src/pdf/obj/catalog.dart#L85)) |

### F8 — Geometria, robustez e arquivos reais — *1–2 dias*

- `MediaBox` com origem ≠ (0,0), `CropBox` invertido, `/UserUnit` ≠ 1, `/Rotate`
  não múltiplo de 90.
- Origem com xref stream e object streams (o parser já lê; garantir que objetos
  comprimidos sejam materializados antes da importação).
- Origem com xref danificado: `allowRepair: true` já cobre; testar que o merge
  sobrevive.
- Origem criptografada: falhar com `PdfMergeException` explicando que não há
  suporte de leitura (B8) — nunca produzir saída silenciosamente corrompida.
- PDFs enormes: ver F11.

### F9 — Assinaturas — *1–2 dias*

Mesclar invalida **toda** assinatura digital existente: a assinatura cobre os
bytes exatos do documento em que foi aplicada, e o merge reescreve o arquivo
inteiro. Não há como contornar. Isto vale em dobro aqui, onde a lib é usada
principalmente para assinar e validar documentos ICP-Brasil.

Pesquisa de mercado registrada no roteiro irmão (PDF24, iLovePDF, PDFsam, Adobe
Acrobat, PDFBox, iText): **nenhuma ferramenta recusa** documentos assinados.
Manter o mesmo comportamento, com três chaves independentes:

| Opção | Padrão | Efeito |
|---|---|---|
| `rejectSignedSources` | `false` | `true` lança `PdfMergeException` ao encontrar origem assinada |
| `keepInvalidSignatures` | `false` | `true` mantém os campos `/FT /Sig` com CMS e certificados; `/SigFlags` propagado. O visualizador reporta assinatura inválida |
| `removeSignatureAppearance` | `false` | `true` remove também o carimbo visual |

Padrão (todas `false`): campos de assinatura removidos, **carimbo visual
preservado** como anotação `/Subtype /Stamp` somente-leitura (bit 64 de `/F`).
A página continua parecendo assinada e nenhum validador reclama de assinatura
quebrada — porque não sobrou assinatura para conferir.

Precedência: `rejectSignedSources` > `keepInvalidSignatures` >
`removeSignatureAppearance`. Toda perda registrada em `warnings`.

**Cuidado específico desta lib:** ao remover `/V`, o dicionário de assinatura
(com o blob PKCS#7, dezenas de KB) não pode continuar sendo importado como
objeto órfão. Podar as entradas **antes** da importação, não depois — foi um bug
corrigido na lib irmã. Detectar assinaturas na origem com
`extractSignatureFields()`, que já existe.

Assinar **depois** de mesclar deve funcionar normalmente: o documento mesclado é
um arquivo novo, sem `prev`, e o fluxo de assinatura opera sobre os bytes
salvos. Cobrir com teste — é o caso de uso real (mesclar o processo e assinar o
consolidado).

### F10 — API pública, exports e documentação — *0,5 dia*

- Exportar em `lib/pdf.dart`: `PdfDocumentMerger`, `PdfMergeOptions`,
  `PdfMergeMode`, `PdfFieldNameConflictPolicy`, `PdfMergeException`.
- Doc comments no padrão da lib, com exemplo executável.
- Atualizar `doc.md`, `README.md` e `CHANGELOG.md`; bump de versão minor.
- Exemplo em `example/merge_documents.dart`.

### F11 — Desempenho e memória — *1–2 dias*

Diferencial relevante para o uso real desta lib (processos digitalizados de
centenas de MB em unidade de rede):

- **Trabalhar a partir de `PdfRandomAccessReader`**, não de `Uint8List`, para que
  N origens não fiquem inteiras em RAM. Depende de B2 estar corrigido de forma
  que a leitura por janela sirva streams grandes sem `readAll()`.
- Deduplicação de recursos (F1) medida: mesclar 5 cópias do mesmo PDF deve sair
  **menor** que a soma dos originais.
- Benchmark em `test/benchmark/`: 50 PDFs × 10 páginas e um caso "PDF
  digitalizado de 200 MB". Métricas: tempo, pico de memória, tamanho de saída.
- `enableEventLoopBalancing` já existe em `save()`
  ([document.dart:390](../lib/src/pdf/document.dart#L390)); a importação também
  deveria ceder o event loop periodicamente para não travar a UI na web.

---

## 6. Plano de testes

| Suíte | Arquivo | Cobre |
|---|---|---|
| Parser | `test/merging/merge_parser_access_test.dart` | B2 (streams completos nos 4 modos), API pública de objetos |
| Importador | `test/merging/merge_importer_test.dart` | ciclos, compartilhamento, stream verbatim, renumeração |
| Básico | `test/merging/merge_basic_test.dart` | contagem e ordem de páginas, tamanho, rotação, ambos os modos |
| Conteúdo | `test/merging/merge_content_test.dart` | content stream idêntico, fontes TTF, imagens, dedup |
| Anotações | `test/merging/merge_annotations_test.dart` | links internos e URI, `/P`, destinos fora do intervalo |
| Formulários | `test/merging/merge_forms_test.dart` | colisão de nomes, `/DR`, campos sem widget, valores ao reabrir |
| Outlines | `test/merging/merge_outlines_test.dart` | árvore combinada, destinos nomeados |
| Camadas | `test/merging/merge_layers_test.dart` | OCGs preservados e independentes |
| Geometria | `test/merging/merge_geometry_test.dart` | MediaBox deslocado, CropBox, `/Rotate`, `/UserUnit` |
| Assinaturas | `test/merging/merge_signatures_test.dart` | as três chaves e sua precedência; ausência de resíduo do PKCS#7; assinar o documento mesclado |
| Robustez | `test/merging/merge_damaged_input_test.dart` | xref quebrado, `startxref` além do fim, origem criptografada |
| Round-trip | `test/merging/merge_roundtrip_test.dart` | merge → salvar → recarregar → mesclar de novo |
| Corpus | `test/merging/merge_corpus_test.dart` | varredura dos 63 PDFs de `test/assets/pdfs` |
| Perf | `test/benchmark/merge_benchmark.dart` | 50×10 páginas e arquivo grande |

**Invariante geral:** a saída sempre recarrega com
`PdfDocument.parseFromBytes(out)` sem exceção, e a contagem de páginas bate com
a soma esperada.

---

## 7. Riscos

| # | Risco | Mitigação |
|---|---|---|
| R1 | B2 aparecer também em outros caminhos (ex.: `extractImages` em produção) | Corrigir na raiz em F0, com teste de regressão; é bug existente, não colateral do merge |
| R2 | `prepare()` de objetos-modelo sobrescrever o que o importador escreveu | B6: decidir por estrutura entre "params cru" e "modelo"; teste que reabre a saída e confere cada estrutura |
| R3 | Explosão de tamanho ao mesclar documentos similares | Memo + `deduplicateResources`; teste de tamanho com 5 cópias |
| R4 | Consumo de memória em processos de centenas de MB | F11: trabalhar por reader, nunca `readAll()` das origens |
| R5 | Mesclar documento assinado sem perceber | Padrão mescla e registra em `warnings`, como o mercado; `rejectSignedSources` para quem quiser barrar |
| R6 | Objeto órfão de assinatura carregando PKCS#7 para a saída | Podar `/V` **antes** da importação (F9) |
| R7 | Tagged PDF (`/StructTreeRoot`) | Descartado na v1, com warning |
| R8 | Origem criptografada | Sem suporte de leitura (B8): falha explícita |

---

## 8. Checklist de execução

```
[x] F0   Parser: janela de stream (B2) + API pública de objetos (B3, B9)
[x] F1   PdfImportContext + PdfObjectImporter (materialização e remapeamento)
[x] F2   Importação de página, herdados, geometria (B5, B7)
[x] F3   Modo flatten + PdfGraphics.drawFormXObject
[x] F4   Anotações, links e destinos (duas passagens)
[x] F5   AcroForm, achatamento de nomes, campos sem widget
[x] F6   Bookmarks pelo modelo PdfOutline
[x] F7   Catálogo: OCG, PageLabels, Info, versão
[x] F8   Geometria atípica, xref stream, arquivo danificado, criptografado
[x] F9   Política de assinaturas (3 chaves) + assinar o mesclado
[x] F10  Exports, docs, CHANGELOG, exemplo
[~] F11  Dedup medida e desempenho aferido; leitura por reader ainda carrega a
         origem em memória quando a chamada usa `PdfDocument.merge(bytes)`
```

---

## 9. Fora do escopo da v1

| Item | Motivo |
|---|---|
| Árvore de marcação estrutural (tagged PDF) | Remapear o `/ParentTree` inteiro; sem demanda conhecida |
| Reconstruir `/Names /Dests` no destino | Destinos são resolvidos para explícitos no import; navega sem a árvore |
| Renomear recursos `/DR` em conflito | Exigiria reescrever toda string `/DA` que os cita; destino vence, colisão vira warning |
| Anexos (`/EmbeddedFiles`) | Opção existe, honrada em versão futura |
| XMP mesclado | Sem semântica óbvia para N documentos |
| Origem criptografada | Falta handler de segurança de **leitura** (B8) |
| PDF/A no destino | Sem validação de fontes embutidas no caminho de importação |
| Carimbo de rodapé nas páginas mescladas | Ver §10, item 7 |

---

## 10. O que aproveitar da implementação irmã

A `insinfo_dart_pdf` já passou por isto; sete lições vieram de lá com custo real
e chegam aqui de graça. As quatro primeiras já estão embutidas nas fases acima:

1. **Duas passagens (páginas → anotações/bookmarks)** eliminam o mecanismo de
   pendências que o plano original previa. F4.
2. **Memo de objetos importados consultado antes do guard de ciclo.** Sem ele, o
   segundo encontro com um recurso compartilhado adota o objeto de origem. Aqui
   o memo *é* o guard (§4), então o bug não existe.
3. **Bookmarks se recriam pelo modelo, não se clonam** — o modelo é dono de
   `/First`, `/Last`, `/Count`. F6, e vale igual para `PdfNames` e
   `PdfPageLabels` nesta lib (B6).
4. **Campos de formulário sem widget existem e importam.** Documentos do SEI têm
   assinatura invisível com `/Rect [0 0 0 0]` e sem widget em `/Annots`; quem
   descobre campos só pelas páginas perde metade das assinaturas. F5.
5. **Hierarquia de campos achatada** com nome totalmente qualificado é mais
   simples e não perdeu nada em produção. F5.
6. **Assinatura: recusar diverge do mercado.** Mesclar e avisar é o comportamento
   certo; o padrão "vira carimbo somente-leitura" foi bem recebido porque
   entrega um arquivo que nenhum validador acusa. F9.
7. **A técnica de carimbo do SEI vale copiar** quando um dia se carimbar página
   mesclada: envolver o conteúdo existente com um stream `q` antes e um stream
   `Q` + carimbo depois, **sem tocar no stream original**. Preserva a fidelidade
   byte a byte e protege o carimbo de estado gráfico deixado aberto pela página.
   Barato e correto.

**Referência de campo.** O documento irmão traz uma perícia completa da saída da
função "Gerar Arquivo PDF do Processo" do SEI — identificação do engine (Apache
PDFBox 2.x em `PDFBOX_LEGACY_MODE` montando, `PDPageContentStream` em modo
append carimbando, com o wkhtmltopdf apenas renderizando um dos documentos), as
duas armadilhas dessa perícia e a tabela de coincidências e divergências. Está
em `insinfo_dart_pdf/doc/roteiro_merge_pdf.md`, §11. Quando o merge daqui
estiver de pé, a mesma comparação ponta a ponta deve ser reproduzida como suíte
de compatibilidade — é o sistema de referência do usuário final desta
biblioteca.

---

## 12. O que foi entregue

Implementado sobre a árvore de trabalho de 27/08/2026. A suíte passou de 767
para **927 testes verdes**, sendo 134 novos em `test/merging/`.

### 12.1 Mapa plano → código

| Fase | Arquivo entregue |
|---|---|
| F0 | [parser_objects.dart](../lib/src/pdf/parsing/parser_objects.dart) (leitura de stream e de dicionário grande), [parser_predictor.dart](../lib/src/pdf/parsing/parser_predictor.dart), API pública em [pdf_document_parser.dart](../lib/src/pdf/parsing/pdf_document_parser.dart) |
| F1 | [pdf_import_context.dart](../lib/src/pdf/merging/pdf_import_context.dart), [pdf_object_importer.dart](../lib/src/pdf/merging/pdf_object_importer.dart) |
| F2 | [pdf_page_importer.dart](../lib/src/pdf/merging/pdf_page_importer.dart), `PdfPage.mediaBoxOverride` |
| F3 | [pdf_flatten_importer.dart](../lib/src/pdf/merging/pdf_flatten_importer.dart), `PdfGraphics.drawFormXObject` |
| F4 | [pdf_annotation_importer.dart](../lib/src/pdf/merging/pdf_annotation_importer.dart) |
| F5 | [pdf_form_importer.dart](../lib/src/pdf/merging/pdf_form_importer.dart) |
| F6 | [pdf_outline_importer.dart](../lib/src/pdf/merging/pdf_outline_importer.dart), `PdfOutline.destinationOverride` |
| F7 | [pdf_catalog_merger.dart](../lib/src/pdf/merging/pdf_catalog_merger.dart) |
| F9 | [pdf_signature_policy.dart](../lib/src/pdf/merging/pdf_signature_policy.dart) |
| F1/F10 | [pdf_document_merger.dart](../lib/src/pdf/merging/pdf_document_merger.dart), [pdf_merge_options.dart](../lib/src/pdf/merging/pdf_merge_options.dart), `PdfDocument.merge`/`appendDocument`/`importPage`/`importPageRange` |
| Testes | [test/merging/](../test/merging/) |

### 12.2 Bugs de parser que a mesclagem obrigou a corrigir

Nenhum deles é específico do merge: todos afetavam a leitura de PDFs no geral e
estavam mascarados porque os caminhos existentes toleravam o objeto ausente.

| # | Bug | Efeito antes | Correção |
|---|---|---|---|
| 1 | Leitura de stream limitada à janela de 8 KB (B2) | `readStreamData` devolvia `null` para qualquer stream maior; imagens sumiam | `extractStreamFromReader` lê o stream direto do arquivo, por `/Length` ou varrendo `endstream` |
| 2 | **Preditor PNG do xref stream não era desfeito** | offsets de objeto viravam lixo — em `sample3.pdf`, 4208 dos 4416 objetos conhecidos eram ilegíveis e o documento aparecia com 255 páginas em vez de 366 | `PdfParserPredictor` (PNG e TIFF) aplicado após o inflate, com `/DecodeParms` lido do dicionário |
| 3 | Dicionário maior que a janela abortava a leitura | o `/Contents` de uma assinatura tem de KB a MB de string hexadecimal *dentro do dicionário*; `readHexString` lançava e o objeto virava `null`, então `/V` sumia do campo | exceção passa a escalar a janela; se nem a maior servir, o objeto é lido até o seu `endobj` |
| 4 | `/ByteRange` obsoleto derrubava o validador | `extractSignatureFieldsFromBytes` fazia `sublist` além do fim do arquivo e lançava `RangeError` num documento mesclado | a janela é presa ao tamanho real do arquivo |
| 5 | `updateFieldMetadata` gravava `/M`, `/Reason`, `/Location` e `/Name` no dicionário do **campo** | pela ISO 32000-1 §12.8.1 essas entradas são do dicionário de **assinatura**, que prevalece na leitura; o valor novo era ignorado assim que o dicionário de assinatura passou a ser legível (bug 3) | grava no dicionário de assinatura quando ele existe |
| 6 | `PdfXObject.name` devolvia `X4`, sem a barra | dicionário de recursos inválido (`<<X4 4 0 R>>`) e operando inválido no content stream, para todo XObject que não fosse imagem | `'/X$objser'` |

### 12.3 Desvios em relação ao plano

1. **O memo é o guard de ciclo.** O objeto de destino é alocado com `params`
   vazio *antes* de o conteúdo ser convertido, então o segundo encontro com um
   objeto compartilhado acha o memo. É o mesmo desenho do `PDFObjectCopier` do
   pdf-lib (`referencias/pdf-lib-master/src/core/PDFObjectCopier.ts`), e faz o
   bug de "adotar o objeto de origem" da lib irmã não ter como existir.
2. **Destinos são reconstruídos a partir da origem, não do convertido.** `/Dest`
   costuma ser uma referência indireta para o array; reescrever o valor já
   convertido deixava 23 links de `sample3.pdf` sem destino. A ação `/A` é
   recriada como dicionário direto pelo mesmo motivo.
3. **`/Dest` e `/A` saem da conversão genérica** da anotação, para não deixar no
   arquivo o array antigo como objeto órfão.
4. **Deduplicação só de streams**, por hash do conteúdo bruto mais assinatura do
   dicionário, e apenas quando o dicionário não tem referências indiretas —
   comparar grafos exigiria hash bottom-up. Pega o que importa: programas de
   fonte, imagens e logotipos repetidos.
5. **`PdfOutline` ganhou `destinationOverride`** para o bookmark importado manter
   a vista original (`/XYZ x y z`) em vez de ser normalizado para `/Fit`, e
   passou a tolerar nó sem destino em vez de lançar ao salvar.

### 12.4 Medições

Máquina de desenvolvimento, `dart run`, documento novo como destino:

| Caso | Entrada | Saída | Tempo |
|---|---|---|---|
| `termo.pdf` | 2 páginas, 213 KB | 205 KB | 98 ms |
| `paginador.pdf` | 94 páginas, 1135 KB | 1107 KB | 115 ms |
| `sample3.pdf` | 366 páginas, 8952 KB | 8903 KB | 687 ms |
| 20× `termo.pdf` | 40 páginas, 4264 KB somados | **337 KB** | 118 ms |

A última linha é a deduplicação: 20 cópias do mesmo documento saem em 8% do
tamanho da soma das entradas.

Fidelidade, medida sobre os 63 PDFs de `test/assets/pdfs`: **63/63** mesclam sem
exceção, com a mesma contagem de páginas e o conteúdo de cada página idêntico
byte a byte depois de decodificado. Em `sample3.pdf`, o documento mais complexo
do corpus: 366 páginas, 26 bookmarks, 63 campos de formulário, 412 anotações e
294 links com destino — todos preservados, com um único aviso (a árvore de
marcação estrutural, descartada por decisão de projeto).

### 12.5 Comparação com o SEI

`test/assets/merge/` traz as três entradas reais de um processo e o consolidado
que o SEI produziu. Com `keepInvalidSignatures: true`, a saída daqui tem as
mesmas 2 assinaturas do consolidado do SEI, com o `/ByteRange` verbatim,
incluindo a assinatura **sem widget** — que só sobrevive porque os campos órfãos
são varridos à parte (§10, lição 4). Na colisão de nomes, o SEI renomeia para
`dummyFieldName1` e perde o nome original; aqui o campo vira `Signature1_2`.
Coberto por `test/merging/merge_sei_compatibility_test.dart`.

### 12.6 O que continua fora

Além do que a §9 já listava: a leitura de origem por `PdfRandomAccessReader` sem
carregar o arquivo inteiro em memória funciona no nível do
`PdfDocumentMerger` (que aceita um parser criado com
`PdfDocumentParser.fromReader`), mas o atalho `PdfDocument.merge` recebe
`Uint8List` e portanto mantém as origens em memória.
