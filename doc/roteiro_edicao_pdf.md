# Roteiro de evolução — edição de PDFs e integração interna

> Alvo: **`pdf_plus`**, versão declarada `4.0.0` no workspace.
>
> Levantamento feito em **27/08/2026** sobre a árvore de trabalho atual. Essa
> árvore contém mudanças ainda não versionadas, inclusive a implementação de
> merge em `lib/src/pdf/merging/`; portanto, este roteiro descreve o código que
> existe no workspace, e não apenas a última versão publicada.
>
> Referências estudadas: `insinfo_dart_pdf`, PDFBox e iText em
> `insinfo_dart_pdf/referencias`, além de pdf-lib e MuPDF em
> `pdf_plus/referencias`.

---

## 0. Resumo executivo

O `pdf_plus` já consegue abrir um PDF, preservar os bytes originais, acrescentar
um incremental update, desenhar sobre páginas carregadas, remover páginas,
alterar metadados, manipular alguns campos de assinatura, criar anotações e
importar páginas. A base necessária para uma biblioteca de edição já existe.

O principal problema não é a ausência de operações isoladas, mas a falta de uma
**infraestrutura única de edição**. Hoje cada subsistema conhece uma parte
diferente do grafo PDF:

- o parser resolve objetos da origem;
- `PdfDocument.objects` guarda somente os objetos materializados ou alterados;
- o merge possui seu próprio conversor e importador de objetos;
- `PdfAcroForm` procura referências varrendo `document.objects`;
- `PdfGraphicStream` repete outra busca para resolver `/Resources`;
- `PdfSignatureFieldEditor` usa um contexto especial extraído pelo parser;
- `PdfLoadedDocument` mantém um segundo ciclo de vida para edição e assinatura.

Ampliar edição diretamente sobre essa estrutura aumentaria a replicação de
código e criaria comportamentos diferentes para páginas, formulários,
anotações, merge e assinatura. A ordem recomendada é:

1. criar um repositório/resolvedor central de objetos e um mecanismo único de
   mutação;
2. criar uma fachada de edição sobre `PdfDocument`;
3. migrar páginas, conteúdo, anotações, formulários, merge e assinatura para a
   fundação compartilhada;
4. só então adicionar edição de texto, redação segura e regravação completa.

### Entregas sugeridas

| Marco | Entrega | Estimativa |
|---|---|---:|
| **M1 — editor estrutural** | fundação comum, páginas, geometria, overlay/underlay, carimbo, watermark e Bates | 10–15 dias |
| **M2 — objetos interativos** | anotações carregadas, formulários completos, appearances e integração com assinatura | 10–16 dias |
| **M3 — conteúdo e saneamento** | análise de conteúdo, busca, substituição controlada, redação segura e full rewrite | 15–24 dias |
| **Total** | F0–F11 | **35–55 dias** |

Uma versão menor pode encerrar em M1. Redação segura não deve ser prometida sem
M3, porque um incremental update mantém o conteúdo removido nos bytes antigos.

---

## 1. Objetivos e limites

### 1.1 Objetivos

- oferecer uma API coerente para editar documentos novos e carregados;
- eliminar resolvedores, conversores e rotinas de atualização duplicados;
- preservar referências, gerações, recursos, caixas e rotações corretamente;
- centralizar políticas de assinaturas, DocMDP, criptografia e modo de salvamento;
- tornar as operações idempotentes: salvar duas vezes não pode duplicar
  `/Annots`, `/Fields`, `/Contents` ou recursos;
- permitir evolução por módulos sem cada módulo conhecer detalhes do parser ou
  do xref;
- manter compatibilidade VM/Web e leitura por `PdfRandomAccessReader`.

### 1.2 Fora do primeiro marco

- edição WYSIWYG de parágrafos com reflow;
- OCR;
- reconstrução completa de tagged PDF depois de mudanças de conteúdo;
- edição de documentos criptografados antes de existir descriptografia de
  leitura e preservação das permissões;
- preservação de validade de assinatura após qualquer alteração fora do que a
  assinatura e o DocMDP permitem.

---

## 2. Estado atual comprovado

### 2.1 Capacidades que já existem

| Capacidade | Implementação atual | Observação |
|---|---|---|
| Abrir PDF de bytes ou reader | [`document.dart`](../lib/src/pdf/document.dart), [`pdf_document_parser.dart`](../lib/src/pdf/parsing/pdf_document_parser.dart) | xref clássico, xref stream, object streams e modo de reparo |
| Salvar alteração incremental | [`PdfDocument.save`](../lib/src/pdf/document.dart) | copia `prev.bytes` e escreve novo xref com `/Prev` |
| Materializar catálogo e páginas | [`PdfDocumentParser.mergeDocument`](../lib/src/pdf/parsing/pdf_document_parser.dart) | o restante do grafo continua lazy nos bytes originais |
| Remover página | [`PdfDocument.removePageAt`](../lib/src/pdf/document.dart) | remove da lista plana, mas não faz limpeza referencial completa |
| Desenhar sobre página carregada | [`PdfPage.getGraphics`](../lib/src/pdf/obj/page.dart) | acrescenta um content stream ao `/Contents` existente |
| Mesclar recursos novos com existentes | [`graphic_stream.dart`](../lib/src/pdf/obj/graphic_stream.dart) | já trata `/Resources` direto e indireto materializado |
| Criar anotações | [`annotation.dart`](../lib/src/pdf/obj/annotation.dart) | texto, links, quadrado, círculo, polígono, ink e widgets |
| Formulários básicos | [`pdf_acroform.dart`](../lib/src/pdf/acroform/pdf_acroform.dart), [`pdf_field.dart`](../lib/src/pdf/acroform/pdf_field.dart) | cria/lê tipos básicos e flags; edição de valor/aparência ainda incompleta |
| Editar campos de assinatura | [`PdfSignatureFieldEditor`](../lib/src/pdf/document.dart) | renomeia, remove, altera dicionário e limpa `/V` |
| Importar/mesclar páginas | [`pdf_document_merger.dart`](../lib/src/pdf/merging/pdf_document_merger.dart) | já contém importador profundo e remapeamento de referências |
| Assinar documento carregado | [`pdf_loaded_document.dart`](../lib/src/pdf/signing/pdf_loaded_document.dart) | mantém bytes e documento em uma fachada paralela |
| Inspecionar segurança | [`pdf_security_inspector.dart`](../lib/src/pdf/pdf_security_inspector.dart) | detecta criptografia, assinaturas e problemas estruturais |

### 2.2 Lacunas funcionais imediatas

1. **Página:** não há coleção pública com `insert`, `move`, `reorder`, `duplicate`
   e remoção de intervalo. `removePageAt` não atualiza automaticamente destinos,
   bookmarks, page labels, widgets e referências `/P`.
2. **Conteúdo:** só existe append implícito. Faltam underlay/prepend, isolamento
   garantido com `q/Q`, carimbo multi-página, Bates e API de transformação de
   coordenadas que respeite `MediaBox`, `CropBox`, `Rotate` e `UserUnit`.
3. **Anotações carregadas:** há classes para criar, mas não uma coleção tipada
   que liste, altere, remova ou achate anotações já existentes.
4. **Formulários:** `flattenFields()` ainda não desenha a appearance; o método
   remove o `/AcroForm`, mas `_flattenField` é apenas um esqueleto. Faltam valores,
   appearances, hierarquia `/Kids`, remoção completa e atualização consistente de
   `/NeedAppearances`, `/DR`, `/DA`, `/AP`, `/AS` e `/V`.
5. **Texto:** não existe API pública de extração posicional nem parser de
   operadores reutilizável para edição.
6. **Redação:** não existe remoção segura de texto/imagem. Desenhar um retângulo
   preto é apenas ocultação visual.
7. **Salvamento:** documentos carregados só seguem o modelo incremental. Falta
   full rewrite com coleta de lixo, requisito para sanitização e redação.
8. **Segurança da edição:** as mutações não passam por uma política central de
   DocMDP/assinaturas e documentos criptografados.

---

## 3. Onde há replicação ou integração frágil

| ID | Situação atual | Risco | Consolidação proposta |
|---|---|---|---|
| **D1** | `PdfDocumentParser` resolve objetos; `PdfAcroForm._resolveObject` e `PdfGraphicStream._resolveResourceDict` varrem `document.objects` separadamente | diferenças entre objeto original, materializado e alterado; buscas O(n) | `PdfObjectStore` indexado por `(obj, gen)` |
| **D2** | `PdfParserObjects.toPdfDataType` e `PdfObjectImporter.convert` convertem o mesmo modelo tokenizado para `PdfDataType` | regras divergentes de strings, refs, nulls e arrays | um `PdfObjectConverter` com política de referências injetável |
| **D3** | `PdfAcroForm`, `PdfSignatureFieldEditor`, `PdfAnnotWidget` e `PdfCatalog.prepare()` modificam `/AcroForm` e `/Fields` por caminhos diferentes | campo duplicado, órfão ou removido só de uma árvore | um `PdfFormEditor` e um `PdfAppearanceService` |
| **D4** | `PdfDocument` edita incrementalmente, mas `PdfLoadedDocument` mantém outra cópia de bytes/documento para assinatura | ciclos de vida, numeração de página e salvamento diferentes | `PdfEditSession` como base; assinatura vira operação/commit especializado |
| **D5** | conversão top-left existe em `PdfDocument._rectFromTopLeft` e `PdfSignatureBounds.toPdfRect` | ambas usam só altura e ignoram origem da caixa, crop e rotação | `PdfCoordinateTransformer` único |
| **D6** | `PdfPage` registra a si própria diretamente na lista e `removePageAt` altera a lista diretamente | não existe ponto único para validar/atualizar dependências | `PdfPageCollectionEditor` dono de toda mutação de páginas |
| **D7** | `prepare()` de página/catálogo mescla e reescreve estruturas durante o save | chamadas repetidas podem produzir efeitos cumulativos; modelos concorrentes podem sobrescrever dados crus | construir snapshots serializáveis ou tornar `prepare()` puro/idempotente |
| **D8** | nomes PDF adicionais vivem em `PdfMergeNames`, fora de `PdfNameTokens` | strings mágicas e vocabulário duplicado | completar `PdfNameTokens` e remover o catálogo paralelo |
| **D9** | decodificação de strings e travessia de campos aparecem no parser, merge e AcroForm | Unicode e herança podem variar conforme a API usada | `PdfStringCodec` e `PdfFieldTreeWalker` compartilhados |
| **D10** | importação profunda pertence ao diretório `merging`, embora seja útil para duplicar página, appearance, anexo e full rewrite | novos recursos tenderão a copiar o importador | mover a infraestrutura genérica para `editing/object_graph` e deixar o merge como consumidor |

Regra arquitetural: **parser lê; object store resolve; editores mutam; writer
salva**. Um editor de alto nível não deve chamar `_getObject`, varrer
`document.objects` nem criar diretamente um objeto substituto com o mesmo
número.

---

## 4. Arquitetura alvo

### 4.1 Camadas

```text
PdfDocument / PdfEditSession                 API e política
  ├─ PdfPageCollectionEditor                 páginas e dependências
  ├─ PdfContentEditor                        streams, overlay e underlay
  ├─ PdfAnnotationEditor                     anotações
  ├─ PdfFormEditor                           AcroForm e assinaturas
  ├─ PdfNavigationEditor                     outline, dests e labels
  └─ PdfDocumentPropertiesEditor             metadata, anexos, viewer prefs
                 │
          PdfMutationContext                 dirty set, warnings, rollback
                 │
             PdfObjectStore                  resolve/materialize/replace/delete
           ┌─────┴────────┐
   PdfDocumentParser    objetos novos/importados
           └─────┬────────┘
             PdfWriter                         incremental ou full rewrite
```

### 4.2 Tipos internos centrais

```dart
final class PdfObjectId {
  const PdfObjectId(this.number, this.generation);
  final int number;
  final int generation;
}

abstract interface class PdfObjectStore {
  PdfDataType? resolve(PdfIndirect reference);
  PdfDict? resolveDict(PdfDataType? value);
  PdfArray? resolveArray(PdfDataType? value);
  PdfObject materialize(PdfIndirect reference);
  PdfObject replace(PdfIndirect reference, PdfDataType value);
  PdfObject create(PdfDataType value);
  void markDeleted(PdfIndirect reference);
}

enum PdfSaveMode { auto, incremental, rewrite }

enum PdfSignedDocumentPolicy {
  rejectForbiddenChanges,
  allowAndWarn,
}
```

Requisitos do store:

- chavear cache por número **e geração**;
- enxergar objetos originais lazy, objetos importados, objetos novos e versões
  substitutas;
- manter um dirty set explícito;
- materializar antes de mutar, sem alterar a instância cacheada do parser;
- resolver ciclos e compartilhamento com memo único;
- expor leitura de stream bruto e decodificado;
- ser a dependência do merge, formulário, conteúdo e writer.

### 4.3 Serviços compartilhados

- `PdfObjectConverter`: token → `PdfDataType`, com estratégias `preserveRef`,
  `remapRef` e `resolveDirect`;
- `PdfResourceManager`: resolve, combina e renomeia recursos sem colisão;
- `PdfCoordinateTransformer`: PDF space ↔ top-left/visual space, incluindo
  boxes, rotação e `UserUnit`;
- `PdfAppearanceService`: gera, seleciona e achata `/AP` para anotações e
  campos;
- `PdfReferenceIndex`: índice reverso opcional para descobrir quem aponta para
  página, campo ou anotação antes de remover;
- `PdfContentStreamCodec`: filtros, tokenização de operadores e escrita;
- `PdfEditPolicyEvaluator`: criptografia, assinatura, DocMDP e escolha do modo
  de save.

### 4.4 Organização sugerida

```text
lib/src/pdf/editing/
  pdf_edit_session.dart
  pdf_edit_options.dart
  pdf_edit_result.dart
  object_graph/
    pdf_object_id.dart
    pdf_object_store.dart
    pdf_object_converter.dart
    pdf_reference_index.dart
  pages/
    pdf_page_collection_editor.dart
    pdf_page_geometry.dart
    pdf_coordinate_transformer.dart
  content/
    pdf_content_editor.dart
    pdf_content_stream_codec.dart
    pdf_resource_manager.dart
    pdf_stamp.dart
  annotations/
    pdf_annotation_editor.dart
    pdf_annotation_view.dart
    pdf_appearance_service.dart
  forms/
    pdf_form_editor.dart
    pdf_field_view.dart
    pdf_field_tree_walker.dart
  navigation/
    pdf_navigation_editor.dart
  security/
    pdf_edit_policy.dart
    pdf_redaction.dart
```

O diretório `merging/` continua com a orquestração específica de mesclagem, mas
o importador de grafo e o gerenciador de recursos passam para `editing/`.

### 4.5 Integridade e desempenho na leitura de streams

Adicionar uma opção explícita de parser, por exemplo
`skipStreamBodies`, com valor **`false` por padrão**. O modo padrão precisa
continuar capaz de materializar o corpo bruto dos streams e não pode trocar
integridade por desempenho silenciosamente. A opção `true` é apenas um modo
rápido, opt-in, para inventário estrutural quando o chamador aceita resultado
parcial.

É importante separar dois conceitos:

- **pular a materialização/decodificação do payload** é a otimização controlada
  pela flag;
- **avançar sobre os limites do stream durante a reconstrução do xref** é uma
  proteção estrutural obrigatória nos dois modos. O reparador não pode
  interpretar sequências como `obj`, `endobj`, `xref`, `trailer` ou
  `startxref` existentes em JPEGs e outros dados binários como estrutura PDF.

Contrato proposto:

```dart
final parser = PdfDocumentParser.fromReader(
  reader,
  allowRepair: true,
  skipStreamBodies: false, // padrão conservador
);
```

Regras obrigatórias:

- resolver `/Length` direto ou indireto antes de procurar `endstream`;
- validar que o limite calculado é compatível com o arquivo e com o token
  `endstream`; usar varredura apenas como fallback de reparo;
- manter o payload lazy no reader, sem copiá-lo nem descompactá-lo até que uma
  operação realmente o solicite;
- com `skipStreamBodies: true`, devolver estado explícito de resultado parcial
  e warning; getters de conteúdo/imagem não podem fingir resultado completo;
- proibir ou ignorar o modo rápido em validação de assinatura, diagnóstico de
  corrupção, edição, merge e full rewrite. Essas operações exigem leitura
  conservadora;
- nunca classificar um documento como íntegro apenas com a leitura rápida;
  permitir no máximo “estrutura não totalmente verificada”.

Caso de benchmark/corpus: `14_34074_Vol 5.pdf`, PDF 1.4 com `startxref`
ausente, reparado pelo MuPDF, 528 páginas e 528 imagens DCT. O baseline observado
no `pdf_info` foi aproximadamente **43,4 s**, concentrado na extração
(aproximadamente 43,2 s). Comparar os dois modos deve preservar contagem e ordem
de páginas, referências de imagens e `MediaBox`; diferenças precisam aparecer
como campos deliberadamente não carregados, nunca como informação incorreta.

---

## 5. API pública proposta

Manter `PdfDocument.parseFromBytes` e acrescentar uma única porta de entrada:

```dart
final document = PdfDocument.parseFromBytes(bytes, allowRepair: true);
final editor = document.edit(
  options: const PdfEditOptions(
    signedDocumentPolicy: PdfSignedDocumentPolicy.rejectForbiddenChanges,
  ),
);

editor.pages.move(4, 0);                 // índices base zero
editor.pages.removeRange(8, 12);         // fim exclusivo
editor.pages[0].rotation = PdfPageRotation.rotate90;
editor.pages[0].cropBox = const PdfBox.fromLTWH(20, 20, 555, 802);

editor.pages[0].drawOverlay((canvas) {
  canvas.drawString(font, 10, 'Processo 123 — página 1/20', 30, 20);
});

editor.annotations.onPage(0).add(
  PdfTextAnnotationData(bounds: rect, contents: 'Revisar'),
);

editor.form.field('cliente.nome').setText('Maria');
editor.form.flatten(fields: ['cliente.nome']);

final result = await editor.save(mode: PdfSaveMode.auto);
print(result.warnings);
```

Decisões de consistência:

- API nova usa índice base zero; métodos legados de `pageNumber` base um ficam
  como adaptadores e são marcados claramente;
- retângulos recebem um `PdfCoordinateSpace`, sem helpers duplicados por operação;
- toda operação retorna `void` apenas quando não há warning possível; operações
  destrutivas retornam um resultado com dependências removidas ou reparadas;
- `save(mode: auto)` escolhe incremental para edição aditiva/estrutural e rewrite
  para redação, sanitização e coleta de lixo;
- `PdfLoadedDocument` pode ser mantido por compatibilidade, delegando à sessão.

---

## 6. Fases de implementação

### F0 — contratos, fixtures e baseline — 1–2 dias

- congelar testes das APIs existentes de edição, merge e assinatura;
- acrescentar testes de `save()` repetido no mesmo objeto;
- criar fixtures mínimas para: gerações não zero, `/Resources` indireto,
  `/Contents` array, caixas deslocadas, rotação, campos hierárquicos, anotações
  com popup, links internos, PDF assinado P=1/P=2/P=3, arquivo criptografado e
  stream binário contendo tokens que parecem objetos/xref;
- documentar invariantes de objeto, página e save;
- registrar o estado atual do corpus antes das refatorações.

**Aceite:** nenhum comportamento atual muda sem um teste que explique a mudança.

### F1 — object store e conversor único — 3–4 dias

- implementar `PdfObjectId` e `PdfObjectStore`;
- indexar `PdfDocument.objects` em O(1), por `(objser, objgen)`;
- integrar leitura lazy do `PdfDocumentParser`;
- mover a conversão genérica de `PdfObjectImporter` para
  `PdfObjectConverter`;
- fazer `PdfParserObjects.toPdfDataType` delegar ao mesmo núcleo;
- migrar `PdfGraphicStream` e `PdfAcroForm` para o store;
- manter o importador de merge como estratégia de remapeamento, não como um
  segundo conversor.

**Aceite:** não restam varreduras manuais de `document.objects` fora do store;
parser, merge, formulário e recursos passam pela mesma resolução.

### F2 — sessão de edição, mutações e política — 2–3 dias

- implementar `PdfEditSession`, `PdfMutationContext` e `PdfEditResult`;
- registrar objetos criados, substituídos, removidos e warnings;
- validar índice, ownership e estado da sessão em um único lugar;
- avaliar assinatura, DocMDP e criptografia antes da primeira mutação;
- transformar `PdfLoadedDocument` em adaptador da sessão;
- impedir operações depois de `save/commit/dispose`, conforme contrato escolhido;
- garantir que falha de validação antes do commit não deixe mutação parcial.

**Aceite:** todas as novas APIs usam a sessão; assinatura carregada e edição
normal compartilham parser, páginas, coordenadas e ciclo de vida.

### F3 — coleção de páginas com integridade — 2–3 dias

- `insert`, `remove`, `removeRange`, `move`, `reorder` e `duplicate`;
- centralizar registro de `PdfPage`; o construtor deixa de editar silenciosamente
  a lista ou ganha um construtor interno não registrador;
- atualizar `/Kids`, `/Count`, `/Parent` e atributos herdados;
- ao remover/reordenar, tratar:
  - destinos explícitos e nomeados;
  - outlines;
  - links internos;
  - page labels;
  - widgets e `/P`;
  - `OpenAction` e estruturas que apontam para páginas;
- oferecer política para referência quebrada: `remove`, `retarget` ou `throw`;
- reutilizar importação profunda para `duplicate` e páginas estrangeiras.

**Aceite:** saída recarrega, tem a ordem esperada e não possui referência para
página removida em nenhuma estrutura coberta.

### F4 — geometria, recursos e carimbos — 2–3 dias

- criar `PdfBox` preservando `llx/lly/urx/ury`;
- suportar Media/Crop/Bleed/Trim/Art box e `UserUnit`;
- unificar conversões de coordenadas, inclusive páginas rotacionadas;
- criar `drawUnderlay`, `drawOverlay` e `replaceContent` com semântica explícita;
- isolar conteúdo antigo e novo com `q ... Q` quando necessário;
- mover a mesclagem de `/Resources` para `PdfResourceManager`;
- tratar colisões de nomes em `/Font`, `/XObject`, `/ExtGState`, `/Pattern`,
  `/Shading`, `/ColorSpace` e `/Properties`;
- entregar `PdfStamp`, watermark e Bates/page-numbering multi-página.

Usar como referência o `AppendMode` e `resetContext` do
[`PDPageContentStream`](../../insinfo_dart_pdf/referencias/pdfbox-trunk/pdfbox/src/main/java/org/apache/pdfbox/pdmodel/PDPageContentStream.java).

**Aceite:** um overlay não altera o estado gráfico do conteúdo original nem
perde recursos de páginas importadas/carregadas.

### F5 — anotações carregadas e appearances — 3–5 dias

- criar views tipadas sobre dicionários existentes, sem duplicar objetos;
- coleção por página com `list/add/update/remove/flatten`;
- cobrir inicialmente Text, Link, FreeText, Square, Circle, Line, Polygon,
  PolyLine, Ink, Highlight, Underline, StrikeOut, Squiggly, Stamp e Popup;
- preservar `/NM`, `/M`, `/F`, `/C`, `/Border`, `/BS`, `/AP`, `/AS`, `/Popup`
  e `/IRT`;
- manter coerência bidirecional entre `/Annots`, `/Popup`, `/Parent` e `/P`;
- compartilhar `PdfAppearanceService` com formulários;
- deixar import/export FDF/XFDF/JSON para uma subfase posterior, usando a
  implementação irmã apenas como referência comportamental.

Referência interna: coleção e flatten em
[`pdf_annotation_collection.dart`](../../insinfo_dart_pdf/lib/src/pdf/implementation/annotations/pdf_annotation_collection.dart).

**Aceite:** editar e remover uma anotação carregada funciona por incremental
update e permanece correto depois de reabrir e salvar novamente.

### F6 — unificação de AcroForm e assinatura — 4–6 dias

- substituir a divisão `PdfAcroForm` × `PdfSignatureFieldEditor` por
  `PdfFormEditor` e views especializadas;
- usar um walker único para herança `/FT`, `/Ff`, `/V`, `/DV`, `/DA`, `/DR`,
  `/Q` e nomes totalmente qualificados;
- suportar text, checkbox, radio, push button, combo, list e signature;
- implementar getters/setters de valor e seleção;
- marcar campos dirty e regenerar appearances quando necessário;
- implementar flatten real: desenhar `/AP /N` na página, respeitar matriz/bbox,
  depois remover widget, field, kids e referências;
- preservar campos de assinatura invisíveis e campos sem widget;
- fazer criação por `PdfAnnotWidget`, helpers legados e serviço de assinatura
  delegarem ao mesmo editor;
- remover XFA apenas por opção explícita e warning.

Referências:

- [`PDFForm.ts`](../referencias/pdf-lib-master/src/api/form/PDFForm.ts), para
  dirty fields, appearances, remoção e flatten;
- [`PDAcroForm.java`](../../insinfo_dart_pdf/referencias/pdfbox-trunk/pdfbox/src/main/java/org/apache/pdfbox/pdmodel/interactive/form/PDAcroForm.java), para refresh de appearance antes de flatten;
- [`pdf_form.dart`](../../insinfo_dart_pdf/lib/src/pdf/implementation/forms/pdf_form.dart), para tipos e casos de formulário já tratados na lib irmã.

**Aceite:** flatten deixa a aparência visível e remove todas as referências do
campo; alterar valor produz a mesma visualização em Acrobat, Chrome e SumatraPDF.

### F7 — propriedades, navegação e anexos — 2–3 dias

- editor de `/Info` sem invalidar silenciosamente o objeto anterior;
- XMP: leitura, substituição e sincronização opcional com `/Info`;
- outlines, named destinations, page labels, viewer preferences e open action;
- anexos via `/Names /EmbeddedFiles` e `/AF`;
- reaproveitar `PdfNavigationEditor` na remoção/reordenação e no merge;
- adicionar operações `removeAllAttachments`, `removeJavaScript` e
  `removeOpenAction` como parte de sanitização explícita.

Referência de API: `attach`, metadados e páginas em
[`PDFDocument.ts`](../referencias/pdf-lib-master/src/api/PDFDocument.ts).

### F8 — análise de conteúdo e edição controlada de texto — 5–8 dias

- portar/adaptar o extrator da biblioteca irmã para um parser de operadores
  compartilhado, não para um módulo isolado;
- entregar busca com página, bounds, glyphs, font, matriz e origem do XObject;
- decodificar `Tj`, `TJ`, `'`, `"`, CMaps e ToUnicode;
- expor duas operações com nomes que não escondam suas limitações:
  - `overlayTextReplacement`: cobre visualmente e desenha texto novo;
  - `rewriteTextOperators`: altera operadores somente quando a fonte consegue
    codificar o novo texto e a estrutura é suportada;
- nunca chamar overlay de “remoção” ou “redação”;
- emitir erro detalhado para Type3, glyph sem mapeamento, XObject compartilhado
  e shaping complexo ainda não suportado.

Referência: extrator em
[`pdf_text_extractor.dart`](../../insinfo_dart_pdf/lib/src/pdf/implementation/exporting/pdf_text_extractor/pdf_text_extractor.dart).

**Aceite:** resultados possuem coordenadas reproduzíveis; substituição por
rewrite só ocorre quando é semanticamente segura, sem corromper o stream.

### F9 — redação segura — 4–6 dias

- criar anotação `/Redact` separada da aplicação da redação;
- ao aplicar, remover operadores de texto, imagem e vetor que intersectem a área;
- tratar Form XObjects compartilhados por clonagem antes da alteração;
- remover metadados, attachments ou actions apenas conforme opções;
- forçar `PdfSaveMode.rewrite` com coleta de lixo;
- rejeitar `incremental`, pois os bytes antigos ainda conteriam a informação;
- avisar que todas as assinaturas anteriores ficam inválidas/removidas;
- verificar ausência do segredo por busca nos bytes, extração de texto e
  renderização comparativa.

O MuPDF explicita que aplicar redações impede salvamento incremental em
[`document.h`](../referencias/mupdf-master/include/mupdf/pdf/document.h) e
fornece as operações de redação em
[`page.h`](../referencias/mupdf-master/include/mupdf/pdf/page.h) e
[`annot.h`](../referencias/mupdf-master/include/mupdf/pdf/annot.h).

**Aceite:** o conteúdo redigido não existe em revisões antigas, streams,
XObjects, metadados ou anexos da saída.

### F10 — writer unificado, full rewrite e otimização — 3–5 dias

- separar seleção de objetos da serialização;
- `incremental`: gravar somente objetos dirty e preservar base;
- `rewrite`: percorrer objetos alcançáveis desde trailer/catalog, renumerar se
  solicitado e eliminar órfãos;
- `auto`: selecionar modo conforme as operações da sessão;
- tornar preparação idempotente ou criar snapshot sem mutar o modelo;
- preservar ou atualizar corretamente `/ID`, versão, xref e generations;
- compactar streams sem recomprimir JPEG/JPX desnecessariamente;
- oferecer deduplicação opcional de recursos usando a infraestrutura do merge;
- rejeitar edição criptografada enquanto não houver security handler de leitura;
- futuramente, preservar criptografia só com senha/permissão válidas.

Referências:

- append mode e preservação de criptografia em
  [`StampingProperties.cs`](../../insinfo_dart_pdf/referencias/itext-dotnet-develop/itext/itext.kernel/itext/kernel/pdf/StampingProperties.cs);
- opções incremental/full e journal em
  [`document.h`](../referencias/mupdf-master/include/mupdf/pdf/document.h) e
  [`object.h`](../referencias/mupdf-master/include/mupdf/pdf/object.h);
- reordenação/clean em
  [`clean.h`](../referencias/mupdf-master/include/mupdf/pdf/clean.h).

**Aceite:** save repetido é estável; incremental preserva prefixo; rewrite não
contém objetos inalcançáveis; ambos recarregam no parser e em leitores externos.

### F11 — testes, documentação, compatibilidade e performance — 2–4 dias

- documentação com tabela “criar × editar carregado × incremental × rewrite”;
- exemplos de reordenar páginas, carimbar, editar formulário, remover anotação e
  redigir com segurança;
- corpus cruzado com PDFs de `pdf_plus`, `insinfo_dart_pdf`, pdf-lib e PDF 2.0;
- validação externa automatizada quando disponível: qpdf, mutool e PDFBox;
- testes visuais por renderização antes/depois;
- fuzz de árvores de páginas, arrays de annotations e fields;
- benchmarks de reader grande, número de objetos, memória e tempo de save,
  incluindo PDF reparado com centenas de streams nos modos conservador e
  `skipStreamBodies`;
- comparar o corpus reparado com `mutool info` e outro leitor externo; o modo
  rápido precisa declarar incompletude e nunca participar do veredito de
  corrupção ou validade de assinatura;
- atualizar exports, README, CHANGELOG e versão apenas na entrega de cada marco.

---

## 7. Plano de testes por domínio

| Suíte | Casos obrigatórios |
|---|---|
| Object store | geração não zero, ciclo, objeto compartilhado, substituição, exclusão e lazy loading |
| Save | incremental preserva prefixo; rewrite remove órfãos; dois saves não duplicam estruturas |
| Páginas | insert/move/remove/range/duplicate; links, outlines, labels e widgets após reorder |
| Geometria | box deslocado, crop diferente de media, 0/90/180/270°, `UserUnit` e top-left |
| Conteúdo | append/prepend, `q/Q`, resources diretos/indiretos, colisão de nomes, XObject compartilhado |
| Anotações | criar/ler/alterar/remover/flatten; popup/reply; appearance normal e estados |
| Formulários | hierarquia, kids, valores, Unicode, opções, appearances, flatten e campos invisíveis |
| Segurança | DocMDP P=1/2/3, assinatura existente, criptografado e política reject/warn |
| Texto | CMap, ToUnicode, kerning, rotação, XObject, Type0/Type1/TrueType e falhas explícitas |
| Redação | segredo ausente de bytes e texto extraído; imagem/vetor; rewrite obrigatório |
| Corpus | abrir → editar mínima → salvar → reabrir em todos os assets elegíveis |

Invariantes globais:

1. nenhuma referência aponta para objeto inexistente;
2. `/Pages /Count` corresponde à árvore;
3. widgets aparecem em `/Annots` e `/Fields` exatamente uma vez;
4. toda alteração em documento assinado gera decisão explícita da política;
5. warnings são determinísticos e testáveis;
6. não há diferença de semântica entre bytes, reader com cache e reader sem cache.

---

## 8. Matriz das referências e o que aproveitar

| Referência | Aproveitar | Não copiar diretamente |
|---|---|---|
| [`insinfo_dart_pdf`](../../insinfo_dart_pdf/lib/src/pdf/implementation/) | cobertura de tipos, casos reais brasileiros, forms, annotations, text extractor e experiências do merge | arquitetura inteira: ela materializa o grafo e tem modelo de save diferente |
| [pdf-lib `PDFDocument`](../referencias/pdf-lib-master/src/api/PDFDocument.ts) | API pequena e previsível para páginas, embed, metadata, anexos e forms | writer full rewrite como única estratégia e limitações de edição textual |
| [pdf-lib `PDFPage`](../referencias/pdf-lib-master/src/api/PDFPage.ts) | boxes, rotação, scale/translate e desenho em páginas carregadas | assumir box na origem zero ou ignorar implicações de conteúdo existente |
| [PDFBox `PDDocument`](../../insinfo_dart_pdf/referencias/pdfbox-trunk/pdfbox/src/main/java/org/apache/pdfbox/pdmodel/PDDocument.java) | páginas, import e save incremental | APIs Java e estado mutável sem adaptar ao modelo lazy do `pdf_plus` |
| [PDFBox `PDPageContentStream`](../../insinfo_dart_pdf/referencias/pdfbox-trunk/pdfbox/src/main/java/org/apache/pdfbox/pdmodel/PDPageContentStream.java) | append/prepend/overwrite e reset do contexto gráfico | dependências de IO e scratch-file |
| [iText `PdfDocument`](../../insinfo_dart_pdf/referencias/itext-dotnet-develop/itext/itext.kernel/itext/kernel/pdf/PdfDocument.cs) | integridade de page tree, copy/move/remove e append mode | superfície extensa e abstrações ligadas ao ecossistema iText |
| [MuPDF PDF API](../referencias/mupdf-master/include/mupdf/pdf/document.h) | dirty objects, journal, incremental/full, graft, páginas e critérios para rewrite | implementação C/rendering engine; usar como especificação comportamental |
| [MuPDF annotations](../referencias/mupdf-master/include/mupdf/pdf/annot.h) | ciclo create/update/delete, appearances e redação | vincular a lib Dart a código nativo |

As referências são fonte de comportamento e casos de teste. O código deve ser
reescrito para o modelo do `pdf_plus` e respeitar as licenças de cada projeto.

---

## 9. Riscos e decisões obrigatórias

| Risco | Mitigação/decisão |
|---|---|
| Alteração inválida em PDF assinado | policy central; default conservador `rejectForbiddenChanges` |
| “Redação” que só esconde visualmente | nomear overlay corretamente e reservar `redact/applyRedactions` para rewrite seguro |
| Campo achatado desaparecer | só remover depois de validar e desenhar `/AP /N` |
| Página removida deixar links/bookmarks quebrados | índice reverso e política explícita de dependências |
| Save repetido duplicar arrays | preparação idempotente e testes de dois/ três saves |
| Resolver objeto errado por ignorar geração | `PdfObjectId(number, generation)` em todos os caches |
| Perder recursos ao desenhar em página carregada | `PdfResourceManager` resolve indiretos e renomeia colisões |
| API com coordenadas inconsistentes | transformer único e coordinate space obrigatório quando ambíguo |
| Explosão de RAM em arquivos grandes | leitura lazy por reader; materializar somente objetos tocados |
| Otimização de streams ocultar dano ou criar falso positivo estrutural | `skipStreamBodies=false` por padrão; modo rápido opt-in e resultado marcado como parcial; reparo sempre respeita os limites do stream |
| Full rewrite apagar informação não compreendida | traversal conservador, corpus e opção de preservação; nunca usar automaticamente salvo quando necessário |
| Duplicar novamente lógica no merge | merge depende do object store/converter/resource manager comuns |

### 9.1 Impacto prospectivo no SALI depois da implementação deste roteiro

Compilar o `new_sali_core` contra o estado atual da versão 4.0.0 serve somente
como **baseline T0**. Isso não demonstra compatibilidade com o resultado futuro
das fases F1–F11. A migração do SALI só pode ser considerada segura depois de
executar novamente os testes contra a implementação final da refatoração.

O SALI possui dois grupos de consumidores com riscos diferentes:

1. **validação e decisão de upload:** usa `PdfQuickInfo`,
   `PdfSecurityInspector`, `PdfSignatureValidator`,
   `PdfSmartSignatureValidator` e `PdfValidationApi`; os resultados alimentam
   diretamente `isCorrupted`, `possuiAssinaturaValida`, `documentoIntegro` e
   `permiteUploadComoAssinaturaExterna`;
2. **geração de documentos:** relatórios, guias, recibos, processos e conversão
   Quill usam `Document`, `MultiPage`, `PdfPageFormat`, widgets, fontes,
   imagens, temas e `save()` em muitos pontos do `new_sali_core`.

Portanto, compatibilidade de assinatura de método não é suficiente. Uma
refatoração pode compilar e ainda bloquear um PDF válido, aceitar assinatura
inválida, perder uma página ou recurso, mudar a paginação ou lançar uma exceção
nova em produção.

| Fase | Área do SALI exposta | Falha possível após a refatoração | Risco | Gate obrigatório |
|---|---|---|---:|---|
| F1 — store/parser | preflight, campos de assinatura, PDFs reparados | resolver geração/objeto errado, não encontrar `/ByteRange`, interpretar token dentro de stream, falso “corrompido” | **crítico** | corpus SALI com comparação T0 × versão final para classificação, quantidade de assinaturas e campos |
| F2 — sessão/política | documentos carregados e assinatura | política bloquear alteração permitida, mutação parcial antes de exception, ciclo de vida diferente | **alto** | testes de rollback, save repetido e exceptions tipadas; APIs legadas delegam sem mudar semântica |
| F3 — páginas | relatórios e documentos editados | página ausente/duplicada, ordem diferente, link ou widget órfão | **alto** | contagem, ordem, boxes e referências depois de reabrir; renderização comparativa |
| F4 — geometria/recursos | todos os relatórios do SALI | fonte ou imagem perdida, coordenada/rotação diferente, colisão de recurso, paginação alterada | **alto** | testes dos geradores reais do SALI e comparação visual, não apenas parse da saída |
| F5 — anotações | links, widgets e visualizador | anotação invisível, popup/ação quebrada ou referência `/P` incorreta | **médio/alto** | round-trip em Acrobat/Chrome/Sumatra e inspeção estrutural |
| F6 — AcroForm/assinatura | detecção, metadata `Reason`, assinatura interna/externa | remover `/V`, associar motivo ao assinante errado, perder campo invisível ou aprovar assinatura errada | **crítico** | CMS, digest, ByteRange, integridade, nome do campo e `Reason` idênticos ao baseline |
| F8 — content streams | extração, reparo e edição de texto | falso objeto dentro de stream, decodificação parcial tratada como completa | **alto** | `skipStreamBodies=false` no fluxo de segurança e fixtures binárias adversariais |
| F9 — redação | eventual saneamento no SALI | segredo permanecer em revisão/stream ou assinatura antiga parecer válida | **crítico** | busca nos bytes, extração, renderização e ausência de assinatura aprovada após rewrite |
| F10 — writer/save | todo PDF gerado ou alterado | xref/trailer inválido, incremental incorreto, mudança de bytes assinados, PDF que abre mas falha em outro leitor | **crítico** | parser próprio + qpdf + mutool + segundo leitor; testes de assinatura antes/depois de cada modo |
| F11 — VM/Web | frontend do SALI | comportamento diferente no dart2js release ou crash causado por `List.unmodifiable(...)` | **crítico** | testes VM e compilação/execução Web release; usar `UnmodifiableListView` nos caminhos do frontend |

#### Invariantes de segurança que a versão final deve preservar

- PDF válido e não assinado nunca vira `isCorrupted=true` somente por diferença
  de parser, xref reparado, stream grande ou otimização;
- PDF sem `%%EOF`, truncado ou com `ByteRange` fora do arquivo continua
  reprovado sem exception não tratada;
- nenhuma assinatura conta como válida sem `cmsValid`, `digestValid`, `intact`
  e status aprovado conforme a política temporal/de confiança do SALI;
- indisponibilidade de truststore não pode virar aprovação automática nem
  corrupção do documento;
- múltiplas assinaturas incrementais preservam quantidade, ordem, campo,
  `Reason`, certificado e cobertura individual;
- `approved`, `indeterminate` e `rejected`, inclusive valores nulos de cadeia e
  revogação, mantêm o significado usado pelo SALI;
- o modo rápido de streams nunca é usado para `PdfQuickInfo`, inspeção de
  segurança, validação, edição, merge ou decisão de upload;
- exceptions internas do novo store/writer não podem ser convertidas
  silenciosamente em “não é PDF”, “corrompido” ou “assinatura inválida”;
- geração com `Document`/`MultiPage` mantém conteúdo, paginação, fontes,
  imagens, links e capacidade de reabrir a saída;
- merge de origem assinada segue política explícita. Enquanto
  `keepInvalidSignatures` não mantiver de fato uma assinatura detectável e
  inequivocamente inválida, essa opção fica bloqueada para uso pelo SALI.

#### Gate de migração do SALI para a versão refatorada

A migração não deve ocorrer apenas porque `dart analyze` ou a compilação
passaram. Antes de atualizar a dependência do SALI:

1. concluir F1–F11 mantendo um baseline versionado dos resultados da 3.17.4;
2. executar no `pdf_plus` a suíte de contrato SALI com PDFs sem assinatura,
   assinados ICP-Brasil/gov.br/SALI, múltiplas assinaturas, assinatura
   corrompida, arquivo truncado, criptografado e xref reparado;
3. executar **toda** a suíte do `new_sali/core` com override para a versão final,
   incluindo geração de PDFs e política de upload;
4. compilar e executar os fluxos do frontend em dart2js release, não somente na
   VM/DDC;
5. comparar relatórios e guias reais por estrutura e renderização; hash binário
   não é gate adequado porque IDs, datas, compressão e ordem física podem mudar;
6. validar o corpus com pelo menos dois leitores externos e registrar qualquer
   divergência;
7. somente depois promover a dependência em ambiente de homologação e testar
   upload, visualização, assinatura e revalidação ponta a ponta.

Qualquer divergência em validade, integridade, corrupção, quantidade de
assinaturas ou decisão de upload é bloqueadora. Mudança apenas de API pública,
desde que acompanhada da migração do chamador e sem mudança semântica, não é
bloqueadora.

---

## 10. Ordem de migração sem quebra de API

1. introduzir infraestrutura interna e manter APIs existentes delegando a ela;
2. migrar `PdfGraphicStream` e merge, pois exercitam recursos e referências;
3. migrar `PdfAcroForm` e `PdfSignatureFieldEditor` para o editor único;
4. fazer `PdfLoadedDocument` delegar à sessão;
5. publicar a nova fachada `document.edit`;
6. marcar helpers redundantes como deprecated somente após equivalência de
   testes e exemplo de migração;
7. remover código legado apenas em versão major.

Não criar uma segunda árvore de objetos “de edição”. O store deve fazer a ponte
entre os objetos lazy do parser e os `PdfObject` já usados pelo writer.

---

## 11. Checklist executável

```text
[ ] F0  Baseline, fixtures e invariantes, incluindo streams binários no reparo
[x] F1  PdfObjectStore + índice por obj/gen + conversor único
[ ] F2  PdfEditSession + mutation context + policy de segurança
[ ] F3  Coleção de páginas e reparo de dependências
[~] F4  Boxes/coordenadas + resource manager + overlay/underlay/carimbos
[ ] F5  Coleção de anotações carregadas + appearances + flatten
[ ] F6  PdfFormEditor único + valores + appearances + flatten real
[ ] F7  Metadata/XMP + navegação + anexos + sanitização estrutural
[ ] F8  Parser de content streams + extração posicional + edição controlada
[ ] F9  Redação segura com full rewrite obrigatório
[ ] F10 Writer incremental/rewrite/auto + GC + idempotência
[ ] F11 Corpus, validação externa, benchmarks dos dois modos de stream, docs e exemplos
```

### Critério para declarar M1 pronto

- página carregada pode ser inserida, movida e removida sem quebrar dependências;
- overlay e underlay funcionam em qualquer rotação/box testado;
- merge usa a mesma resolução/conversão/gestão de recursos do editor;
- `PdfDocument.save()` repetido não duplica conteúdo ou arrays;
- política de documento assinado é aplicada antes da mutação.

### Critério para declarar a edição completa pronta

- M1, M2 e M3 concluídos;
- formulários e anotações têm round-trip e flatten real;
- redação força rewrite e elimina fisicamente os dados;
- corpus passa em parser próprio e em ao menos dois validadores/leitores externos;
- não existem resolvedores ou conversores paralelos fora da infraestrutura comum.

---

## 12. Estado da implementação

Atualizado em 27/08/2026, sobre a mesma árvore de trabalho.

### F1 — entregue

- `lib/src/pdf/editing/object_graph/pdf_object_store.dart`: `PdfObjectId` e
  `PdfObjectStore`, com índice por `(objser, objgen)` reconstruído quando
  `document.objects` muda de tamanho, `lookup`/`resolve`/`resolveDict`/
  `resolveArray` e fallback opcional ao `PdfDocumentParser` para o documento
  carregado. `PdfObjectStore.of(document)` guarda a instância por documento.
- `lib/src/pdf/editing/object_graph/pdf_object_converter.dart`: o conversor
  único, com `PdfReferencePolicy.preserve` / `.remap` e `PdfArrayGapPolicy`.
- Consumidores migrados: `PdfParserObjects.toPdfDataType`/`toPdfDict`/
  `toPdfArray`/`mergeDictIntoPdfDict` delegam ao núcleo (D2);
  `PdfAcroForm` e `PdfGraphicStream` usam o store em vez de varrer
  `document.objects` (D1); e o `PdfObjectImporter` da mesclagem passou a ser
  apenas uma política de referência sobre o mesmo conversor — o que muda entre
  ler um documento e importar de outro é só o destino das referências.
- Não sobrou varredura linear de `document.objects` para resolver referência em
  `lib/`.
- Efeito colateral registrado: a resolução no `PdfAcroForm` passou a casar
  geração além do número do objeto, o que antes era ignorado.

### F4 — parcial

Entregue: `PdfBox` (com `/MediaBox`, `/CropBox`, `/BleedBox`, `/TrimBox`,
`/ArtBox`, normalização de caixa invertida e interseção),
`PdfCoordinateTransformer`, `PdfPageContentEditor` (overlay, underlay e carimbo
com a técnica `q` … `Q` sem tocar no stream original) e `PdfBatesNumbering`,
todos exportados por `package:pdf_plus/pdf.dart`.

As duas conversões antigas de coordenada foram substituídas (D5):
`PdfDocument._rectFromTopLeft` e `PdfSignatureBounds.toPdfRect` delegam ao
transformador, o que corrige a posição em página com caixa deslocada e em página
rotacionada.

Fica para depois: `PdfResourceManager` com política de colisão de nomes,
opacidade via `/ExtGState` (hoje `prepare()` substituiria um `/ExtGState` direto
já existente) e `replaceContent`, que depende da coleção de páginas de F3.

### Bugs de corrupção que esta fase desenterrou

Dois defeitos que atingiam qualquer documento carregado, não só a edição:

| Bug | Efeito | Correção |
|---|---|---|
| `mergeDocument` registrava cada página duas vezes | todo save de documento carregado saía com `/Kids` duplicado e `/Count` dobrado | o construtor de `PdfPage` já registra; o `addAll` foi removido |
| `/Resources` indireto não materializado era substituído | desenhar sobre página carregada apagava fontes e imagens dela (12 PDFs do corpus) | o dicionário original é lido pelo parser e recebe o merge |

### O que a mesclagem já entrega da fundação comum

O trabalho de merge (ver `roteiro_merge_pdf.md`) resolveu, antes de F1, quatro
itens que este roteiro listava como pendências de infraestrutura:

| Item | Onde |
|---|---|
| Importação profunda com remapeamento de referências | `lib/src/pdf/merging/pdf_object_importer.dart` — é a base que F3 vai reusar para `duplicate` de página |
| Materialização de atributos herdados da árvore `/Pages` | `PdfPageImporter._materializeInherited` |
| `/MediaBox` com origem diferente de (0,0) | `PdfPage.mediaBoxOverride` — a limitação de `PdfPageFormat` apontada em §2.2 |
| `/Resources` indireto mesclado em vez de sobrescrito | `PdfGraphicStream.prepare` |

Continua valendo a regra de arquitetura da §3: parser lê, store resolve,
editores mutam, writer salva.
