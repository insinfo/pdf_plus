import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:pdf_plus/widgets.dart' as pw;

/// Bytes de um PDF do corpus de teste.
Uint8List asset(String name) =>
    File('test/assets/pdfs/$name').readAsBytesSync();

/// Bytes de uma fixture de mesclagem.
Uint8List mergeAsset(String name) =>
    File('test/assets/merge/$name').readAsBytesSync();

/// Reabre um PDF gerado, garantindo que ele é legível.
PdfDocumentParser reopen(Uint8List bytes) =>
    PdfDocumentParser(bytes, allowRepair: true);

/// Gera um PDF simples com [pageCount] páginas de texto.
Future<Uint8List> buildTextPdf({
  int pageCount = 2,
  String prefix = 'Pagina',
  PdfPageFormat format = PdfPageFormat.a4,
}) async {
  final document = pw.Document();
  for (var i = 1; i <= pageCount; i++) {
    document.addPage(
      pw.Page(
        pageFormat: format,
        build: (context) => pw.Center(child: pw.Text('$prefix $i')),
      ),
    );
  }
  return document.save();
}

/// Gera um PDF com uma imagem, para exercitar streams grandes e dedup.
Future<Uint8List> buildImagePdf({int pageCount = 1}) async {
  final bytes = File('test/assets/images/logo_sali.png').readAsBytesSync();
  final image = pw.MemoryImage(bytes);
  final document = pw.Document();
  for (var i = 0; i < pageCount; i++) {
    document.addPage(
      pw.Page(build: (context) => pw.Center(child: pw.Image(image))),
    );
  }
  return document.save();
}

/// Conteúdo da página já decodificado, para comparar fidelidade sem depender
/// de o destino recomprimir o que a origem trazia sem filtro.
Uint8List? decodedPageContent(PdfDocumentParser parser, int pageIndex) {
  final page = parser.pageDictAt(pageIndex);
  if (page == null) return null;

  final parts = <int>[];
  void addStream(dynamic value) {
    final ref = PdfParserObjects.asRef(value);
    if (ref == null) return;
    final object = parser.getObject(ref.obj);
    var data = object?.streamData;
    if (data == null || object == null) return;

    final dict = object.value;
    if (dict is PdfDictToken) {
      for (final filter in _filterNames(parser, dict.values['/Filter'])) {
        if (filter != '/FlateDecode') return;
        try {
          data = Uint8List.fromList(ZLibDecoder().decodeBytes(data!));
        } catch (_) {
          return;
        }
      }
    }
    parts.addAll(data!);
  }

  final contents = page.values['/Contents'];
  final resolved = parser.resolve(contents);
  if (resolved is PdfArrayToken) {
    for (final item in resolved.values) {
      addStream(item);
    }
  } else {
    addStream(contents);
  }

  return parts.isEmpty ? null : Uint8List.fromList(parts);
}

List<String> _filterNames(PdfDocumentParser parser, dynamic value) {
  final resolved = parser.resolve(value);
  if (resolved is PdfNameToken) return <String>[resolved.value];
  if (resolved is PdfArrayToken) {
    return resolved.values
        .whereType<PdfNameToken>()
        .map((e) => e.value)
        .toList();
  }
  return const <String>[];
}

/// Quantidade total de anotações do documento.
int annotationCount(PdfDocumentParser parser) {
  var total = 0;
  for (var i = 0; i < parser.pageCount; i++) {
    final page = parser.pageDictAt(i);
    if (page == null) continue;
    final annots = parser.resolve(page.values['/Annots']);
    if (annots is PdfArrayToken) total += annots.values.length;
  }
  return total;
}

/// Anotações de uma página, já resolvidas.
List<PdfDictToken> annotationsOf(PdfDocumentParser parser, int pageIndex) {
  final page = parser.pageDictAt(pageIndex);
  if (page == null) return const <PdfDictToken>[];
  final annots = parser.resolve(page.values['/Annots']);
  if (annots is! PdfArrayToken) return const <PdfDictToken>[];
  return annots.values
      .map(parser.resolve)
      .whereType<PdfDictToken>()
      .toList(growable: false);
}

/// Links que continuam sabendo para onde saltar.
int linksWithDestination(PdfDocumentParser parser) {
  var total = 0;
  for (var i = 0; i < parser.pageCount; i++) {
    for (final annot in annotationsOf(parser, i)) {
      if (PdfParserObjects.asName(annot.values['/Subtype']) != '/Link') {
        continue;
      }
      if (annot.values['/Dest'] != null) {
        total++;
        continue;
      }
      final action = parser.resolve(annot.values['/A']);
      if (action is PdfDictToken &&
          PdfParserObjects.asName(action.values['/S']) == '/GoTo' &&
          action.values['/D'] != null) {
        total++;
      }
    }
  }
  return total;
}

/// Dicionário `/AcroForm` do documento, se houver.
PdfDictToken? acroForm(PdfDocumentParser parser) {
  final root = parser.rootDict;
  if (root == null) return null;
  final form = parser.resolve(root.values['/AcroForm']);
  return form is PdfDictToken ? form : null;
}

/// Nomes dos campos de formulário no topo de `/Fields`.
List<String> fieldNames(PdfDocumentParser parser) {
  final form = acroForm(parser);
  if (form == null) return const <String>[];
  final fields = parser.resolve(form.values['/Fields']);
  if (fields is! PdfArrayToken) return const <String>[];

  final names = <String>[];
  for (final entry in fields.values) {
    final dict = parser.resolve(entry);
    if (dict is! PdfDictToken) continue;
    final title = parser.resolve(dict.values['/T']);
    names.add(title is PdfStringToken
        ? String.fromCharCodes(title.bytes)
        : '(sem nome)');
  }
  return names;
}

/// Quantidade de nós na árvore de bookmarks.
int outlineCount(PdfDocumentParser parser) {
  final root = parser.rootDict;
  if (root == null) return 0;
  final outlines = parser.resolve(root.values['/Outlines']);
  if (outlines is! PdfDictToken) return 0;

  var total = 0;
  void walk(dynamic first, int depth) {
    if (depth > 40) return;
    var current = first;
    final visited = <int>{};
    for (var guard = 0; guard < 100000; guard++) {
      final ref = PdfParserObjects.asRef(current);
      if (ref != null && !visited.add(ref.obj)) break;
      final node = parser.resolve(current);
      if (node is! PdfDictToken) break;
      total++;
      final child = node.values['/First'];
      if (child != null) walk(child, depth + 1);
      final next = node.values['/Next'];
      if (next == null) break;
      current = next;
    }
  }

  final first = outlines.values['/First'];
  if (first != null) walk(first, 0);
  return total;
}

/// Títulos dos bookmarks, em ordem de leitura.
List<String> outlineTitles(PdfDocumentParser parser) {
  final root = parser.rootDict;
  final titles = <String>[];
  if (root == null) return titles;
  final outlines = parser.resolve(root.values['/Outlines']);
  if (outlines is! PdfDictToken) return titles;

  void walk(dynamic first, int depth) {
    if (depth > 40) return;
    var current = first;
    final visited = <int>{};
    for (var guard = 0; guard < 100000; guard++) {
      final ref = PdfParserObjects.asRef(current);
      if (ref != null && !visited.add(ref.obj)) break;
      final node = parser.resolve(current);
      if (node is! PdfDictToken) break;
      final title = parser.resolve(node.values['/Title']);
      if (title is PdfStringToken) {
        titles.add(String.fromCharCodes(title.bytes));
      }
      final child = node.values['/First'];
      if (child != null) walk(child, depth + 1);
      final next = node.values['/Next'];
      if (next == null) break;
      current = next;
    }
  }

  final first = outlines.values['/First'];
  if (first != null) walk(first, 0);
  return titles;
}

/// Índice, no documento mesclado, da página para onde o bookmark salta.
int? outlineTargetPage(PdfDocumentParser parser, int outlineIndex) {
  final root = parser.rootDict;
  if (root == null) return null;
  final outlines = parser.resolve(root.values['/Outlines']);
  if (outlines is! PdfDictToken) return null;

  final nodes = <PdfDictToken>[];
  void walk(dynamic first, int depth) {
    if (depth > 40) return;
    var current = first;
    final visited = <int>{};
    for (var guard = 0; guard < 100000; guard++) {
      final ref = PdfParserObjects.asRef(current);
      if (ref != null && !visited.add(ref.obj)) break;
      final node = parser.resolve(current);
      if (node is! PdfDictToken) break;
      nodes.add(node);
      final child = node.values['/First'];
      if (child != null) walk(child, depth + 1);
      final next = node.values['/Next'];
      if (next == null) break;
      current = next;
    }
  }

  final first = outlines.values['/First'];
  if (first != null) walk(first, 0);
  if (outlineIndex < 0 || outlineIndex >= nodes.length) return null;

  final dest = parser.resolve(nodes[outlineIndex].values['/Dest']);
  if (dest is! PdfArrayToken || dest.values.isEmpty) return null;
  final pageRef = PdfParserObjects.asRef(dest.values.first);
  if (pageRef == null) return null;
  return pageIndexOfRef(parser, pageRef.obj);
}

/// Índice da página cujo objeto tem o número [objId].
int? pageIndexOfRef(PdfDocumentParser parser, int objId) {
  final refs = parser.pageRefs;
  for (var i = 0; i < refs.length; i++) {
    if (refs[i].obj == objId) return i;
  }
  return null;
}

/// Índice da página apontada pelo destino de um link.
int? linkTargetPage(PdfDocumentParser parser, PdfDictToken link) {
  dynamic dest = link.values['/Dest'];
  if (dest == null) {
    final action = parser.resolve(link.values['/A']);
    if (action is PdfDictToken) dest = action.values['/D'];
  }
  final resolved = parser.resolve(dest);
  if (resolved is! PdfArrayToken || resolved.values.isEmpty) return null;
  final pageRef = PdfParserObjects.asRef(resolved.values.first);
  if (pageRef == null) return null;
  return pageIndexOfRef(parser, pageRef.obj);
}
