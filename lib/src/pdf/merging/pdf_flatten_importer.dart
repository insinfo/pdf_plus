import 'dart:typed_data';

import 'package:archive/archive.dart';

import '../format/array.dart';
import '../format/name.dart';
import '../obj/formxobject.dart';
import '../obj/page.dart';
import '../page_format.dart';
import '../parsing/parser_objects.dart';
import '../parsing/parser_pages.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_object_importer.dart';

/// Importa cada página de origem como um Form XObject desenhado em uma página
/// nova.
///
/// Mantém só o conteúdo gráfico: anotações, links, campos e marcação ficam de
/// fora — é o contrato do modo. Os recursos (fontes, imagens) continuam sendo
/// importados de verdade, porque um XObject cujos recursos vivem no arquivo de
/// origem não renderiza nada.
class PdfFlattenImporter {
  PdfFlattenImporter(this.context, this.objects);

  final PdfImportContext context;
  final PdfObjectImporter objects;

  PdfPage import(PdfRefToken pageRef, PdfDictToken pageDict) {
    final box = _normalizeBox(context.source.resolvePageMediaBox(pageDict)) ??
        <double>[0, 0, PdfPageFormat.a4.width, PdfPageFormat.a4.height];
    final width = box[2] - box[0];
    final height = box[3] - box[1];

    final rotation = PdfParserPages.pageRotationFromValue(
        context.source.inheritedPageAttribute(pageDict, PdfNameTokens.rotate));

    final page = PdfPage(
      context.destination,
      pageFormat: PdfPageFormat(width, height),
      rotate: rotation,
    );
    context.pageMap[pageRef.obj] = page;

    final content = _pageContent(pageDict);
    if (content == null || content.isEmpty) return page;

    final xObject = PdfFormXObject(context.destination);
    xObject.params[PdfNameTokens.bbox] = PdfArray.fromNum(box);
    xObject.buf.putBytes(content);

    final resources = context.source.resolvePageResources(pageDict);
    if (resources != null) {
      xObject.params[PdfNameTokens.resources] =
          objects.convertDict(resources);
    }

    final group = pageDict.values[PdfNameTokens.group];
    if (group != null) {
      final converted = objects.convert(group);
      if (converted != null) xObject.params[PdfNameTokens.group] = converted;
    }

    // Desloca a origem quando a caixa da origem não começa em (0,0).
    page.getGraphics().drawFormXObject(
      xObject,
      matrix: <double>[1, 0, 0, 1, -box[0], -box[1]],
    );

    return page;
  }

  /// Conteúdo da página, já decodificado e concatenado.
  ///
  /// Concatenar exige um estado de filtro único, então o conteúdo é
  /// decodificado aqui; o `PdfFormXObject` recomprime na serialização.
  Uint8List? _pageContent(PdfDictToken pageDict) {
    final contents = pageDict.values[PdfNameTokens.contents];
    if (contents == null) return null;

    final parts = <Uint8List>[];

    void addStream(dynamic value) {
      final ref = PdfParserObjects.asRef(value);
      if (ref == null) return;
      final object = context.source.getObject(ref.obj);
      final data = object?.streamData;
      if (data == null || object == null) return;
      final dict = object.value;
      if (dict is! PdfDictToken) return;
      final decoded = _decode(data, dict);
      if (decoded != null) parts.add(decoded);
    }

    final resolved = context.source.resolve(contents);
    if (resolved is PdfArrayToken) {
      for (final item in resolved.values) {
        addStream(item);
      }
    } else {
      addStream(contents);
    }

    if (parts.isEmpty) return null;

    final total = parts.fold<int>(0, (sum, part) => sum + part.length + 1);
    final out = Uint8List(total);
    var offset = 0;
    for (final part in parts) {
      out.setRange(offset, offset + part.length, part);
      offset += part.length;
      out[offset++] = 0x0A; // separador entre streams
    }
    return out;
  }

  Uint8List? _decode(Uint8List data, PdfDictToken dict) {
    final filters = _filterNames(dict.values[PdfNameTokens.filter]);
    if (filters.isEmpty) return data;

    var current = data;
    for (final filter in filters) {
      if (filter == PdfNameTokens.flateDecode) {
        try {
          current = Uint8List.fromList(ZLibDecoder().decodeBytes(current));
        } catch (error) {
          context.warn('conteúdo comprimido não pôde ser lido: $error');
          return null;
        }
        continue;
      }
      context.warn(
        'conteúdo com filtro $filter não é suportado no modo flatten e a '
        'página saiu vazia',
      );
      return null;
    }
    return current;
  }

  List<String> _filterNames(dynamic value) {
    final resolved = context.source.resolve(value);
    if (resolved is PdfNameToken) return <String>[resolved.value];
    if (resolved is PdfArrayToken) {
      return resolved.values
          .whereType<PdfNameToken>()
          .map((e) => e.value)
          .toList();
    }
    return const <String>[];
  }

  List<double>? _normalizeBox(List<double>? box) {
    if (box == null || box.length < 4) return null;
    final x0 = box[0] < box[2] ? box[0] : box[2];
    final y0 = box[1] < box[3] ? box[1] : box[3];
    final x1 = box[0] < box[2] ? box[2] : box[0];
    final y1 = box[1] < box[3] ? box[3] : box[1];
    if (x1 - x0 <= 0 || y1 - y0 <= 0) return null;
    return <double>[x0, y0, x1, y1];
  }
}

/// `/Name` é usado só para comparar filtros.
typedef PdfFilterName = PdfName;
