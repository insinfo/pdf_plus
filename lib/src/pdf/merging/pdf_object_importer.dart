import 'dart:convert';
import 'dart:typed_data';

import '../crypto/pdf_crypto.dart';
import '../editing/object_graph/pdf_object_converter.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/dict_stream.dart';
import '../format/indirect.dart';
import '../format/null_value.dart';
import '../obj/object.dart';
import '../parsing/parser_objects.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';

/// Materializa objetos lidos de um documento de origem como objetos indiretos
/// do documento de destino, renumerando todas as referências.
///
/// O documento carregado por esta biblioteca não materializa seu grafo — ele
/// vive nos bytes do arquivo original (ver `PdfDocument.load`). Mesclar exige o
/// contrário: cada objeto alcançável precisa existir no destino com número
/// novo. É o que esta classe faz.
///
/// Duas garantias sustentam o algoritmo:
///
/// 1. **O objeto de destino é alocado antes de o conteúdo ser convertido.**
///    Assim, um ciclo (`A → B → A`) reencontra o objeto no memo em vez de
///    recursar para sempre.
/// 2. **Referências a páginas não são seguidas.** Importar `/Parent`, ou o
///    destino de um link, arrastaria a árvore de páginas inteira da origem.
///    Elas são resolvidas pelo mapa de páginas já importadas.
class PdfObjectImporter {
  PdfObjectImporter(this.context);

  final PdfImportContext context;

  /// Chaves nunca copiadas de um objeto importado.
  static const _alwaysDropped = <String>{
    PdfNameTokens.length, // recalculado na serialização
  };

  /// Importa o objeto indireto [ref] e devolve a referência dele no destino.
  ///
  /// Devolve `null` quando o objeto não existe na origem ou quando é uma
  /// página que não foi importada.
  PdfIndirect? importRef(PdfRefToken ref) {
    final existing = context.imported[ref.obj];
    if (existing != null) return existing.ref();

    // Páginas nunca são seguidas: são resolvidas pelo mapa de páginas.
    if (context.isSourcePage(ref.obj)) {
      return context.pageMap[ref.obj]?.ref();
    }

    final parsed = context.source.getObject(ref.obj);
    if (parsed == null) {
      context.warn('objeto ${ref.obj} ${ref.gen} R não pôde ser lido');
      return null;
    }

    if (parsed.value is PdfDictToken) {
      final type = PdfParserObjects.asName(
          (parsed.value as PdfDictToken).values[PdfNameTokens.type]);
      if (type == PdfNameTokens.page || type == PdfNameTokens.pages) {
        // Página que a varredura da árvore não alcançou.
        return context.pageMap[ref.obj]?.ref();
      }
      if (type == PdfNameTokens.xRef || type == PdfNameTokens.objStm) {
        // Objetos estruturais do arquivo de origem não têm sentido no destino.
        return null;
      }
    }

    return _materialize(ref.obj, parsed).ref();
  }

  /// Cria o objeto no destino e preenche seu conteúdo.
  PdfObject _materialize(int srcObjId, ParsedIndirectObject parsed) {
    final rawStream = parsed.streamData;

    if (rawStream != null && parsed.value is PdfDictToken) {
      final srcDict = parsed.value as PdfDictToken;
      final reusable = _reusableStream(srcDict, rawStream);
      if (reusable != null) {
        context.imported[srcObjId] = reusable;
        return reusable;
      }

      final object = PdfObject<PdfDictStream>(
        context.destination,
        params: PdfDictStream(
          values: <String, PdfDataType>{},
          data: rawStream,
          // Streams com /Filter próprio são copiados verbatim; os sem filtro
          // podem ser comprimidos pelo destino.
          compress: !srcDict.values.containsKey(PdfNameTokens.filter),
        ),
      );
      context.imported[srcObjId] = object;
      _fillDict(object.params, srcDict);
      _rememberStream(srcDict, rawStream, object);
      return object;
    }

    final value = parsed.value;

    if (value is PdfDictToken) {
      final object = PdfObject<PdfDict>(
        context.destination,
        params: PdfDict(),
      );
      context.imported[srcObjId] = object;
      _fillDict(object.params, value);
      return object;
    }

    if (value is PdfArrayToken) {
      // Arrays indiretos aparecem em `/Annots`, `/Kids` e destinos.
      final object = PdfObject<PdfArray>(
        context.destination,
        params: PdfArray(),
      );
      context.imported[srcObjId] = object;
      for (final item in value.values) {
        object.params.add(convert(item) ?? const PdfNull());
      }
      return object;
    }

    // Escalares não podem conter referências, então não há ciclo a fechar.
    final object = PdfObject<PdfDataType>(
      context.destination,
      params: convert(value) ?? const PdfNull(),
    );
    context.imported[srcObjId] = object;
    return object;
  }

  void _fillDict(PdfDict target, PdfDictToken source,
      {Set<String> ignoreKeys = const <String>{}}) {
    source.values.forEach((key, value) {
      if (_alwaysDropped.contains(key) || ignoreKeys.contains(key)) return;
      final converted = convert(value);
      if (converted != null) {
        target[key] = converted;
      }
    });
  }

  /// Conversor compartilhado, com a política de referência desta sessão: toda
  /// referência indireta passa por [importRef].
  ///
  /// A conversão em si é a mesma que o parser usa para ler um documento — o que
  /// muda entre os dois casos é apenas o destino das referências.
  late final PdfObjectConverter _converter = PdfObjectConverter(
    referencePolicy: importRef,
    // Um item que sumiu vira `null` do PDF para não deslocar os demais: em um
    // destino `[pageRef /XYZ x y z]`, a posição de cada valor tem significado.
    arrayGapPolicy: PdfArrayGapPolicy.keepNull,
  );

  /// Converte um valor lido pelo parser para o modelo de escrita, remapeando
  /// referências indiretas.
  ///
  /// Devolve `null` quando o valor deve desaparecer (referência quebrada ou
  /// página não importada); em dicionários isso significa remover a chave, o
  /// que é equivalente a `null` pela especificação.
  PdfDataType? convert(dynamic value) => _converter.convert(value);

  /// Converte um dicionário direto (não indireto).
  PdfDict convertDict(PdfDictToken dict,
          {Set<String> ignoreKeys = const <String>{}}) =>
      _converter.convertDict(dict, ignoreKeys: ignoreKeys);

  /// Converte um array direto. Valores que desaparecem viram `null` do PDF
  /// para não deslocar as posições dos demais.
  PdfArray convertArray(PdfArrayToken array) =>
      _converter.convertArray(array);

  /// Converte um array descartando os itens que sumiram, em vez de substituí-los
  /// por `null` — usado onde a posição não importa (`/Annots`, `/Kids`).
  PdfArray convertArrayCompact(PdfArrayToken array) =>
      _converter.convertArray(array, gapPolicy: PdfArrayGapPolicy.drop);

  // --------------------------------------------------------------------------
  // Deduplicação de streams
  // --------------------------------------------------------------------------

  String? _streamDigest(PdfDictToken dict, Uint8List data) {
    if (!context.options.deduplicateResources) return null;
    // Só vale a pena para conteúdo grande o suficiente para pagar o hash.
    if (data.length < 512) return null;
    // Um dicionário com referências indiretas só seria igual a outro se os
    // objetos apontados também fossem — o que esta checagem barata não sabe.
    if (_hasIndirectValue(dict)) return null;

    final signature = StringBuffer();
    final keys = dict.values.keys.toList()..sort();
    for (final key in keys) {
      if (key == PdfNameTokens.length) continue;
      signature
        ..write(key)
        ..write('=')
        ..write(_signatureOf(dict.values[key]))
        ..write(';');
    }
    final hash = PdfCrypto.sha256(data);
    return '${data.length}:${base64.encode(hash)}:$signature';
  }

  PdfObject? _reusableStream(PdfDictToken dict, Uint8List data) {
    final digest = _streamDigest(dict, data);
    if (digest == null) return null;
    return context.streamsByDigest[digest];
  }

  void _rememberStream(PdfDictToken dict, Uint8List data, PdfObject object) {
    final digest = _streamDigest(dict, data);
    if (digest == null) return;
    context.streamsByDigest[digest] = object;
  }

  bool _hasIndirectValue(dynamic value, {int depth = 0}) {
    if (depth > 8) return true;
    if (value is PdfRefToken) return true;
    if (value is PdfArrayToken) {
      for (final item in value.values) {
        if (_hasIndirectValue(item, depth: depth + 1)) return true;
      }
      return false;
    }
    if (value is PdfDictToken) {
      for (final item in value.values.values) {
        if (_hasIndirectValue(item, depth: depth + 1)) return true;
      }
      return false;
    }
    return false;
  }

  String _signatureOf(dynamic value) {
    if (value is PdfNameToken) return '/${value.value}';
    if (value is PdfStringToken) return '(${base64.encode(value.bytes)})';
    if (value is PdfArrayToken) {
      return '[${value.values.map(_signatureOf).join(' ')}]';
    }
    if (value is PdfDictToken) {
      final keys = value.values.keys.toList()..sort();
      return '<<${keys.map((k) => '$k ${_signatureOf(value.values[k])}').join(' ')}>>';
    }
    return '$value';
  }
}
