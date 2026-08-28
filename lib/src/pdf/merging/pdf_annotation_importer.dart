import 'dart:convert';
import 'dart:typed_data';

import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/null_value.dart';
import '../obj/object.dart';
import '../obj/page.dart';
import '../parsing/parser_objects.dart';
import '../parsing/parser_tokens.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_object_importer.dart';
import 'pdf_signature_policy.dart';

/// Importa as anotações de uma página: links, notas, carimbos e widgets de
/// formulário.
///
/// Roda na segunda passagem, quando todas as páginas do intervalo já existem no
/// destino — é o que permite religar `/P` e reapontar destinos sem precisar de
/// um mecanismo de pendências.
class PdfAnnotationImporter {
  PdfAnnotationImporter(this.context, this.objects)
      : _signatures = PdfSignaturePolicy(context);

  final PdfImportContext context;
  final PdfObjectImporter objects;
  final PdfSignaturePolicy _signatures;

  /// Chaves da anotação que a importação sempre trata à parte.
  static const _handledKeys = <String>{
    PdfNameTokens.p, // reaponta para a página do destino
    PdfNameTokens.parent, // hierarquia de campo, resolvida pelo formulário
    PdfNameTokens.dest, // destino resolvido a partir da origem
    PdfNameTokens.action, // idem, dentro da ação
  };

  void importPageAnnotations(PdfPage page, PdfDictToken pageDict) {
    final annots = _resolveArray(pageDict.values[PdfNameTokens.annots]);
    if (annots == null) return;

    final imported = PdfArray();

    for (final item in annots.values) {
      final ref = PdfParserObjects.asRef(item);
      final dict = _resolveDict(item);
      if (dict == null) continue;

      final subtype =
          PdfParserObjects.asName(dict.values[PdfNameTokens.subtype]);
      final isWidget = subtype == PdfNameTokens.widget;

      if (isWidget && !context.options.importFormFields) continue;
      if (!isWidget && !context.options.importAnnotations) continue;

      final object = _importAnnotation(page, ref, dict, isWidget: isWidget);
      if (object == null) continue;
      imported.add(object.ref());
    }

    if (imported.values.isEmpty) return;

    final existing = page.params[PdfNameTokens.annots];
    if (existing is PdfArray) {
      existing.values.addAll(imported.values);
    } else {
      page.params[PdfNameTokens.annots] = imported;
    }
  }

  PdfObject? _importAnnotation(
    PdfPage page,
    PdfRefToken? ref,
    PdfDictToken dict, {
    required bool isWidget,
  }) {
    final signature = isWidget ? _signatures.classify(dict) : null;
    if (signature == PdfSignatureAction.drop) return null;

    if (ref != null) {
      final cached = context.imported[ref.obj];
      if (cached != null) return cached;
    }

    final skipped = <String>{
      ..._handledKeys,
      if (signature == PdfSignatureAction.stamp)
        ...PdfSignaturePolicy.signatureFieldKeys,
    };

    final object = PdfObject<PdfDict>(context.destination, params: PdfDict());
    if (ref != null) {
      context.imported[ref.obj] = object;
    }

    dict.values.forEach((key, value) {
      if (skipped.contains(key)) return;
      final converted = objects.convert(value);
      if (converted != null) object.params[key] = converted;
    });

    // `/P` sempre aponta para a página que de fato contém a anotação.
    object.params[PdfNameTokens.p] = page.ref();

    if (signature == PdfSignatureAction.stamp) {
      _signatures.turnIntoStamp(object);
      context.warn(
        'assinatura digital invalidada pela mesclagem: o campo foi removido e '
        'a marca visual mantida como carimbo somente-leitura',
      );
    } else if (signature == PdfSignatureAction.keep) {
      context.warn(
        'assinatura digital mantida, porém inválida: a mesclagem reescreve os '
        'bytes que ela cobria',
      );
    }

    _remapDestinations(object, dict);

    if (isWidget && signature != PdfSignatureAction.stamp) {
      context.widgets.add(PdfImportedWidget(
        sourceRef: ref,
        sourceDict: dict,
        destination: object,
        page: page,
      ));
    }

    return object;
  }

  // ---------------------------------------------------------------------------
  // Destinos
  // ---------------------------------------------------------------------------

  /// Reaponta `/Dest` e `/A << /S /GoTo /D … >>` para as páginas do destino.
  ///
  /// O destino é sempre reconstruído a partir do dicionário de origem, nunca do
  /// que a conversão genérica produziu: `/Dest` costuma ser uma referência
  /// indireta para o array, e é o array que precisa ser reescrito.
  void _remapDestinations(PdfObject annotation, PdfDictToken sourceDict) {
    final params = annotation.params;
    if (params is! PdfDict) return;

    final sourceDest = sourceDict.values[PdfNameTokens.dest];
    if (sourceDest != null) {
      final fixed = _destinationFrom(sourceDest, owner: 'link');
      if (fixed != null) params[PdfNameTokens.dest] = fixed;
    }

    final sourceAction =
        context.source.resolve(sourceDict.values[PdfNameTokens.action]);
    if (sourceAction is PdfDictToken) {
      final built = _buildAction(sourceAction, 0);
      if (built != null) params[PdfNameTokens.action] = built;
    }
  }

  /// Recria uma ação, reapontando o destino quando ela é interna ao documento.
  PdfDict? _buildAction(PdfDictToken source, int depth) {
    if (depth > 16) return null;

    final action = PdfDict();
    final type = PdfParserObjects.asName(source.values[PdfNameTokens.s]);

    source.values.forEach((key, value) {
      if (key == PdfNameTokens.d && type == PdfNameTokens.goto) return;
      if (key == PdfNameTokens.next) return;
      final converted = objects.convert(value);
      if (converted != null) action[key] = converted;
    });

    // `/URI`, `/Launch` e `/GoToR` apontam para fora e são copiadas inteiras.
    if (type == PdfNameTokens.goto) {
      final sourceDest = source.values[PdfNameTokens.d];
      if (sourceDest != null) {
        final fixed = _destinationFrom(sourceDest, owner: 'ação GoTo');
        if (fixed != null) action[PdfNameTokens.d] = fixed;
      }
    }

    final next = context.source.resolve(source.values[PdfNameTokens.next]);
    if (next is PdfDictToken) {
      final built = _buildAction(next, depth + 1);
      if (built != null) action[PdfNameTokens.next] = built;
    } else if (next is PdfArrayToken) {
      final list = PdfArray();
      for (final item in next.values) {
        final node = context.source.resolve(item);
        if (node is! PdfDictToken) continue;
        final built = _buildAction(node, depth + 1);
        if (built != null) list.add(built);
      }
      if (list.values.isNotEmpty) action[PdfNameTokens.next] = list;
    }

    return action;
  }

  /// Devolve o destino explícito equivalente, lendo o valor da origem.
  ///
  /// `null` quando ele não pode ser resolvido dentro do que foi importado — o
  /// chamador remove a chave e a anotação continua na página, sem o salto.
  PdfDataType? _destinationFrom(dynamic sourceValue,
      {required String owner}) {
    final resolved = context.source.resolve(sourceValue);

    if (resolved is PdfArrayToken) {
      if (resolved.values.isEmpty) return null;
      final converted = objects.convertArray(resolved);
      if (converted.values.isEmpty || converted.values.first is PdfNull) {
        context.warn(
          '$owner sem destino: a página apontada está fora do intervalo '
          'importado',
        );
        return null;
      }
      return converted;
    }

    String? name;
    if (resolved is PdfNameToken) {
      name = resolved.value.startsWith('/')
          ? resolved.value.substring(1)
          : resolved.value;
    } else if (resolved is PdfStringToken) {
      name = _decodeName(resolved.bytes);
    }

    if (name == null) {
      context.warn('$owner sem destino: formato não reconhecido');
      return null;
    }

    final target = _resolveNamed(name);
    if (target == null) {
      context.warn(
        '$owner sem destino: o destino nomeado "$name" não foi encontrado',
      );
    }
    return target;
  }

  /// Resolve um destino nomeado da origem e o reemite como destino explícito.
  PdfDataType? _resolveNamed(String name) {
    if (!context.options.importNamedDestinations) return null;
    try {
      final token = _lookupNamedDestination(name);
      if (token == null) return null;

      dynamic target = token;
      if (target is PdfDictToken) {
        target = target.values[PdfNameTokens.d];
      }
      target = context.source.resolve(target);
      if (target is! PdfArrayToken) return null;

      final converted = objects.convertArray(target);
      if (converted.values.isEmpty) return null;
      if (converted.values.first is PdfNull) return null;
      return converted;
    } catch (error) {
      // Árvore de nomes malformada não pode derrubar a mesclagem inteira.
      context.warn('destino nomeado "$name" não pôde ser lido: $error');
      return null;
    }
  }

  dynamic _lookupNamedDestination(String name) {
    final root = context.source.rootDict;
    if (root == null) return null;

    // PDF 1.2+: /Root /Names /Dests, uma árvore de nomes.
    final names = context.source.resolve(root.values[PdfNameTokens.names]);
    if (names is PdfDictToken) {
      final tree = context.source.resolve(names.values[PdfNameTokens.dests]);
      if (tree is PdfDictToken) {
        final found = _searchNameTree(tree, name, 0);
        if (found != null) return found;
      }
    }

    // PDF 1.1: /Root /Dests, um dicionário simples.
    final legacy = context.source.resolve(root.values[PdfNameTokens.dests]);
    if (legacy is PdfDictToken) {
      final direct = legacy.values['/$name'] ?? legacy.values[name];
      if (direct != null) return context.source.resolve(direct);
    }

    return null;
  }

  dynamic _searchNameTree(PdfDictToken node, String name, int depth) {
    if (depth > 32) return null;

    final names = context.source.resolve(node.values[PdfNameTokens.names]);
    if (names is PdfArrayToken) {
      // Pares [nome, destino]; um array com número ímpar de itens é inválido,
      // mas existe no mundo real.
      for (var i = 0; i + 1 < names.values.length; i += 2) {
        final key = names.values[i];
        final keyName = key is PdfStringToken
            ? _decodeName(key.bytes)
            : (key is PdfNameToken ? key.value : null);
        if (keyName == name) {
          return context.source.resolve(names.values[i + 1]);
        }
      }
    }

    final kids = context.source.resolve(node.values[PdfNameTokens.kids]);
    if (kids is PdfArrayToken) {
      for (final kid in kids.values) {
        final kidNode = context.source.resolve(kid);
        if (kidNode is! PdfDictToken) continue;
        if (!_withinLimits(kidNode, name)) continue;
        final found = _searchNameTree(kidNode, name, depth + 1);
        if (found != null) return found;
      }
    }

    return null;
  }

  /// Usa `/Limits` para não descer em ramos que não podem conter o nome.
  bool _withinLimits(PdfDictToken node, String name) {
    final limits = context.source.resolve(node.values[PdfNameTokens.limits]);
    if (limits is! PdfArrayToken || limits.values.length < 2) return true;
    final low = limits.values[0];
    final high = limits.values[1];
    if (low is! PdfStringToken || high is! PdfStringToken) return true;
    final lowName = _decodeName(low.bytes);
    final highName = _decodeName(high.bytes);
    return name.compareTo(lowName) >= 0 && name.compareTo(highName) <= 0;
  }

  String _decodeName(List<int> bytes) {
    try {
      return PdfParserTokens.decodePdfString(Uint8List.fromList(bytes));
    } catch (_) {
      try {
        return utf8.decode(bytes, allowMalformed: true);
      } catch (_) {
        return String.fromCharCodes(bytes);
      }
    }
  }

  // ---------------------------------------------------------------------------

  PdfDictToken? _resolveDict(dynamic value) {
    final resolved = context.source.resolve(value);
    return resolved is PdfDictToken ? resolved : null;
  }

  PdfArrayToken? _resolveArray(dynamic value) {
    final resolved = context.source.resolve(value);
    return resolved is PdfArrayToken ? resolved : null;
  }
}

