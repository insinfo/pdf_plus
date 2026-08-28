import '../format/dict.dart';
import '../format/name.dart';
import '../format/num.dart';
import '../obj/object.dart';
import '../parsing/parser_objects.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_merge_options.dart';

/// O que fazer com um campo de assinatura encontrado na origem.
enum PdfSignatureAction {
  /// Importar como está — o visualizador vai reportar assinatura inválida.
  keep,

  /// Manter só a marca visual, como carimbo somente-leitura.
  stamp,

  /// Não importar nada.
  drop,
}

/// Política aplicada às assinaturas digitais das origens.
///
/// Mesclar invalida toda assinatura existente: ela cobre os bytes exatos do
/// documento em que foi aplicada, e a mesclagem reescreve o arquivo inteiro.
/// Nenhuma ferramenta de mercado recusa documentos assinados — todas mesclam e
/// a assinatura deixa de conferir. Esta biblioteca faz o mesmo, avisando, e
/// oferece três chaves para escolher o desfecho.
class PdfSignaturePolicy {
  PdfSignaturePolicy(this.context);

  final PdfImportContext context;

  /// Chaves que fazem de uma anotação um campo de formulário. Removê-las
  /// transforma o widget em anotação comum.
  static const signatureFieldKeys = <String>{
    PdfNameTokens.v,
    PdfNameTokens.ft,
    PdfNameTokens.t,
    PdfNameTokens.tu,
    PdfNameTokens.ff,
    PdfNameTokens.dv,
    PdfNameTokens.da,
    PdfNameTokens.q,
    PdfNameTokens.kids,
    PdfNameTokens.lock,
    _additionalActions,
    _seedValue,
  };

  static const _additionalActions = '/AA';
  static const _seedValue = '/SV';

  /// Bits de `/F`: imprimir (4) e somente-leitura (64).
  static const _printFlag = 4;
  static const _readOnlyFlag = 64;

  /// Verifica a origem antes de importar qualquer página.
  void inspectSource() {
    List<dynamic> fields;
    try {
      fields = context.source.extractSignatureFields();
    } catch (_) {
      // Um documento cuja estrutura de assinatura não pode ser lida não deve
      // impedir a mesclagem; o tratamento por widget ainda vale.
      return;
    }

    if (fields.isEmpty) return;
    context.sourceHasSignatures = true;

    if (context.options.rejectSignedSources) {
      throw PdfMergeException(
        'O documento "${context.sourceLabel}" tem ${fields.length} '
        'assinatura(s) digital(is). Mesclar invalidaria todas elas e '
        'rejectSignedSources está ligado.',
      );
    }
  }

  /// Classifica um widget. Devolve `null` quando não é campo de assinatura.
  PdfSignatureAction? classify(PdfDictToken widgetDict) {
    if (!_isSignatureField(widgetDict)) return null;

    if (context.options.keepInvalidSignatures) return PdfSignatureAction.keep;
    if (context.options.removeSignatureAppearance) {
      return PdfSignatureAction.drop;
    }
    return PdfSignatureAction.stamp;
  }

  /// Converte o widget importado em carimbo somente-leitura.
  ///
  /// A página continua parecendo assinada, e nenhum visualizador reclama de
  /// assinatura quebrada, porque não sobrou assinatura para conferir.
  void turnIntoStamp(PdfObject object) {
    final params = object.params;
    if (params is! PdfDict) return;

    params[PdfNameTokens.subtype] = const PdfName(PdfNameTokens.stamp);

    final flags = params[PdfNameTokens.f];
    final current = flags is PdfNum ? flags.value.toInt() : 0;
    params[PdfNameTokens.f] =
        PdfNum(current | _printFlag | _readOnlyFlag);
  }

  bool _isSignatureField(PdfDictToken dict) {
    var current = dict;
    for (var depth = 0; depth < 16; depth++) {
      final type = PdfParserObjects.asName(current.values[PdfNameTokens.ft]);
      if (type == PdfNameTokens.sig) return true;
      if (type != null) return false;

      final value = context.source.resolve(current.values[PdfNameTokens.v]);
      if (value is PdfDictToken &&
          (value.values.containsKey(PdfNameTokens.byteRange) ||
              PdfParserObjects.asName(value.values[PdfNameTokens.type]) ==
                  PdfNameTokens.sig)) {
        return true;
      }

      final parent =
          context.source.resolve(current.values[PdfNameTokens.parent]);
      if (parent is! PdfDictToken) return false;
      current = parent;
    }
    return false;
  }
}
