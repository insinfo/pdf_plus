import '../../format/array.dart';
import '../../format/base.dart';
import '../../format/bool.dart';
import '../../format/dict.dart';
import '../../format/indirect.dart';
import '../../format/name.dart';
import '../../format/null_value.dart';
import '../../format/num.dart';
import '../../format/string.dart';
import '../../parsing/pdf_parser_types.dart';

/// Decide o que uma referência indireta lida pelo parser vira no modelo de
/// escrita.
///
/// Devolver `null` significa que o valor deve desaparecer: em dicionários a
/// chave é removida — o que a especificação considera equivalente a `null` —
/// e em arrays o item some ou vira `null`, conforme [PdfArrayGapPolicy].
typedef PdfReferenceResolver = PdfDataType? Function(PdfRefToken ref);

/// Políticas de referência prontas para o [PdfObjectConverter].
abstract final class PdfReferencePolicy {
  /// Mantém o par (número, geração) tal como está no documento de origem.
  ///
  /// É a política usada na leitura de um documento carregado, onde os números
  /// de objeto do arquivo continuam valendo.
  static PdfDataType? preserve(PdfRefToken ref) => PdfIndirect(ref.obj, ref.gen);

  /// Delega a decisão a [remapper], que traduz a referência de origem para a
  /// referência correspondente no documento de destino.
  ///
  /// É a política de quem copia objetos entre documentos — a mesclagem, por
  /// exemplo —, onde os números precisam ser renumerados. O remapeador pode
  /// devolver `null` para descartar uma referência quebrada.
  static PdfReferenceResolver remap(PdfReferenceResolver remapper) => remapper;
}

/// O que fazer com um item de array que a conversão descartou.
enum PdfArrayGapPolicy {
  /// Remove o item. Usado onde a posição não importa (`/Annots`, `/Kids`).
  drop,

  /// Substitui por `null` do PDF, preservando a posição dos demais itens.
  keepNull,
}

/// Converte o modelo tokenizado do parser (`PdfDictToken`, `PdfArrayToken`,
/// `PdfNameToken`, `PdfStringToken`, `PdfRefToken`, números, booleanos e
/// `null`) para o modelo de escrita (`PdfDataType`).
///
/// Este é o núcleo único dessa conversão. Quem precisa de uma regra diferente
/// para referências injeta uma [PdfReferenceResolver] em vez de escrever outro
/// conversor: a leitura de um documento carregado usa
/// [PdfReferencePolicy.preserve] e a importação entre documentos usa
/// [PdfReferencePolicy.remap].
///
/// Valores que o parser não sabe representar viram `null`, e não uma exceção.
class PdfObjectConverter {
  /// Cria um conversor com a política de referência e a política de lacunas
  /// desejadas.
  const PdfObjectConverter({
    this.referencePolicy = PdfReferencePolicy.preserve,
    this.arrayGapPolicy = PdfArrayGapPolicy.drop,
  });

  /// Conversor que preserva os números de objeto da origem.
  static const PdfObjectConverter preserving = PdfObjectConverter();

  /// Como uma referência indireta é traduzida.
  final PdfReferenceResolver referencePolicy;

  /// Como um item descartado de array é tratado.
  final PdfArrayGapPolicy arrayGapPolicy;

  /// Devolve uma cópia deste conversor com outra política de referência.
  PdfObjectConverter withReferencePolicy(PdfReferenceResolver policy) =>
      PdfObjectConverter(
        referencePolicy: policy,
        arrayGapPolicy: arrayGapPolicy,
      );

  /// Converte um valor qualquer do modelo tokenizado.
  ///
  /// `null` do PDF vira [PdfNull]; só um tipo desconhecido devolve `null` do
  /// Dart.
  PdfDataType? convert(dynamic value) {
    if (value == null) return const PdfNull();
    if (value is bool) return PdfBool(value);
    if (value is int) return PdfNum(value);
    if (value is double) return PdfNum(value);
    if (value is PdfNameToken) return PdfName(value.value);
    if (value is PdfStringToken) {
      return PdfString(value.bytes, format: value.format, encrypted: false);
    }
    if (value is PdfRefToken) return referencePolicy(value);
    if (value is PdfArrayToken) return convertArray(value);
    if (value is PdfDictToken) return convertDict(value);
    return null;
  }

  /// Converte um dicionário direto, ignorando as chaves em [ignoreKeys].
  ///
  /// Chaves cujo valor sumiu na conversão não entram no resultado.
  PdfDict<PdfDataType> convertDict(
    PdfDictToken dict, {
    Set<String> ignoreKeys = const <String>{},
  }) {
    final values = <String, PdfDataType>{};
    for (final entry in dict.values.entries) {
      if (ignoreKeys.contains(entry.key)) continue;
      final converted = convert(entry.value);
      if (converted != null) values[entry.key] = converted;
    }
    return PdfDict.values(values);
  }

  /// Converte um array direto.
  ///
  /// [gapPolicy] sobrescreve [arrayGapPolicy] só nesta chamada.
  PdfArray convertArray(
    PdfArrayToken array, {
    PdfArrayGapPolicy? gapPolicy,
  }) {
    final gaps = gapPolicy ?? arrayGapPolicy;
    final values = <PdfDataType>[];
    for (final item in array.values) {
      final converted = convert(item);
      if (converted != null) {
        values.add(converted);
      } else if (gaps == PdfArrayGapPolicy.keepNull) {
        values.add(const PdfNull());
      }
    }
    return PdfArray(values);
  }

  /// Mescla as chaves de [source] em [target], ignorando [ignoreKeys].
  void mergeDictInto(
    PdfDict<PdfDataType> target,
    PdfDictToken source, {
    Set<String> ignoreKeys = const <String>{},
  }) {
    final converted = convertDict(source, ignoreKeys: ignoreKeys);
    for (final entry in converted.values.entries) {
      target[entry.key] = entry.value;
    }
  }
}
