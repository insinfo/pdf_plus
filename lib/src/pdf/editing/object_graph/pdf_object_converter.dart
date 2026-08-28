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

/// Decides what an indirect reference read by the parser becomes in the
/// writing model.
///
/// Returning `null` means the value must disappear: in dictionaries the key
/// is removed — which the specification treats as equivalent to `null` — and
/// in arrays the item vanishes or becomes `null`, per [PdfArrayGapPolicy].
typedef PdfReferenceResolver = PdfDataType? Function(PdfRefToken ref);

/// Ready-made reference policies for the [PdfObjectConverter].
abstract final class PdfReferencePolicy {
  /// Keeps the (number, generation) pair as it is in the source document.
  ///
  /// This is the policy used when reading a loaded document, where the object
  /// numbers from the file still hold.
  static PdfDataType? preserve(PdfRefToken ref) => PdfIndirect(ref.obj, ref.gen);

  /// Delegates the decision to [remapper], which translates the source
  /// reference into the matching reference in the target document.
  ///
  /// This is the policy for whoever copies objects between documents —
  /// merging, for instance — where the numbers have to be renumbered. The
  /// remapper can return `null` to drop a broken reference.
  static PdfReferenceResolver remap(PdfReferenceResolver remapper) => remapper;
}

/// What to do with an array item that the conversion dropped.
enum PdfArrayGapPolicy {
  /// Drops the item. Used where position does not matter (`/Annots`, `/Kids`).
  drop,

  /// Replaces it with the PDF `null`, keeping the position of other items.
  keepNull,
}

/// Converts the parser's tokenized model (`PdfDictToken`, `PdfArrayToken`,
/// `PdfNameToken`, `PdfStringToken`, `PdfRefToken`, numbers, booleans and
/// `null`) into the writing model (`PdfDataType`).
///
/// This is the single core of that conversion. Whoever needs a different rule
/// for references injects a [PdfReferenceResolver] instead of writing another
/// converter: reading a loaded document uses [PdfReferencePolicy.preserve]
/// and importing between documents uses [PdfReferencePolicy.remap].
///
/// Values the parser cannot represent become `null`, not an exception.
class PdfObjectConverter {
  /// Creates a converter with the wanted reference and array-gap policies.
  const PdfObjectConverter({
    this.referencePolicy = PdfReferencePolicy.preserve,
    this.arrayGapPolicy = PdfArrayGapPolicy.drop,
  });

  /// Converter that preserves the source object numbers.
  static const PdfObjectConverter preserving = PdfObjectConverter();

  /// How an indirect reference is translated.
  final PdfReferenceResolver referencePolicy;

  /// How a dropped array item is handled.
  final PdfArrayGapPolicy arrayGapPolicy;

  /// Returns a copy of this converter with another reference policy.
  PdfObjectConverter withReferencePolicy(PdfReferenceResolver policy) =>
      PdfObjectConverter(
        referencePolicy: policy,
        arrayGapPolicy: arrayGapPolicy,
      );

  /// Converts any value from the tokenized model.
  ///
  /// The PDF `null` becomes [PdfNull]; only an unknown type returns the Dart
  /// `null`.
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

  /// Converts a direct dictionary, ignoring the keys in [ignoreKeys].
  ///
  /// Keys whose value vanished in the conversion do not enter the result.
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

  /// Converts a direct array.
  ///
  /// [gapPolicy] overrides [arrayGapPolicy] for this call only.
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

  /// Merges the keys of [source] into [target], ignoring [ignoreKeys].
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
