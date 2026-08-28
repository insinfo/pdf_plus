import '../format/dict.dart';
import '../format/name.dart';
import '../format/num.dart';
import '../obj/object.dart';
import '../parsing/parser_objects.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_merge_options.dart';

/// What to do with a signature field found in the source.
enum PdfSignatureAction {
  /// Import it as is — the viewer will report an invalid signature.
  keep,

  /// Keep only the visual mark, as a read-only stamp.
  stamp,

  /// Import nothing.
  drop,
}

/// Policy applied to the digital signatures of the sources.
///
/// Merging invalidates every existing signature: it covers the exact bytes of
/// the document it was applied to, and merging rewrites the whole file. No
/// tool on the market refuses signed documents — they all merge and the
/// signature stops checking out. This library does the same, with a warning,
/// and offers three switches to choose the outcome.
class PdfSignaturePolicy {
  PdfSignaturePolicy(this.context);

  final PdfImportContext context;

  /// Keys that make an annotation a form field. Removing them turns the
  /// widget into a plain annotation.
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

  /// `/F` bits: print (4) and read-only (64).
  static const _printFlag = 4;
  static const _readOnlyFlag = 64;

  /// Checks the source before importing any page.
  void inspectSource() {
    List<dynamic> fields;
    try {
      fields = context.source.extractSignatureFields();
    } catch (_) {
      // A document whose signature structure cannot be read must not block
      // the merge; the per-widget handling still applies.
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

  /// Classifies a widget. Returns `null` when it is not a signature field.
  PdfSignatureAction? classify(PdfDictToken widgetDict) {
    if (!_isSignatureField(widgetDict)) return null;

    if (context.options.keepInvalidSignatures) return PdfSignatureAction.keep;
    if (context.options.removeSignatureAppearance) {
      return PdfSignatureAction.drop;
    }
    return PdfSignatureAction.stamp;
  }

  /// Turns the imported widget into a read-only stamp.
  ///
  /// The page still looks signed, and no viewer complains about a broken
  /// signature, because there is no signature left to check.
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
