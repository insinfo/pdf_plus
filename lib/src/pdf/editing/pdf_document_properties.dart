import 'dart:convert';
import 'dart:typed_data';

import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/bool.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../format/name.dart';
import '../format/num.dart';
import '../format/string.dart';
import '../obj/page.dart';
import '../parsing/pdf_document_parser.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'object_graph/pdf_object_converter.dart';
import 'object_graph/pdf_object_store.dart';

/// How the viewer should open the document.
enum PdfPageLayout {
  singlePage('/SinglePage'),
  oneColumn('/OneColumn'),
  twoColumnLeft('/TwoColumnLeft'),
  twoColumnRight('/TwoColumnRight'),
  twoPageLeft('/TwoPageLeft'),
  twoPageRight('/TwoPageRight');

  const PdfPageLayout(this.name);

  /// Matching PDF name.
  final String name;

  static PdfPageLayout? fromName(String? name) {
    if (name == null) return null;
    for (final value in values) {
      if (value.name == name) return value;
    }
    return null;
  }
}

/// View used by an open destination.
enum PdfOpenActionView {
  /// Whole page.
  fit('/Fit'),

  /// Page width.
  fitWidth('/FitH'),

  /// Explicit position and zoom.
  xyz('/XYZ');

  const PdfOpenActionView(this.name);

  final String name;
}

/// Reading and writing of the document-level properties: metadata, navigation
/// and viewer preferences.
///
/// Works both on a new document and on a loaded one. On a loaded one, what
/// still lives in the original bytes is read through the parser; what is
/// changed enters the incremental update, without touching the rest of the
/// file.
///
/// Does not touch `/Names /Dests`: the named destination tree belongs to the
/// `PdfNames` model, which rewrites it on save.
class PdfDocumentProperties {
  PdfDocumentProperties(this.document)
      : _store = PdfObjectStore.forDocument(document);

  final PdfDocument document;
  final PdfObjectStore _store;

  PdfDict get _catalog => document.catalog.params;

  // ---------------------------------------------------------------------------
  // /Info
  // ---------------------------------------------------------------------------

  /// Metadata from the document `/Info`, when there is any.
  ///
  /// On a loaded document the read comes from the original file; on a new
  /// document, from what was set by [setInfo].
  Map<String, String> readInfo() {
    final parser = document.prev;
    if (parser is! PdfDocumentParser) return const <String, String>{};
    final infoObj = parser.trailer.infoObj;
    if (infoObj == null) return const <String, String>{};

    final object = parser.getObject(infoObj);
    final dict = object?.value;
    if (dict is! PdfDictToken) return const <String, String>{};

    final out = <String, String>{};
    dict.values.forEach((key, value) {
      final resolved = parser.resolve(value);
      if (resolved is PdfStringToken) {
        out[key] = _decodeText(resolved.bytes);
      } else if (resolved is PdfNameToken) {
        out[key] = resolved.value;
      }
    });
    return out;
  }

  /// Writes the `/Info`, preserving whatever is not given.
  void setInfo({
    String? title,
    String? author,
    String? creator,
    String? subject,
    String? keywords,
    String? producer,
  }) {
    final current = readInfo();
    document.updateInfo(
      title: title ?? current[PdfNameTokens.title],
      author: author ?? current[PdfNameTokens.author],
      creator: creator ?? current[PdfNameTokens.creator],
      subject: subject ?? current[PdfNameTokens.subject],
      keywords: keywords ?? current[PdfNameTokens.keywords],
      producer: producer ?? current[PdfNameTokens.producer],
    );
  }

  // ---------------------------------------------------------------------------
  // XMP
  // ---------------------------------------------------------------------------

  /// Document XMP (`/Metadata`), as text, when there is any.
  String? readXmp() {
    final value = _catalog[PdfNameTokens.metadata];
    if (value == null) return null;

    final parser = document.prev;
    if (parser is PdfDocumentParser && value is PdfIndirectLike) {
      final data = _streamOf(parser, value);
      if (data != null) return utf8.decode(data, allowMalformed: true);
    }
    return null;
  }

  Uint8List? _streamOf(PdfDocumentParser parser, PdfDataType value) {
    final id = _objectNumberOf(value);
    if (id == null) return null;
    return parser.getObject(id)?.streamData;
  }

  // ---------------------------------------------------------------------------
  // Navigation
  // ---------------------------------------------------------------------------

  /// Open mode (`/PageMode`).
  ///
  /// The value lives in the catalog model, which rewrites the key on every
  /// save.
  PdfPageMode? get pageMode {
    final fromModel = document.catalog.pageMode;
    if (fromModel != null) return fromModel;

    final value = _catalog[PdfNameTokens.pagemode];
    if (value is! PdfName) return null;
    for (final entry in _pageModeNames.entries) {
      if (entry.value == value.value) return entry.key;
    }
    return null;
  }

  set pageMode(PdfPageMode? mode) {
    document.catalog.pageMode = mode;
    if (mode == null) {
      _catalog.values.remove(PdfNameTokens.pagemode);
      return;
    }
    _catalog[PdfNameTokens.pagemode] = PdfName(_pageModeNames[mode]!);
  }

  static const _pageModeNames = <PdfPageMode, String>{
    PdfPageMode.none: '/UseNone',
    PdfPageMode.outlines: '/UseOutlines',
    PdfPageMode.thumbs: '/UseThumbs',
    PdfPageMode.fullscreen: '/FullScreen',
  };

  /// Page arrangement (`/PageLayout`).
  PdfPageLayout? get pageLayout {
    final value = _catalog[PdfNameTokens.pageLayout];
    return value is PdfName ? PdfPageLayout.fromName(value.value) : null;
  }

  set pageLayout(PdfPageLayout? layout) {
    if (layout == null) {
      _catalog.values.remove(PdfNameTokens.pageLayout);
      return;
    }
    _catalog[PdfNameTokens.pageLayout] = PdfName(layout.name);
  }

  /// Declared document language (`/Lang`).
  String? get language {
    final value = _catalog[PdfNameTokens.lang];
    return value is PdfString ? _decodeText(value.value) : null;
  }

  set language(String? value) {
    if (value == null) {
      _catalog.values.remove(PdfNameTokens.lang);
      return;
    }
    _catalog[PdfNameTokens.lang] = PdfString.fromString(value);
  }

  /// Makes the document open at [page], with the chosen view.
  void openAt(
    PdfPage page, {
    PdfOpenActionView view = PdfOpenActionView.fit,
    double? left,
    double? top,
    double? zoom,
  }) {
    final destination = PdfArray(<PdfDataType>[
      page.ref(),
      PdfName(view.name),
      if (view == PdfOpenActionView.xyz) ...<PdfDataType>[
        PdfNum(left ?? 0),
        PdfNum(top ?? 0),
        PdfNum(zoom ?? 0),
      ],
      if (view == PdfOpenActionView.fitWidth) PdfNum(top ?? 0),
    ]);
    _catalog[PdfNameTokens.openAction] = destination;
  }

  /// Removes the open action.
  void clearOpenAction() {
    _catalog.values.remove(PdfNameTokens.openAction);
  }

  /// Index of the page the document opens at, when the destination is
  /// explicit.
  int? get openAtPageIndex {
    final value = _resolveDict(_catalog[PdfNameTokens.openAction]);
    PdfDataType? destination = _catalog[PdfNameTokens.openAction];
    if (value != null) {
      // `/OpenAction` can also be a `/GoTo` action.
      destination = value[PdfNameTokens.d];
    }
    if (destination is! PdfArray || destination.values.isEmpty) return null;

    final target = destination.values.first;
    final id = _objectNumberOf(target);
    if (id == null) return null;

    final pages = document.pdfPageList.pages;
    for (var i = 0; i < pages.length; i++) {
      if (pages[i].objser == id) return i;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Viewer preferences
  // ---------------------------------------------------------------------------

  /// Boolean `/ViewerPreferences`, by key name.
  ///
  /// Examples: `/HideToolbar`, `/HideMenubar`, `/FitWindow`, `/CenterWindow`,
  /// `/DisplayDocTitle`.
  bool? viewerPreference(String key) {
    final preferences = _resolveDict(_catalog[PdfNameTokens.viewerPreferences]);
    final value = preferences?[key];
    return value is PdfBool ? value.value : null;
  }

  /// Sets a boolean viewer preference.
  void setViewerPreference(String key, bool? value) {
    final existing = _catalog[PdfNameTokens.viewerPreferences];
    final preferences = existing is PdfDict
        ? existing
        : (_materializeDict(existing) ?? PdfDict());
    if (!identical(existing, preferences)) {
      _catalog[PdfNameTokens.viewerPreferences] = preferences;
    }

    if (value == null) {
      preferences.values.remove(key);
    } else {
      preferences[key] = PdfBool(value);
    }
  }

  // ---------------------------------------------------------------------------

  /// Resolves a dictionary that may be direct, materialized or still in the
  /// bytes of the original file.
  PdfDict? _resolveDict(PdfDataType? value) {
    if (value is PdfDict) return value;
    if (value == null) return null;
    final resolved = _store.resolveDict(value);
    if (resolved != null) return resolved;
    return _materializeDict(value);
  }

  /// Reads through the parser a dictionary that only exists in the original
  /// file and returns a direct copy, so that it can be changed.
  PdfDict? _materializeDict(PdfDataType? value) {
    final id = _objectNumberOf(value);
    if (id == null) return null;
    final parser = document.prev;
    if (parser is! PdfDocumentParser) return null;
    final object = parser.getObject(id);
    final dict = object?.value;
    if (dict is! PdfDictToken) return null;
    return PdfObjectConverter.preserving.convertDict(dict);
  }

  int? _objectNumberOf(PdfDataType? value) {
    if (value is PdfIndirectLike) return value.ser;
    return null;
  }

  String _decodeText(List<int> bytes) {
    // UTF-16BE with a BOM is the PDF text format; the rest is latin-1.
    if (bytes.length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) {
      final units = <int>[];
      for (var i = 2; i + 1 < bytes.length; i += 2) {
        units.add((bytes[i] << 8) | bytes[i + 1]);
      }
      return String.fromCharCodes(units);
    }
    return latin1.decode(bytes, allowInvalid: true);
  }
}

/// `PdfIndirect` exposed through a local alias, so that the type check does
/// not depend on importing the format directly at every use site.
typedef PdfIndirectLike = PdfIndirect;
