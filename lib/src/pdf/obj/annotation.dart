/*
 * Copyright (C) 2017, David PHAM-VAN <dev.nfet.net@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'package:meta/meta.dart';
import 'package:pdf_plus/src/utils/vector_math/vector_math_64.dart';

import '../color.dart';
import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/name.dart';
import '../format/null_value.dart';
import '../format/num.dart';
import '../format/stream.dart';
import '../format/string.dart';
import '../graphics.dart';
import '../point.dart';
import '../rect.dart';
import 'border.dart';
import 'font.dart';
import 'graphic_stream.dart';
import 'object.dart';
import 'page.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

/// Choice field widget (combo/list).
class PdfChoiceField extends PdfAnnotWidget {
  /// Creates a choice field widget.
  PdfChoiceField({
    required PdfRect rect,
    required this.textColor,
    required this.font,
    required this.fontSize,
    required this.items,
    String? fieldName,
    this.value,
    this.defaultValue,
  }) : super(
          rect: rect,
          fieldType: PdfNameTokens.ch,
          fieldName: fieldName,
        );

  /// Option items.
  final List<String> items;
  /// Text color for the appearance.
  final PdfColor textColor;
  /// Current value.
  final String? value;
  /// Default value.
  final String? defaultValue;
  final Set<PdfFieldFlags>? fieldFlags = {
    PdfFieldFlags.combo,
  };
  /// Font used to draw the value.
  final PdfFont font;

  /// Font size used to draw the value.
  final double fontSize;
  @override
  /// Writes the widget appearance and field parameters.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);
    // What is /F?
    //params[PdfNameTokens.f] = const PdfNum(4);
    params[PdfNameTokens.ff] = PdfNum(fieldFlagsValue);
    params[PdfNameTokens.opt] =
        PdfArray<PdfString>(items.map((e) => PdfString.fromString(e)).toList());

    if (defaultValue != null) {
      params[PdfNameTokens.dv] = PdfString.fromString(defaultValue!);
    }

    if (value != null) {
      params[PdfNameTokens.v] = PdfString.fromString(value!);
    } else {
      params[PdfNameTokens.v] = const PdfNull();
    }

    final buf = PdfStream();
    final g = PdfGraphics(page, buf);
    g.setFillColor(textColor);
    g.setFont(font, fontSize);

    params[PdfNameTokens.da] = PdfString.fromStream(buf);

    // What is /TU? Tooltip?
    //params[PdfNameTokens.tu] = PdfString.fromString('Select from list');
  }

  /// Encoded field flags value.
  int get fieldFlagsValue {
    if (fieldFlags == null || fieldFlags!.isEmpty) {
      return 0;
    }

    return fieldFlags!
        .map<int>((PdfFieldFlags e) => 1 << e.index)
        .reduce((int a, int b) => a | b);
  }
}

/// Annotation object wrapper attached to a page.
class PdfAnnot extends PdfObject<PdfDict> {
  /// Creates an annotation object on [pdfPage].
  PdfAnnot(this.pdfPage, this.annot, {int? objser, int objgen = 0})
      : super(pdfPage.pdfDocument,
            objser: objser,
            objgen: objgen,
            params: PdfDict.values({
              PdfNameTokens.type: const PdfName(PdfNameTokens.annot),
            })) {
    pdfPage.annotations.add(this);
  }

  /// The annotation content
  final PdfAnnotBase annot;

  /// The page where the annotation will display
  final PdfPage pdfPage;

  /// Outputs the annotation contents.
  @override
  void prepare() {
    super.prepare();
    annot.build(pdfPage, this, params);
  }
}

/// Annotation behavior flags.
enum PdfAnnotFlags {
  /// 1
  invisible,

  /// 2
  hidden,

  /// 3
  print,

  /// 4
  noZoom,

  /// 5
  noRotate,

  /// 6
  noView,

  /// 7
  readOnly,

  /// 8
  locked,

  /// 9
  toggleNoView,

  /// 10
  lockedContent,
}

/// Annotation appearance states.
enum PdfAnnotAppearance {
  normal,
  rollover,
  down,
}

/// Base class for PDF annotations.
abstract class PdfAnnotBase {
  /// Creates an annotation base.
  PdfAnnotBase({
    required this.subtype,
    required this.rect,
    this.border,
    this.content,
    this.name,
    Set<PdfAnnotFlags>? flags,
    this.date,
    this.color,
    this.subject,
    this.author,
  }) {
    this.flags = flags ??
        {
          PdfAnnotFlags.print,
        };
  }

  /// The annotation subtype.
  final String subtype;

  /// Annotation rectangle.
  final PdfRect rect;

  /// Border for this annotation.
  final PdfBorder? border;

  /// Text content of the annotation.
  final String? content;

  /// Internal name for a link.
  final String? name;

  /// The author of the annotation.
  final String? author;

  /// The subject of the annotation.
  final String? subject;

  /// Flags specifying various characteristics of the annotation.
  late final Set<PdfAnnotFlags> flags;

  /// Last modification date.
  final DateTime? date;

  /// Annotation color.
  final PdfColor? color;

  final _appearances = <String, PdfDataType>{};

  PdfName? _as;

  /// Encoded annotation flags value.
  int get flagValue {
    if (flags.isEmpty) {
      return 0;
    }

    return flags
        .map<int>((PdfAnnotFlags e) => 1 << e.index)
        .reduce((int a, int b) => a | b);
  }

  /// Creates and registers a form XObject for the appearance stream.
  PdfGraphics appearance(
    PdfDocument pdfDocument,
    PdfAnnotAppearance type, {
    String? name,
    Matrix4? matrix,
    PdfRect? boundingBox,
    bool selected = false,
  }) {
    final s = PdfGraphicXObject(pdfDocument, PdfNameTokens.form);
    String? n;
    switch (type) {
      case PdfAnnotAppearance.normal:
        n = PdfNameTokens.n;
        break;
      case PdfAnnotAppearance.rollover:
        n = PdfNameTokens.r;
        break;
      case PdfAnnotAppearance.down:
        n = PdfNameTokens.d;
        break;
    }
    if (name == null) {
      _appearances[n] = s.ref();
    } else {
      if (_appearances[n] is! PdfDict) {
        _appearances[n] = PdfDict();
      }
      final d = _appearances[n];
      if (d is PdfDict) {
        d[name] = s.ref();
      }
    }

    if (matrix != null) {
      s.params[PdfNameTokens.matrix] = PdfArray.fromNum(
          [matrix[0], matrix[1], matrix[4], matrix[5], matrix[12], matrix[13]]);
    }

    final bBox = boundingBox ?? PdfRect.fromPoints(PdfPoint.zero, rect.size);
    s.params[PdfNameTokens.bbox] =
        PdfArray.fromNum([bBox.left, bBox.bottom, bBox.width, bBox.height]);
    final g = PdfGraphics(s, s.buf);

    if (selected && name != null) {
      _as = PdfName(name);
    }
    return g;
  }

  @protected
  @mustCallSuper
  /// Writes the annotation dictionary entries.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    params[PdfNameTokens.subtype] = PdfName(subtype);
    params[PdfNameTokens.rect] =
        PdfArray.fromNum([rect.left, rect.bottom, rect.right, rect.top]);

    params[PdfNameTokens.p] = page.ref();

    // handle the border
    if (border == null) {
      params[PdfNameTokens.border] = PdfArray.fromNum(const [0, 0, 0]);
    } else {
      params[PdfNameTokens.bs] = border!.ref();
    }

    if (content != null) {
      params[PdfNameTokens.contents] = PdfString.fromString(content!);
    }

    if (name != null) {
      params[PdfNameTokens.nm] = PdfString.fromString(name!);
    }

    if (flags.isNotEmpty) {
      params[PdfNameTokens.f] = PdfNum(flagValue);
    }

    if (date != null) {
      params[PdfNameTokens.m] = PdfString.fromDate(date!);
    }

    if (color != null) {
      params[PdfNameTokens.c] = PdfArray.fromColor(color!);
    }

    if (subject != null) {
      params[PdfNameTokens.subj] = PdfString.fromString(subject!);
    }

    if (author != null) {
      params[PdfNameTokens.t] = PdfString.fromString(author!);
    }

    if (_appearances.isNotEmpty) {
      params[PdfNameTokens.ap] = PdfDict.values(_appearances);
      if (_as != null) {
        params[PdfNameTokens.as] = _as!;
      }
    }
  }
}

/// Text annotation.
class PdfAnnotText extends PdfAnnotBase {
  /// Creates a text annotation.
  PdfAnnotText({
    required PdfRect rect,
    required String content,
    PdfBorder? border,
    String? name,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    String? subject,
    String? author,
  }) : super(
          subtype: PdfNameTokens.text,
          rect: rect,
          border: border,
          content: content,
          name: name,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
        );
}

/// Named destination link annotation.
class PdfAnnotNamedLink extends PdfAnnotBase {
  /// Creates a named link annotation.
  PdfAnnotNamedLink({
    required PdfRect rect,
    required this.dest,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    String? subject,
    String? author,
  }) : super(
          subtype: PdfNameTokens.link,
          rect: rect,
          border: border,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
        );

  /// Destination name.
  final String dest;

  @override
  /// Writes the named destination action.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);
    params[PdfNameTokens.a] = PdfDict.values(
      {
        PdfNameTokens.s: const PdfName(PdfNameTokens.goto),
        PdfNameTokens.d: PdfString.fromString(dest),
      },
    );
  }
}

/// URL link annotation.
class PdfAnnotUrlLink extends PdfAnnotBase {
  /// Creates a URL link annotation.
  PdfAnnotUrlLink({
    required PdfRect rect,
    required this.url,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    String? subject,
    String? author,
  }) : super(
          subtype: PdfNameTokens.link,
          rect: rect,
          border: border,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
        );

  /// Target URL.
  final String url;

  @override
  /// Writes the URI action.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);
    params[PdfNameTokens.a] = PdfDict.values(
      {
        PdfNameTokens.s: const PdfName(PdfNameTokens.uri),
        PdfNameTokens.uri: PdfString.fromString(url),
      },
    );
  }
}

/// Convenience wrapper for URL annotations.
class PdfUriAnnotation extends PdfAnnotUrlLink {
  /// Creates a URI annotation.
  PdfUriAnnotation({
    required PdfRect bounds,
    required String uri,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    String? subject,
    String? author,
  }) : super(
          rect: bounds,
          url: uri,
          border: border,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
        );
}

/// Square annotation.
class PdfAnnotSquare extends PdfAnnotBase {
  /// Creates a square annotation.
  PdfAnnotSquare({
    required PdfRect rect,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    this.interiorColor,
    String? subject,
    String? author,
  }) : super(
          subtype: PdfNameTokens.square,
          rect: rect,
          border: border,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
        );

  /// Interior fill color.
  final PdfColor? interiorColor;

  @override
  /// Writes the square annotation dictionary.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);
    if (interiorColor != null) {
      params[PdfNameTokens.ic] = PdfArray.fromColor(interiorColor!);
    }
  }
}

/// Circle annotation.
class PdfAnnotCircle extends PdfAnnotBase {
  /// Creates a circle annotation.
  PdfAnnotCircle({
    required PdfRect rect,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    this.interiorColor,
    String? subject,
    String? author,
  }) : super(
          subtype: PdfNameTokens.circle,
          rect: rect,
          border: border,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
        );

  /// Interior fill color.
  final PdfColor? interiorColor;

  @override
  /// Writes the circle annotation dictionary.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);
    if (interiorColor != null) {
      params[PdfNameTokens.ic] = PdfArray.fromColor(interiorColor!);
    }
  }
}

/// Polygon/polyline annotation.
class PdfAnnotPolygon extends PdfAnnotBase {
  /// Creates a polygon/polyline annotation.
  PdfAnnotPolygon(this.document, this.points,
      {required PdfRect rect,
      PdfBorder? border,
      Set<PdfAnnotFlags>? flags,
      DateTime? date,
      PdfColor? color,
      this.interiorColor,
      String? subject,
      String? author,
      bool closed = true})
      : super(
          subtype: closed ? PdfNameTokens.polyline : PdfNameTokens.polygon,
          rect: rect,
          border: border,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
        );

  /// Document owning this annotation.
  final PdfDocument document;

  /// Vertex points.
  final List<PdfPoint> points;

  /// Interior fill color.
  final PdfColor? interiorColor;

  @override
  /// Writes the polygon/polyline dictionary.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);

    // Flip the points on the Y axis.
    final flippedPoints =
        points.map((e) => PdfPoint(e.x, rect.height - e.y)).toList();

    final vertices = <num>[];
    for (var i = 0; i < flippedPoints.length; i++) {
      vertices.add(flippedPoints[i].x);
      vertices.add(flippedPoints[i].y);
    }

    params[PdfNameTokens.vertices] = PdfArray.fromNum(vertices);

    if (interiorColor != null) {
      params[PdfNameTokens.ic] = PdfArray.fromColor(interiorColor!);
    }
  }
}

/// Ink list annotation.
class PdfAnnotInk extends PdfAnnotBase {
  /// Creates an ink list annotation.
  PdfAnnotInk(
    this.document,
    this.points, {
    required PdfRect rect,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    String? subject,
    String? author,
    String? content,
  }) : super(
          subtype: PdfNameTokens.ink,
          rect: rect,
          border: border,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
          content: content,
        );

  /// Document owning this annotation.
  final PdfDocument document;

  /// List of ink strokes.
  final List<List<PdfPoint>> points;

  @override
  /// Writes the ink list dictionary.
  void build(
    PdfPage page,
    PdfObject object,
    PdfDict params,
  ) {
    super.build(page, object, params);

    final vertices = List<List<num>>.filled(points.length, <num>[]);
    for (var listIndex = 0; listIndex < points.length; listIndex++) {
      // Flip the points on the Y axis.
      final flippedPoints = points[listIndex]
          .map((e) => PdfPoint(e.x, rect.height - e.y))
          .toList();
      for (var i = 0; i < flippedPoints.length; i++) {
        vertices[listIndex].add(flippedPoints[i].x);
        vertices[listIndex].add(flippedPoints[i].y);
      }
    }

    params[PdfNameTokens.inklist] =
        PdfArray(vertices.map((v) => PdfArray.fromNum(v)).toList());
  }
}

/// Highlighting modes for widget annotations.
enum PdfAnnotHighlighting { none, invert, outline, push, toggle }

/// Base class for widget annotations (AcroForm).
abstract class PdfAnnotWidget extends PdfAnnotBase {
  /// Creates a widget annotation.
  PdfAnnotWidget({
    required PdfRect rect,
    required this.fieldType,
    this.fieldName,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    this.backgroundColor,
    this.highlighting,
    String? subject,
    String? author,
  }) : super(
          subtype: PdfNameTokens.widget,
          rect: rect,
          border: border,
          flags: flags,
          date: date,
          color: color,
          subject: subject,
          author: author,
        );

  /// Field type name.
  final String fieldType;

  /// Field name.
  final String? fieldName;

  /// Highlighting behavior.
  final PdfAnnotHighlighting? highlighting;

  /// Background color.
  final PdfColor? backgroundColor;

  @override
  /// Writes widget annotation fields.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);

    params[PdfNameTokens.ft] = PdfName(fieldType);

    if (fieldName != null) {
      params[PdfNameTokens.t] = PdfString.fromString(fieldName!);
    }

    final mk = PdfDict();
    if (color != null) {
      mk.values[PdfNameTokens.bc] = PdfArray.fromColor(color!);
    }

    if (backgroundColor != null) {
      mk.values[PdfNameTokens.bg] = PdfArray.fromColor(backgroundColor!);
    }

    if (mk.values.isNotEmpty) {
      params[PdfNameTokens.mk] = mk;
    }

    if (highlighting != null) {
      switch (highlighting!) {
        case PdfAnnotHighlighting.none:
          params[PdfNameTokens.h] = const PdfName(PdfNameTokens.n);
          break;
        case PdfAnnotHighlighting.invert:
          params[PdfNameTokens.h] = const PdfName(PdfNameTokens.i);
          break;
        case PdfAnnotHighlighting.outline:
          params[PdfNameTokens.h] = const PdfName(PdfNameTokens.o);
          break;
        case PdfAnnotHighlighting.push:
          params[PdfNameTokens.h] = const PdfName(PdfNameTokens.p);
          break;
        case PdfAnnotHighlighting.toggle:
          params[PdfNameTokens.h] = const PdfName(PdfNameTokens.t);
          break;
      }
    }
  }
}

/// Signature widget annotation.
class PdfAnnotSign extends PdfAnnotWidget {
  /// Creates a signature widget annotation.
  PdfAnnotSign({
    required PdfRect rect,
    String? fieldName,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    PdfAnnotHighlighting? highlighting,
  }) : super(
          rect: rect,
          fieldType: PdfNameTokens.sig,
          fieldName: fieldName,
          border: border,
          flags: flags,
          date: date,
          color: color,
          highlighting: highlighting,
        );

  @override
  /// Writes signature widget fields and /V if present.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);
    if (!params.containsKey(PdfNameTokens.v) && page.pdfDocument.sign != null) {
      params[PdfNameTokens.v] = page.pdfDocument.sign!.ref();
    }
  }
}

/// AcroForm field flags.
enum PdfFieldFlags {
  /// 1 - If set, the user may not change the value of the field.
  readOnly,

  /// 2 - If set, the field shall have a value at the time it is exported by
  /// a submit-form action.
  mandatory,

  /// 3 - If set, the field shall not be exported by a submit-form action.
  noExport,

  /// 4
  reserved4,

  /// 5
  reserved5,

  /// 6
  reserved6,

  /// 7
  reserved7,

  /// 8
  reserved8,

  /// 9
  reserved9,

  /// 10
  reserved10,

  /// 11
  reserved11,

  /// 12
  reserved12,

  /// 13 - If set, the field may contain multiple lines of text; if clear,
  /// the field’s text shall be restricted to a single line.
  multiline,

  /// 14 - If set, the field is intended for entering a secure password that
  /// should not be echoed visibly to the screen. Characters typed from
  /// the keyboard shall instead be echoed in some unreadable form, such
  /// as asterisks or bullet characters.
  password,

  /// 15 - If set, exactly one radio button shall be selected at all times.
  noToggleToOff,

  /// 16 - If set, the field is a set of radio buttons; if clear,
  /// the field is a check box.
  radio,

  /// 17 - If set, the field is a pushbutton that does not retain
  /// a permanent value.
  pushButton,

  /// 18 - If set, the field is a combo box; if clear, the field is a list box.
  combo,

  /// 19 - If set, the combo box shall include an editable text box as well
  /// as a drop-down list
  edit,

  /// 20 - If set, the field’s option items shall be sorted alphabetically.
  sort,

  /// 21 - If set, the text entered in the field represents the pathname
  /// of a file whose contents shall be submitted as the value of the field.
  fileSelect,

  /// 22 - If set, more than one of the field’s option items may be selected
  /// simultaneously
  multiSelect,

  /// 23 - If set, text entered in the field shall not be spell-checked.
  doNotSpellCheck,

  /// 24 - If set, the field shall not scroll to accommodate more text
  /// than fits within its annotation rectangle.
  doNotScroll,

  /// 25 - If set, the field shall be automatically divided into as many
  /// equally spaced positions, or combs, as the value of MaxLen,
  /// and the text is laid out into those combs.
  comb,

  /// 26 - If set, a group of radio buttons within a radio button field
  /// that use the same value for the on state will turn on and off in unison.
  radiosInUnison,

  /// 27 - If set, the new value shall be committed as soon as a selection
  /// is made.
  commitOnSelChange,
}

/// Base class for AcroForm fields.
class PdfFormField extends PdfAnnotWidget {
  /// Creates a form field widget.
  PdfFormField({
    required String fieldType,
    required PdfRect rect,
    String? fieldName,
    this.alternateName,
    this.mappingName,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    String? subject,
    String? author,
    PdfColor? color,
    PdfColor? backgroundColor,
    PdfAnnotHighlighting? highlighting,
    this.fieldFlags,
  }) : super(
          rect: rect,
          fieldType: fieldType,
          fieldName: fieldName,
          border: border,
          flags: flags,
          date: date,
          subject: subject,
          author: author,
          backgroundColor: backgroundColor,
          color: color,
          highlighting: highlighting,
        );

  /// Alternate field name.
  final String? alternateName;

  /// Mapping name.
  final String? mappingName;

  /// Field flags.
  final Set<PdfFieldFlags>? fieldFlags;

  /// Encoded field flags value.
  int get fieldFlagsValue {
    if (fieldFlags == null || fieldFlags!.isEmpty) {
      return 0;
    }

    return fieldFlags!
        .map<int>((PdfFieldFlags e) => 1 << e.index)
        .reduce((int a, int b) => a | b);
  }

  @override
  /// Writes form field dictionary entries.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);
    if (alternateName != null) {
      params[PdfNameTokens.tu] = PdfString.fromString(alternateName!);
    }
    if (mappingName != null) {
      params[PdfNameTokens.tm] = PdfString.fromString(mappingName!);
    }

    params[PdfNameTokens.ff] = PdfNum(fieldFlagsValue);
  }
}

/// Text alignment for text fields.
enum PdfTextFieldAlign { left, center, right }

/// Text field widget.
class PdfTextField extends PdfFormField {
  /// Creates a text field widget.
  PdfTextField({
    required PdfRect rect,
    String? fieldName,
    String? alternateName,
    String? mappingName,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    String? subject,
    String? author,
    PdfColor? color,
    PdfColor? backgroundColor,
    PdfAnnotHighlighting? highlighting,
    Set<PdfFieldFlags>? fieldFlags,
    this.value,
    this.defaultValue,
    this.maxLength,
    required this.font,
    required this.fontSize,
    required this.textColor,
    this.textAlign,
  }) : super(
          rect: rect,
          fieldType: PdfNameTokens.tx,
          fieldName: fieldName,
          border: border,
          flags: flags,
          date: date,
          subject: subject,
          author: author,
          color: color,
          backgroundColor: backgroundColor,
          highlighting: highlighting,
          alternateName: alternateName,
          mappingName: mappingName,
          fieldFlags: fieldFlags,
        );

  /// Maximum input length.
  final int? maxLength;

  /// Current value.
  final String? value;

  /// Default value.
  final String? defaultValue;

  /// Font used to render text.
  final PdfFont font;

  /// Font size.
  final double fontSize;

  /// Text color.
  final PdfColor textColor;

  /// Text alignment.
  final PdfTextFieldAlign? textAlign;

  @override
  /// Writes text field parameters and default appearance.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);
    if (maxLength != null) {
      params[PdfNameTokens.maxLen] = PdfNum(maxLength!);
    }

    final buf = PdfStream();
    final g = PdfGraphics(page, buf);
    g.setFillColor(textColor);
    g.setFont(font, fontSize);
    params[PdfNameTokens.da] = PdfString.fromStream(buf);

    if (value != null) {
      params[PdfNameTokens.v] = PdfString.fromString(value!);
    }
    if (defaultValue != null) {
      params[PdfNameTokens.dv] = PdfString.fromString(defaultValue!);
    }
    if (textAlign != null) {
      params[PdfNameTokens.q] = PdfNum(textAlign!.index);
    }
  }
}

/// Button field widget.
class PdfButtonField extends PdfFormField {
  /// Creates a button field widget.
  PdfButtonField({
    required PdfRect rect,
    required String fieldName,
    String? alternateName,
    String? mappingName,
    PdfBorder? border,
    Set<PdfAnnotFlags>? flags,
    DateTime? date,
    PdfColor? color,
    PdfColor? backgroundColor,
    PdfAnnotHighlighting? highlighting,
    Set<PdfFieldFlags>? fieldFlags,
    this.value,
    this.defaultValue,
  }) : super(
          rect: rect,
          fieldType: PdfNameTokens.btn,
          fieldName: fieldName,
          border: border,
          flags: flags,
          date: date,
          color: color,
          backgroundColor: backgroundColor,
          highlighting: highlighting,
          alternateName: alternateName,
          mappingName: mappingName,
          fieldFlags: fieldFlags,
        );

  /// Current value.
  final String? value;

  /// Default value.
  final String? defaultValue;

  @override
  /// Writes button field parameters.
  void build(PdfPage page, PdfObject object, PdfDict params) {
    super.build(page, object, params);

    if (value != null) {
      params[PdfNameTokens.v] = PdfName(value!);
    }

    if (defaultValue != null) {
      params[PdfNameTokens.dv] = PdfName(defaultValue!);
    }
  }
}





