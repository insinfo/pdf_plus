/*
 * Copyright (C) 2026, Isaque Neves <insinfo2008@gmail.com>
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

import 'dart:math' as math;
import 'dart:typed_data';

import '../parsing/pdf_document_parser.dart';
import '../point.dart';
import '../rect.dart';
import 'pdf_content_font.dart';
import 'pdf_content_operator.dart';
import 'pdf_content_parser.dart';
import 'pdf_content_resources.dart';

/// A run of extracted text with the position it was drawn at.
class PdfTextItem {
  /// Creates a text item.
  const PdfTextItem({
    required this.text,
    required this.bounds,
    required this.origin,
    required this.fontSize,
    required this.renderedFontSize,
    this.fontName,
    this.baseFont,
    this.fullyMapped = true,
    this.formDepth = 0,
    this.renderMode = 0,
  });

  /// Text of the run.
  final String text;

  /// Approximate rectangle occupied by the run, in user space.
  ///
  /// The height is estimated as `0.75 em` above and `0.25 em` below the
  /// baseline, because the extractor does not read the real bbox of the
  /// glyphs. The width comes from the widths declared in the font, which are
  /// exact when `/Widths` (or `/W`) exists and a guess when it does not.
  final PdfRect bounds;

  /// Origin of the baseline, in user space.
  final PdfPoint origin;

  /// Size requested by `Tf`, before the matrices.
  final double fontSize;

  /// Effective size after `Tm` and the CTM — the size visible on the page.
  final double renderedFontSize;

  /// Font resource name (`/F1`), when there was a `Tf`.
  final String? fontName;

  /// `/BaseFont` of the font, when the resource could be resolved.
  final String? baseFont;

  /// `false` when some code could not be mapped to text.
  final bool fullyMapped;

  /// Zero when the text is directly on the page; higher inside a form
  /// XObject.
  final int formDepth;

  /// Current rendering mode (`Tr`). Mode 3 is invisible text — common in OCR
  /// layers — and is still extracted.
  final int renderMode;

  @override
  String toString() =>
      'PdfTextItem("$text", ${bounds.left.toStringAsFixed(1)}, '
      '${bounds.bottom.toStringAsFixed(1)})';
}

/// Text extraction settings.
class PdfTextExtractionOptions {
  /// Creates the options.
  const PdfTextExtractionOptions({
    this.followFormXObjects = true,
    this.maxFormDepth = 8,
    this.spaceGapRatio = 0.2,
  });

  /// When `true`, descends into the form XObjects drawn by `Do`.
  final bool followFormXObjects;

  /// Maximum nesting depth of form XObjects.
  final int maxFormDepth;

  /// Fraction of the font size from which a negative adjustment inside a `TJ`
  /// is read as a space between words.
  final double spaceGapRatio;
}

/// Extracts positioned text from a list of content stream operators.
///
/// ## What is tracked
///
/// `BT`/`ET`, `Tf`, `Td`, `TD`, `Tm`, `T*`, `Tj`, `TJ`, `'`, `"`, `Tc`, `Tw`,
/// `Tz`, `TL`, `Ts`, `Tr`, plus the current transformation matrix through
/// `cm`, `q` and `Q`. Optionally descends into the form XObjects of `Do`,
/// applying the form's `/Matrix`.
///
/// ## Where it gets things wrong, spelled out
///
/// - **subsetted Type0 font without `/ToUnicode`**: the codes are internal
///   glyph indices and there is no way to recover the text. The characters
///   come out as `�` and the item carries [PdfTextItem.fullyMapped] as
///   `false`. Reading the `cmap` table of the embedded font would solve part
///   of this and is out of scope here;
/// - **approximate rectangle**: the height is estimated and does not come from
///   the bbox of the glyphs; the width depends on `/Widths` and `/W`. Without
///   them, the extractor settles on 500/1000 em per glyph;
/// - **Type3**: the font's own `/FontMatrix` is ignored, so position and width
///   come out wrong;
/// - **vertical writing** (`/Identity-V`, `/WMode 1`): treated as horizontal;
/// - **reading order**: the items come out in stream order, which is not
///   necessarily the visual order. [plainText] applies a simple heuristic, not
///   a column segmentation;
/// - **text in annotations** (`/AP`) is not part of the page content and is
///   not visited, unless the caller passes the appearance stream.
///
/// ## What is left out by decision
///
/// Text replacement is **not** implemented. Rewriting `Tj`/`TJ` safely
/// requires re-encoding the text in the target font, checking whether the
/// embedded subset has the glyphs, recomputing advances and, when it does not,
/// embedding or swapping the font — the work that in practice only MuPDF does
/// in open source. Covering the reading half without promising the writing
/// half is deliberate: a replacement that sometimes corrupts the stream or
/// changes the drawing would be worse than none at all. See
/// `doc/roteiro_edicao_pdf.md`, phase F8.
class PdfTextExtractor {
  /// Creates an extractor.
  PdfTextExtractor({
    PdfContentResources? resources,
    this.options = const PdfTextExtractionOptions(),
  }) : resources = resources ?? PdfContentResources.empty;

  /// Resources used to resolve fonts and form XObjects.
  final PdfContentResources resources;

  /// Options.
  final PdfTextExtractionOptions options;

  /// Extracts the text of a page from a document opened by the parser.
  ///
  /// Returns an empty list when the page does not exist or has no readable
  /// content.
  static List<PdfTextItem> extractPage(
    PdfDocumentParser parser,
    int pageIndex, {
    PdfTextExtractionOptions options = const PdfTextExtractionOptions(),
  }) {
    final content = decodePageContent(parser, pageIndex);
    if (content == null || content.isEmpty) return const <PdfTextItem>[];
    final resources = PdfParserContentResources.forPage(parser, pageIndex);
    return PdfTextExtractor(resources: resources, options: options)
        .extract(PdfContentParser.parseBytes(content));
  }

  /// Extracts the text of [operators].
  List<PdfTextItem> extract(List<PdfContentOperator> operators) {
    final items = <PdfTextItem>[];
    _run(operators, resources, _identity, 0, <int>{}, items);
    return items;
  }

  /// Joins the items into running text, inserting breaks when the baseline
  /// changes and spaces when there is a horizontal gap.
  ///
  /// It is a convenience heuristic, not a layout analysis: columns, tables and
  /// rotated text come out scrambled.
  static String plainText(List<PdfTextItem> items) {
    final buffer = StringBuffer();
    PdfTextItem? previous;
    for (final item in items) {
      if (item.text.isEmpty) continue;
      if (previous != null) {
        final size = math.max(item.renderedFontSize, 1.0);
        final sameLine = (previous.origin.y - item.origin.y).abs() < size * 0.5;
        if (!sameLine) {
          buffer.write('\n');
        } else {
          final gap = item.bounds.left - previous.bounds.right;
          final needsSpace = gap > size * 0.2 &&
              !buffer.toString().endsWith(' ') &&
              !item.text.startsWith(' ');
          if (needsSpace) buffer.write(' ');
        }
      }
      buffer.write(item.text);
      previous = item;
    }
    return buffer.toString();
  }

  // ---------------------------------------------------------------------------
  // Execution
  // ---------------------------------------------------------------------------

  static const List<double> _identity = <double>[1, 0, 0, 1, 0, 0];

  void _run(
    List<PdfContentOperator> operators,
    PdfContentResources resources,
    List<double> initialCtm,
    int depth,
    Set<int> visitedForms,
    List<PdfTextItem> items,
  ) {
    final stack = <_TextGraphicsState>[];
    var state = _TextGraphicsState(ctm: initialCtm);

    var textMatrix = _identity;
    var lineMatrix = _identity;

    for (final operator in operators) {
      switch (operator.operator) {
        case 'q':
          stack.add(state.clone());
          break;

        case 'Q':
          if (stack.isNotEmpty) state = stack.removeLast();
          break;

        case 'cm':
          final matrix = _matrixOf(operator, 0);
          if (matrix != null) state.ctm = _multiply(matrix, state.ctm);
          break;

        case 'BT':
        case 'ET':
          // `BT` resets the text matrices; resetting on `ET` too keeps the
          // state predictable when a stream forgets the next `BT`.
          textMatrix = _identity;
          lineMatrix = _identity;
          break;

        case 'Tf':
          state.fontName = operator.nameAt(0);
          state.fontSize = operator.numberAt(1) ?? state.fontSize;
          state.font = state.fontName == null
              ? null
              : resources.findFont(state.fontName!);
          break;

        case 'Tc':
          state.charSpacing = operator.numberAt(0) ?? state.charSpacing;
          break;

        case 'Tw':
          state.wordSpacing = operator.numberAt(0) ?? state.wordSpacing;
          break;

        case 'Tz':
          state.horizontalScale =
              (operator.numberAt(0) ?? 100) / 100.0;
          break;

        case 'TL':
          state.leading = operator.numberAt(0) ?? state.leading;
          break;

        case 'Ts':
          state.rise = operator.numberAt(0) ?? state.rise;
          break;

        case 'Tr':
          state.renderMode = (operator.numberAt(0) ?? 0).toInt();
          break;

        case 'Td':
          final tx = operator.numberAt(0) ?? 0;
          final ty = operator.numberAt(1) ?? 0;
          lineMatrix = _multiply(_translation(tx, ty), lineMatrix);
          textMatrix = lineMatrix;
          break;

        case 'TD':
          final tx = operator.numberAt(0) ?? 0;
          final ty = operator.numberAt(1) ?? 0;
          state.leading = -ty;
          lineMatrix = _multiply(_translation(tx, ty), lineMatrix);
          textMatrix = lineMatrix;
          break;

        case 'Tm':
          final matrix = _matrixOf(operator, 0);
          if (matrix != null) {
            lineMatrix = matrix;
            textMatrix = matrix;
          }
          break;

        case 'T*':
          lineMatrix =
              _multiply(_translation(0, -state.leading), lineMatrix);
          textMatrix = lineMatrix;
          break;

        case 'Tj':
          if (operator.operands.isNotEmpty) {
            final value = operator.operands.first;
            if (value is PdfContentString) {
              textMatrix = _show(
                  <PdfContentValue>[value], state, textMatrix, depth, items);
            }
          }
          break;

        case 'TJ':
          if (operator.operands.isNotEmpty) {
            final value = operator.operands.first;
            if (value is PdfContentArray) {
              textMatrix =
                  _show(value.values, state, textMatrix, depth, items);
            }
          }
          break;

        case "'":
          lineMatrix =
              _multiply(_translation(0, -state.leading), lineMatrix);
          textMatrix = lineMatrix;
          if (operator.operands.isNotEmpty) {
            final value = operator.operands.last;
            if (value is PdfContentString) {
              textMatrix = _show(
                  <PdfContentValue>[value], state, textMatrix, depth, items);
            }
          }
          break;

        case '"':
          state.wordSpacing = operator.numberAt(0) ?? state.wordSpacing;
          state.charSpacing = operator.numberAt(1) ?? state.charSpacing;
          lineMatrix =
              _multiply(_translation(0, -state.leading), lineMatrix);
          textMatrix = lineMatrix;
          if (operator.operands.length >= 3) {
            final value = operator.operands[2];
            if (value is PdfContentString) {
              textMatrix = _show(
                  <PdfContentValue>[value], state, textMatrix, depth, items);
            }
          }
          break;

        case 'Do':
          if (!options.followFormXObjects) break;
          if (depth >= options.maxFormDepth) break;
          final name = operator.nameAt(0);
          if (name == null) break;
          final form = resources.findFormXObject(name);
          if (form == null) break;
          final id = form.objectId;
          if (id != null && !visitedForms.add(id)) break;
          try {
            final matrix = form.matrix != null && form.matrix!.length >= 6
                ? _multiply(form.matrix!.sublist(0, 6), state.ctm)
                : state.ctm;
            _run(PdfContentParser.parseBytes(form.content), form.resources,
                matrix, depth + 1, visitedForms, items);
          } finally {
            if (id != null) visitedForms.remove(id);
          }
          break;

        default:
          break;
      }
    }
  }

  /// Draws the elements of a `Tj`/`TJ` and returns the new text matrix.
  List<double> _show(
    List<PdfContentValue> elements,
    _TextGraphicsState state,
    List<double> textMatrix,
    int depth,
    List<PdfTextItem> items,
  ) {
    final font = state.font ?? PdfContentFont.unknown(state.fontName);
    final buffer = StringBuffer();
    final startMatrix = textMatrix;
    var advance = 0.0;
    var fullyMapped = true;

    for (final element in elements) {
      if (element is PdfContentNumber) {
        final shift = -element.value / 1000.0 *
            state.fontSize *
            state.horizontalScale;
        advance += shift;
        // A large kern is the usual way to write a space without spending a
        // glyph; without this heuristic adjacent words become a single one.
        if (-element.value / 1000.0 * state.fontSize >
                state.fontSize * options.spaceGapRatio &&
            buffer.isNotEmpty &&
            !buffer.toString().endsWith(' ')) {
          buffer.write(' ');
        }
        continue;
      }
      if (element is! PdfContentString) continue;

      for (final glyph in font.decode(element.bytes)) {
        buffer.write(glyph.text);
        if (!glyph.mapped) fullyMapped = false;
        final isSpace = glyph.byteLength == 1 && glyph.code == 32;
        advance += (glyph.width / 1000.0 * state.fontSize +
                state.charSpacing +
                (isSpace ? state.wordSpacing : 0)) *
            state.horizontalScale;
      }
    }

    final text = buffer.toString();
    final newMatrix = _multiply(_translation(advance, 0), startMatrix);

    if (text.isNotEmpty) {
      final combined = _multiply(startMatrix, state.ctm);
      final bottom = state.rise - state.fontSize * 0.25;
      final top = state.rise + state.fontSize * 0.75;
      final corners = <PdfPoint>[
        _apply(combined, 0, bottom),
        _apply(combined, advance, bottom),
        _apply(combined, advance, top),
        _apply(combined, 0, top),
      ];
      var left = corners.first.x;
      var right = corners.first.x;
      var lowest = corners.first.y;
      var highest = corners.first.y;
      for (final corner in corners) {
        left = math.min(left, corner.x);
        right = math.max(right, corner.x);
        lowest = math.min(lowest, corner.y);
        highest = math.max(highest, corner.y);
      }

      final verticalScale =
          math.sqrt(combined[2] * combined[2] + combined[3] * combined[3]);

      items.add(PdfTextItem(
        text: text,
        bounds: PdfRect.fromLBRT(left, lowest, right, highest),
        origin: _apply(combined, 0, state.rise),
        fontSize: state.fontSize,
        renderedFontSize: state.fontSize * verticalScale,
        fontName: state.fontName,
        baseFont: state.font?.baseFont,
        fullyMapped: fullyMapped,
        formDepth: depth,
        renderMode: state.renderMode,
      ));
    }

    return newMatrix;
  }

  // ---------------------------------------------------------------------------
  // 3x2 matrices in PDF form: [a b c d e f]
  // ---------------------------------------------------------------------------

  static List<double>? _matrixOf(PdfContentOperator operator, int start) {
    if (operator.operands.length < start + 6) return null;
    final values = <double>[];
    for (var i = 0; i < 6; i++) {
      final value = operator.numberAt(start + i);
      if (value == null) return null;
      values.add(value);
    }
    return values;
  }

  static List<double> _translation(double tx, double ty) =>
      <double>[1, 0, 0, 1, tx, ty];

  static List<double> _multiply(List<double> a, List<double> b) => <double>[
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
      ];

  static PdfPoint _apply(List<double> m, double x, double y) =>
      PdfPoint(m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]);
}

class _TextGraphicsState {
  _TextGraphicsState({
    required this.ctm,
    this.font,
    this.fontName,
    this.fontSize = 0,
    this.charSpacing = 0,
    this.wordSpacing = 0,
    this.horizontalScale = 1,
    this.leading = 0,
    this.rise = 0,
    this.renderMode = 0,
  });

  List<double> ctm;
  PdfContentFont? font;
  String? fontName;
  double fontSize;
  double charSpacing;
  double wordSpacing;
  double horizontalScale;
  double leading;
  double rise;
  int renderMode;

  _TextGraphicsState clone() => _TextGraphicsState(
        ctm: ctm,
        font: font,
        fontName: fontName,
        fontSize: fontSize,
        charSpacing: charSpacing,
        wordSpacing: wordSpacing,
        horizontalScale: horizontalScale,
        leading: leading,
        rise: rise,
        renderMode: renderMode,
      );
}

/// Extracts the text of a whole page that is already decoded.
///
/// A shortcut for callers that already have the content stream bytes and the
/// resource dictionary at hand.
List<PdfTextItem> extractTextFromContent(
  Uint8List content, {
  PdfContentResources? resources,
  PdfTextExtractionOptions options = const PdfTextExtractionOptions(),
}) =>
    PdfTextExtractor(resources: resources, options: options)
        .extract(PdfContentParser.parseBytes(content));
