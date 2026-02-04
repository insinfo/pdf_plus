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

import 'dart:math' as math;

import 'point.dart';

/// Describes a page size and margins in PDF points.
class PdfPageFormat {
  /// Creates a page format with optional margins.
  const PdfPageFormat(this.width, this.height,
      {double marginTop = 0.0,
      double marginBottom = 0.0,
      double marginLeft = 0.0,
      double marginRight = 0.0,
      double? marginAll})
      : assert(width > 0),
        assert(height > 0),
        marginTop = marginAll ?? marginTop,
        marginBottom = marginAll ?? marginBottom,
        marginLeft = marginAll ?? marginLeft,
        marginRight = marginAll ?? marginRight;

  /// A3 page format with default margins.
  static const PdfPageFormat a3 =
      PdfPageFormat(29.7 * cm, 42 * cm, marginAll: 2.0 * cm);
  /// A4 page format with default margins.
  static const PdfPageFormat a4 =
      PdfPageFormat(21.0 * cm, 29.7 * cm, marginAll: 2.0 * cm);
  /// A5 page format with default margins.
  static const PdfPageFormat a5 =
      PdfPageFormat(14.8 * cm, 21.0 * cm, marginAll: 2.0 * cm);
  /// A6 page format with default margins.
  static const PdfPageFormat a6 =
      PdfPageFormat(105 * mm, 148 * mm, marginAll: 1.0 * cm);
  /// US Letter page format with default margins.
  static const PdfPageFormat letter =
      PdfPageFormat(8.5 * inch, 11.0 * inch, marginAll: inch);
  /// US Legal page format with default margins.
  static const PdfPageFormat legal =
      PdfPageFormat(8.5 * inch, 14.0 * inch, marginAll: inch);

  /// 57mm roll format with default margins.
  static const PdfPageFormat roll57 =
      PdfPageFormat(57 * mm, double.infinity, marginAll: 5 * mm);
  /// 80mm roll format with default margins.
  static const PdfPageFormat roll80 =
      PdfPageFormat(80 * mm, double.infinity, marginAll: 5 * mm);

  /// Undefined page format (infinite size).
  static const PdfPageFormat undefined =
      PdfPageFormat(double.infinity, double.infinity);

  /// Standard page format alias (A4).
  static const PdfPageFormat standard = a4;

  /// PDF point unit.
  static const double point = 1.0;
  /// Inches in points.
  static const double inch = 72.0;
  /// Centimeters in points.
  static const double cm = inch / 2.54;
  /// Millimeters in points.
  static const double mm = inch / 25.4;

  /// Flutter's Logical Pixel
  static const double dp = 72.0 / 150.0;

  /// Page width in points.
  final double width;
  /// Page height in points.
  final double height;

  /// Top margin in points.
  final double marginTop;
  /// Bottom margin in points.
  final double marginBottom;
  /// Left margin in points.
  final double marginLeft;
  /// Right margin in points.
  final double marginRight;

  /// Returns a copy with updated values.
  PdfPageFormat copyWith(
      {double? width,
      double? height,
      double? marginTop,
      double? marginBottom,
      double? marginLeft,
      double? marginRight}) {
    return PdfPageFormat(width ?? this.width, height ?? this.height,
        marginTop: marginTop ?? this.marginTop,
        marginBottom: marginBottom ?? this.marginBottom,
        marginLeft: marginLeft ?? this.marginLeft,
        marginRight: marginRight ?? this.marginRight);
  }

  /// Total page dimensions.
  PdfPoint get dimension => PdfPoint(width, height);

  /// Total page width excluding margins.
  double get availableWidth => width - marginLeft - marginRight;

  /// Total page height excluding margins.
  double get availableHeight => height - marginTop - marginBottom;

  /// Total page dimensions excluding margins.
  PdfPoint get availableDimension => PdfPoint(availableWidth, availableHeight);

  /// Landscape orientation variant.
  PdfPageFormat get landscape =>
      width >= height ? this : copyWith(width: height, height: width);

  /// Portrait orientation variant.
  PdfPageFormat get portrait =>
      height >= width ? this : copyWith(width: height, height: width);

  /// Applies minimum margins to this format.
  PdfPageFormat applyMargin(
          {required double left,
          required double top,
          required double right,
          required double bottom}) =>
      copyWith(
        marginLeft: math.max(marginLeft, left),
        marginTop: math.max(marginTop, top),
        marginRight: math.max(marginRight, right),
        marginBottom: math.max(marginBottom, bottom),
      );

  @override
  String toString() {
    return '$runtimeType ${width}x$height margins:$marginLeft, $marginTop, $marginRight, $marginBottom';
  }

  @override
  bool operator ==(Object other) {
    if (other is! PdfPageFormat) {
      return false;
    }

    return other.width == width &&
        other.height == height &&
        other.marginLeft == marginLeft &&
        other.marginTop == marginTop &&
        other.marginRight == marginRight &&
        other.marginBottom == marginBottom;
  }

  @override
  int get hashCode => toString().hashCode;
}
