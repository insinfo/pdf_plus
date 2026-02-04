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

import 'point.dart';

@immutable
/// Immutable rectangle in PDF user space.
class PdfRect {
  /// Creates a rectangle from left, bottom, width and height.
  const PdfRect(this.left, this.bottom, this.width, this.height);

  /// Creates a rectangle from left, bottom, right, top (deprecated).
  @Deprecated('Use PdfRect.fromLBRT instead')
  factory PdfRect.fromLTRB(
      double left, double bottom, double right, double top) = PdfRect.fromLBRT;

  /// Creates a rectangle from left, bottom, right and top.
  factory PdfRect.fromLBRT(
      double left, double bottom, double right, double top) {
    return PdfRect(left, bottom, right - left, top - bottom);
  }

  /// Creates a rectangle from left, top, width and height.
  factory PdfRect.fromLTWH(
      double left, double top, double width, double height) {
    return PdfRect(left, top, width, height);
  }

  /// Creates a rectangle from origin and size points.
  factory PdfRect.fromPoints(PdfPoint offset, PdfPoint size) {
    return PdfRect(offset.x, offset.y, size.x, size.y);
  }

  /// Left coordinate in PDF user space.
  final double left, bottom, width, height;

  /// The zero rectangle at origin.
  static const PdfRect zero = PdfRect(0, 0, 0, 0);

  /// Left coordinate (deprecated alias).
  @Deprecated('Use left instead')
  double get x => left;

  /// Bottom coordinate (deprecated alias).
  @Deprecated('Use bottom instead')
  double get y => bottom;

  /// Right coordinate.
  double get right => left + width;

  /// Top coordinate.
  double get top => bottom + height;

  /// Horizontal center (deprecated alias).
  @Deprecated('type => horizontalCenter')
  double get horizondalCenter => horizontalCenter;

  /// Horizontal center.
  double get horizontalCenter => left + width / 2;

  /// Vertical center.
  double get verticalCenter => bottom + height / 2;

  @override
  String toString() => 'PdfRect($left, $bottom, $width, $height)';

  /// Scales the rectangle by [factor].
  PdfRect operator *(double factor) {
    return PdfRect(
        left * factor, bottom * factor, width * factor, height * factor);
  }

  /// Returns the rectangle origin as a point.
  PdfPoint get offset => PdfPoint(left, bottom);

  /// Returns the rectangle size as a point.
  PdfPoint get size => PdfPoint(width, height);

  /// Top-left point (deprecated alias).
  @Deprecated('Use leftBottom instead')
  PdfPoint get topLeft => PdfPoint(left, bottom);
  /// Left-bottom point.
  PdfPoint get leftBottom => PdfPoint(left, bottom);

  /// Top-right point (deprecated alias).
  @Deprecated('Use rightBottom instead')
  PdfPoint get topRight => PdfPoint(right, bottom);
  /// Right-bottom point.
  PdfPoint get rightBottom => PdfPoint(right, bottom);

  /// Bottom-left point (deprecated alias).
  @Deprecated('Use leftTop instead')
  PdfPoint get bottomLeft => PdfPoint(left, top);
  /// Left-top point.
  PdfPoint get leftTop => PdfPoint(left, top);

  /// Bottom-right point (deprecated alias).
  @Deprecated('Use rightTop instead')
  PdfPoint get bottomRight => PdfPoint(right, top);
  /// Right-top point.
  PdfPoint get rightTop => PdfPoint(right, top);

  /// Returns a new rectangle with edges moved outwards by the given delta.
  PdfRect inflate(double delta) {
    return PdfRect.fromLBRT(
        left - delta, bottom - delta, right + delta, top + delta);
  }

  /// Returns a new rectangle with edges moved inwards by the given delta.
  PdfRect deflate(double delta) => inflate(-delta);

  /// Returns a copy with the provided values replaced.
  PdfRect copyWith({
    @Deprecated('Use left instead') double? x,
    double? left,
    @Deprecated('Use bottom instead') double? y,
    double? bottom,
    double? width,
    double? height,
  }) {
    return PdfRect(
      left ?? x ?? this.left,
      bottom ?? y ?? this.bottom,
      width ?? this.width,
      height ?? this.height,
    );
  }
}
