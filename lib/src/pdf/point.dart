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

/// Immutable point in PDF user space.
@immutable
class PdfPoint {
  /// Creates a point at [x], [y].
  const PdfPoint(this.x, this.y);

  /// X coordinate.
  final double x, y;

  /// The origin point.
  static const PdfPoint zero = PdfPoint(0.0, 0.0);

  @override
  String toString() => 'PdfPoint($x, $y)';

  /// Returns a translated point.
  PdfPoint translate(double offsetX, double offsetY) =>
      PdfPoint(x + offsetX, y + offsetY);
}

@immutable

/// Immutable size with width and height.
class PdfSize {
  /// Creates a size with [width] and [height].
  const PdfSize(this.width, this.height);

  /// Width component.
  final double width;

  /// Height component.
  final double height;

  /// Converts this size to a point.
  PdfPoint toPoint() => PdfPoint(width, height);

  @override
  String toString() => 'PdfSize($width, $height)';
}
