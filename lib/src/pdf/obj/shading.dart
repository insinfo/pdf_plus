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

import '../document.dart';
import '../format/array.dart';
import '../format/bool.dart';
import '../format/dict.dart';
import '../format/name.dart';
import '../format/num.dart';
import '../point.dart';
import '../rect.dart';
import 'function.dart';
import 'object.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

enum PdfShadingType { axial, radial }

class PdfShading extends PdfObject<PdfDict> {
  PdfShading(
    PdfDocument pdfDocument, {
    required this.shadingType,
    required this.function,
    required this.start,
    required this.end,
    this.radius0,
    this.radius1,
    this.boundingBox,
    this.extendStart = false,
    this.extendEnd = false,
  }) : super(pdfDocument, params: PdfDict());

  /// Name of the Shading object
  String get name => '/S$objser';

  final PdfShadingType shadingType;

  final PdfBaseFunction function;

  final PdfPoint start;

  final PdfPoint end;

  final PdfRect? boundingBox;

  final bool extendStart;

  final bool extendEnd;

  final double? radius0;

  final double? radius1;

  @override
  void prepare() {
    super.prepare();

    params[PdfNameTokens.shadingtype] = PdfNum(shadingType.index + 2);
    if (boundingBox != null) {
      params[PdfNameTokens.bbox] = PdfArray.fromNum([
        boundingBox!.left,
        boundingBox!.bottom,
        boundingBox!.right,
        boundingBox!.top,
      ]);
    }
    params[PdfNameTokens.antialias] = const PdfBool(true);
    params[PdfNameTokens.colorSpace] = const PdfName(PdfNameTokens.deviceRgb);

    if (shadingType == PdfShadingType.axial) {
      params[PdfNameTokens.coords] = PdfArray.fromNum([start.x, start.y, end.x, end.y]);
    } else if (shadingType == PdfShadingType.radial) {
      assert(radius0 != null);
      assert(radius1 != null);
      params[PdfNameTokens.coords] = PdfArray.fromNum(
          [start.x, start.y, radius0!, end.x, end.y, radius1!]);
    }
    // params[PdfNameTokens.domain] = PdfArray.fromNum(<num>[0, 1]);
    if (extendStart || extendEnd) {
      params[PdfNameTokens.extend] =
          PdfArray(<PdfBool>[PdfBool(extendStart), PdfBool(extendEnd)]);
    }
    params[PdfNameTokens.function] = function.ref();
  }
}





