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

import '../format/array.dart';
import '../format/dict.dart';
import '../format/name.dart';
import '../format/num.dart';
import 'object.dart';
import 'object_stream.dart';
import 'ttffont.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

/// Font descriptor object
class PdfFontDescriptor extends PdfObject<PdfDict> {
  /// Create a Font descriptor object
  PdfFontDescriptor(
    this.ttfFont,
    this.file,
  ) : super(
          ttfFont.pdfDocument,
          params: PdfDict.values({
            PdfNameTokens.type: const PdfName(PdfNameTokens.fontDescriptor),
          }),
        );

  /// File data
  final PdfObjectStream file;

  /// TrueType font
  final PdfTtfFont ttfFont;

  @override
  void prepare() {
    super.prepare();

    params[PdfNameTokens.fontname] = PdfName('/${ttfFont.fontName}');
    params[PdfNameTokens.fontfile2] = file.ref();
    params[PdfNameTokens.flags] = PdfNum(ttfFont.font.unicode ? 4 : 32);
    params[PdfNameTokens.fontbbox] = PdfArray.fromNum(<int>[
      (ttfFont.font.xMin / ttfFont.font.unitsPerEm * 1000).toInt(),
      (ttfFont.font.yMin / ttfFont.font.unitsPerEm * 1000).toInt(),
      (ttfFont.font.xMax / ttfFont.font.unitsPerEm * 1000).toInt(),
      (ttfFont.font.yMax / ttfFont.font.unitsPerEm * 1000).toInt()
    ]);
    params[PdfNameTokens.ascent] = PdfNum((ttfFont.ascent * 1000).toInt());
    params[PdfNameTokens.descent] = PdfNum((ttfFont.descent * 1000).toInt());
    params[PdfNameTokens.italicangle] = const PdfNum(0);
    params[PdfNameTokens.capheight] = const PdfNum(10);
    params[PdfNameTokens.stemv] = const PdfNum(79);
  }
}





