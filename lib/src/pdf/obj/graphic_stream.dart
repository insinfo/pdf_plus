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
import '../graphic_state.dart';
import 'font.dart';
import 'object.dart';
import 'pattern.dart';
import 'shading.dart';
import 'xobject.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

/// Helper functions for graphic objects
mixin PdfGraphicStream on PdfObject<PdfDict> {
  /// Isolated transparency: If this flag is true, objects within the group
  /// shall be composited against a fully transparent initial backdrop;
  /// if false, they shall be composited against the group’s backdrop
  bool isolatedTransparency = false;

  /// Whether the transparency group is a knockout group.
  /// If this flag is false, later objects within the group shall be composited
  /// with earlier ones with which they overlap; if true, they shall be
  /// composited with the group’s initial backdrop and shall overwrite any
  /// earlier overlapping objects.
  bool knockoutTransparency = false;

  /// The fonts associated with this page
  final fonts = <String, PdfFont>{};

  /// The shaders associated with this page
  final shading = <String, PdfShading>{};

  /// The shaders associated with this page
  final patterns = <String, PdfPattern>{};

  /// The xobjects or other images in the pdf
  final xObjects = <String, PdfXObject>{};

  bool _altered = false;
  bool get altered => _altered;
  set altered(bool _) => _altered = true;

  /// Add a font to this graphic object
  void addFont(PdfFont font) {
    if (!fonts.containsKey(font.name)) {
      fonts[font.name] = font;
    }
  }

  /// Add a shader to this graphic object
  void addShader(PdfShading shader) {
    if (!shading.containsKey(shader.name)) {
      shading[shader.name] = shader;
    }
  }

  /// Add a pattern to this graphic object
  void addPattern(PdfPattern pattern) {
    if (!patterns.containsKey(pattern.name)) {
      patterns[pattern.name] = pattern;
    }
  }

  /// Add an XObject to this graphic object
  void addXObject(PdfXObject object) {
    if (!xObjects.containsKey(object.name)) {
      xObjects[object.name] = object;
    }
  }

  /// Get the default font of this graphic object
  PdfFont? getDefaultFont() {
    if (pdfDocument.fonts.isEmpty) {
      PdfFont.helvetica(pdfDocument);
    }

    return pdfDocument.fonts.elementAt(0);
  }

  /// Generate a name for the graphic state object
  String stateName(PdfGraphicState state) {
    return pdfDocument.graphicStates.stateName(state);
  }

  @override
  void prepare() {
    super.prepare();

    // This holds any resources for this page
    final resources = PdfDict();

    if (altered) {
      resources[PdfNameTokens.procset] = PdfArray(const <PdfName>[
        PdfName(PdfNameTokens.pdf),
        PdfName(PdfNameTokens.text),
        PdfName(PdfNameTokens.imageb),
        PdfName(PdfNameTokens.imagec),
      ]);
    }

    // fonts
    if (fonts.isNotEmpty) {
      resources[PdfNameTokens.font] = PdfDict.fromObjectMap(fonts);
    }

    // shaders
    if (shading.isNotEmpty) {
      resources[PdfNameTokens.shading] = PdfDict.fromObjectMap(shading);
    }

    // patterns
    if (patterns.isNotEmpty) {
      resources[PdfNameTokens.pattern] = PdfDict.fromObjectMap(patterns);
    }

    // Now the XObjects
    if (xObjects.isNotEmpty) {
      resources[PdfNameTokens.xObject] = PdfDict.fromObjectMap(xObjects);
    }

    if (pdfDocument.hasGraphicStates && !params.containsKey(PdfNameTokens.group)) {
      // Declare Transparency Group settings
      params[PdfNameTokens.group] = PdfDict.values({
        PdfNameTokens.type: const PdfName(PdfNameTokens.group),
        PdfNameTokens.s: const PdfName(PdfNameTokens.transparency),
        PdfNameTokens.cs: const PdfName(PdfNameTokens.deviceRgb),
        PdfNameTokens.i: PdfBool(isolatedTransparency),
        PdfNameTokens.k: PdfBool(knockoutTransparency),
      });

      resources[PdfNameTokens.extgstate] = pdfDocument.graphicStates.ref();
    }

    if (resources.isNotEmpty) {
      if (params.containsKey(PdfNameTokens.resources)) {
        final res = params[PdfNameTokens.resources];
        if (res is PdfDict) {
          res.merge(resources);
          return;
        }
      }

      params[PdfNameTokens.resources] = resources;
    }
  }
}

/// Graphic XObject
class PdfGraphicXObject extends PdfXObject with PdfGraphicStream {
  /// Creates a Graphic XObject
  PdfGraphicXObject(
    PdfDocument pdfDocument, [
    String? subtype,
  ]) : super(pdfDocument, subtype);
}





