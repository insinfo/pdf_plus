/*
 * Copyright (C) 2017, David PHAM-VAN <dev.nfet.net@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import '../document.dart';
import '../format/array.dart';
import '../format/dict.dart';
import '../format/name.dart';
import '../format/num.dart';
import 'annotation.dart';
import 'metadata.dart';
import 'names.dart';
import 'object.dart';
import 'outline.dart';
import 'page_label.dart';
import 'page_list.dart';
import 'pdfa/pdfa_attached_files.dart';
import 'pdfa/pdfa_color_profile.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

/// Pdf Catalog object
class PdfCatalog extends PdfObject<PdfDict> {
  /// This constructs a Pdf Catalog object
  PdfCatalog(
    PdfDocument pdfDocument,
    this.pdfPageList, {
    this.pageMode,
    int objgen = 0,
    int? objser,
  }) : super(
          pdfDocument,
          params: PdfDict.values({
            PdfNameTokens.type: const PdfName(PdfNameTokens.catalog),
          }),
          objser: objser,
          objgen: objgen,
        );

  /// The pages of the document
  final PdfPageList pdfPageList;

  /// The outlines of the document
  PdfOutline? outlines;

  /// The document metadata
  PdfMetadata? metadata;

  /// Colorprofile output intent (Pdf/A)
  PdfaColorProfile? colorProfile;

  /// Attached files (Pdf/A 3b)
  PdfaAttachedFiles? attached;

  /// The initial page mode
  final PdfPageMode? pageMode;

  /// The anchor names
  PdfNames? names;

  /// The page labels of the document
  PdfPageLabels? pageLabels;

  /// These map the page modes just defined to the page modes setting of the Pdf.
  static const List<String> _pdfPageModes = <String>[
    PdfNameTokens.usenone,
    PdfNameTokens.useoutlines,
    PdfNameTokens.usethumbs,
    PdfNameTokens.fullscreen
  ];

  @override
  void prepare() {
    super.prepare();

    /// the PDF specification version, overrides the header version starting from 1.4
    params[PdfNameTokens.version] = PdfName('/${pdfDocument.versionString}');

    params[PdfNameTokens.pages] = pdfPageList.ref();

    // the Outlines object
    if (outlines != null && outlines!.outlines.isNotEmpty) {
      params[PdfNameTokens.outlines] = outlines!.ref();
    }

    if (metadata != null) {
      params[PdfNameTokens.metadata] = metadata!.ref();
    }

    if (attached != null && attached!.isNotEmpty) {
      names!.params.merge(attached!.catalogNames());
      params[PdfNameTokens.af] = attached!.catalogAF();
    }

    // the Names object
    if (names != null) {
      params[PdfNameTokens.names] = names!.ref();
    }

    // the PageLabels object
    if (pageLabels != null && pageLabels!.labels.isNotEmpty) {
      params[PdfNameTokens.pagelabels] = pageLabels!.ref();
    }

    // the /PageMode setting
    if (pageMode != null) {
      params[PdfNameTokens.pagemode] = PdfName(_pdfPageModes[pageMode!.index]);
    }

    if (pdfDocument.sign != null) {
      if (pdfDocument.sign!.value.hasMDP) {
        params[PdfNameTokens.perms] = PdfDict.values({
          PdfNameTokens.docMdp: pdfDocument.sign!.ref(),
        });
      }
    }

    final dss = PdfDict();
    if (pdfDocument.sign != null) {
      if (pdfDocument.sign!.crl.isNotEmpty) {
        dss[PdfNameTokens.crls] = PdfArray.fromObjects(pdfDocument.sign!.crl);
      }
      if (pdfDocument.sign!.cert.isNotEmpty) {
        dss[PdfNameTokens.certs] = PdfArray.fromObjects(pdfDocument.sign!.cert);
      }
      if (pdfDocument.sign!.ocsp.isNotEmpty) {
        dss[PdfNameTokens.ocsps] = PdfArray.fromObjects(pdfDocument.sign!.ocsp);
      }
    }

    if (pdfDocument.dss != null) {
      if (pdfDocument.dss!.crl.isNotEmpty) {
        dss[PdfNameTokens.crls] = PdfArray.fromObjects(pdfDocument.dss!.crl);
      }
      if (pdfDocument.dss!.cert.isNotEmpty) {
        dss[PdfNameTokens.certs] = PdfArray.fromObjects(pdfDocument.dss!.cert);
      }
      if (pdfDocument.dss!.ocsp.isNotEmpty) {
        dss[PdfNameTokens.ocsps] = PdfArray.fromObjects(pdfDocument.dss!.ocsp);
      }
    }

    if (dss.values.isNotEmpty) {
      params[PdfNameTokens.dss] = dss;
    }

    final widgets = <PdfAnnot>[];
    for (final page in pdfDocument.pdfPageList.pages) {
      for (final annot in page.annotations) {
        if (annot.annot.subtype == PdfNameTokens.widget) {
          widgets.add(annot);
        }
      }
    }

    if (widgets.isNotEmpty) {
      final acroForm = (params[PdfNameTokens.acroForm] ??= PdfDict()) as PdfDict;
      acroForm[PdfNameTokens.sigflags] = PdfNum(pdfDocument.sign?.flagsValue ?? 0) |
          (acroForm[PdfNameTokens.sigflags] as PdfNum? ?? const PdfNum(0));
      final fields = (acroForm[PdfNameTokens.fields] ??= PdfArray()) as PdfArray;
      final fontRefs = PdfDict();
      for (final w in widgets) {
        if (w.annot is PdfTextField) {
          // collect textfield font references
          final tf = w.annot as PdfTextField;
          fontRefs.addAll(PdfDict.values({tf.font.name: tf.font.ref()}));
        }
        final ref = w.ref();
        if (!fields.values.contains(ref)) {
          fields.add(ref);
        }
      }
      if (fontRefs.isNotEmpty) {
        acroForm[PdfNameTokens.dr] = PdfDict.values(// "Document Resources"
            {PdfNameTokens.font: fontRefs});
      }
    }

    if (colorProfile != null) {
      params[PdfNameTokens.outputintents] = colorProfile!.outputIntents();
    }
  }
}





