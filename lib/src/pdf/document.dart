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

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/sha256.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_document_parser.dart';
import 'io/pdf_random_access_reader.dart';

import 'document_parser.dart';
import 'format/array.dart';
import 'format/num.dart';
import 'format/object_base.dart';
import 'format/base.dart';
import 'format/stream.dart';
import 'format/string.dart';
import 'format/xref.dart';
import 'format/dict.dart';
import 'format/indirect.dart';
import 'format/null_value.dart';
import 'graphic_state.dart';
import 'graphics.dart';
import 'io/na.dart'
    if (dart.library.io) 'io/vm.dart'
    if (dart.library.js_interop) 'io/js.dart';

import 'obj/annotation.dart';
import 'obj/catalog.dart';
import 'obj/encryption.dart';
import 'obj/font.dart';
import 'obj/info.dart';
import 'obj/names.dart';
import 'obj/object.dart';
import 'obj/outline.dart';
import 'obj/page.dart';
import 'obj/page_label.dart';
import 'obj/page_list.dart';
import 'obj/signature.dart';
import 'rect.dart';
import 'validation/pdf_dss.dart';
import 'acroform/pdf_acroform.dart';
import 'parsing/pdf_document_info.dart';

/// Display hint for the PDF viewer
enum PdfPageMode {
  /// This page mode indicates that the document
  /// should be opened just with the page visible.  This is the default
  none,

  /// This page mode indicates that the Outlines
  /// should also be displayed when the document is opened.
  outlines,

  /// This page mode indicates that the Thumbnails should be visible when the
  /// document first opens.
  thumbs,

  /// This page mode indicates that when the document is opened, it is displayed
  /// in full-screen-mode. There is no menu bar, window controls nor any other
  /// window present.
  fullscreen
}

/// This class is the base of the Pdf generator. A [PdfDocument] class is
/// created for a document, and each page, object, annotation,
/// etc is added to the document.
/// Once complete, the document can be written to a Stream, and the Pdf
/// document's internal structures are kept in sync.
class PdfDocument {
  /// This creates a Pdf document
  PdfDocument({
    PdfPageMode pageMode = PdfPageMode.none,
    DeflateCallback? deflate,
    bool compress = true,
    bool verbose = false,
    PdfVersion version = PdfVersion.pdf_1_5,
  })  : prev = null,
        _objser = 1 {
    settings = PdfSettings(
      deflate: compress ? (deflate ?? defaultDeflate) : null,
      verbose: verbose,
      version: version,
      encryptCallback: (input, object) =>
          encryption?.encrypt(input, object) ?? input,
    );
    // create the catalog
    catalog = PdfCatalog(this, PdfPageList(this), pageMode: pageMode);
  }

  factory PdfDocument.parseFromReader(
    PdfRandomAccessReader reader, {
    bool enableCache = true,
    int cacheBlockSize = 256 * 1024,
    int cacheMaxBlocks = 32,
    bool allowRepair = false,
  }) {
    final parser = PdfDocumentParser.fromReader(
      reader,
      enableCache: enableCache,
      cacheBlockSize: cacheBlockSize,
      cacheMaxBlocks: cacheMaxBlocks,
      allowRepair: allowRepair,
    );
    return PdfDocument.load(parser);
  }

  factory PdfDocument.parseFromBytes(
    Uint8List pdfBytes, {
    bool enableCache = true,
    int cacheBlockSize = 256 * 1024,
    int cacheMaxBlocks = 32,
    bool allowRepair = false,
  }) {
    final parser = PdfDocumentParser(
      pdfBytes,
      enableCache: enableCache,
      cacheBlockSize: cacheBlockSize,
      cacheMaxBlocks: cacheMaxBlocks,
      allowRepair: allowRepair,
    );
    return PdfDocument.load(parser);
  }

  PdfDocument.load(
    this.prev, {
    DeflateCallback? deflate,
    bool compress = true,
    bool verbose = false,
  }) : _objser = prev!.size {
    settings = PdfSettings(
      deflate: compress ? (deflate ?? defaultDeflate) : null,
      verbose: verbose,
      version: prev!.version,
      encryptCallback: (input, object) =>
          encryption?.encrypt(input, object) ?? input,
    );

    // Import the existing document
    prev!.mergeDocument(this);
  }

  final PdfDocumentParserBase? prev;

  /// This is used to allocate objects a unique serial number in the document.
  int _objser;

  int get objser => _objser;

  /// This vector contains each indirect object within the document.
  final Set<PdfObject> objects = <PdfObject>{};

  /// This is the Catalog object, which is required by each Pdf Document
  late final PdfCatalog catalog;

  /// PDF generation settings
  late final PdfSettings settings;

  /// PDF version to generate
  @Deprecated('Use settings.version')
  PdfVersion get version => settings.version;

  /// This is the info object. Although this is an optional object, we
  /// include it.
  PdfInfo? _info;

  @Deprecated('This can safely be removed.')
  PdfInfo? get info => _info;

  @Deprecated('This can safely be removed.')
  set info(PdfInfo? value) => _info = value;

  /// This is the Pages object, which is required by each Pdf Document
  PdfPageList get pdfPageList => catalog.pdfPageList;

  /// The anchor names dictionary
  PdfNames get pdfNames {
    catalog.names ??= PdfNames(this);
    return catalog.names!;
  }

  /// This holds a [PdfObject] describing the default border for annotations.
  /// It's only used when the document is being written.
  PdfObject? defaultOutlineBorder;

  /// Callback to compress the stream in the pdf file.
  /// Use `deflate: zlib.encode` if using dart:io
  /// No compression by default
  @Deprecated('Use settings.deflate')
  DeflateCallback? get deflate => settings.deflate;

  /// Object used to encrypt the document
  PdfEncryption? encryption;

  /// Object used to sign the document
  PdfSignature? sign;

  /// DSS data (LTV)
  PdfDssData? dss;

  /// Graphics state, representing only opacity.
  PdfGraphicStates? _graphicStates;

  /// The PDF specification version
  final String versionString = '1.7';

  /// This holds the current fonts
  final Set<PdfFont> fonts = <PdfFont>{};

  PdfSignatureFieldEditor? _signatureEditor;

  PdfAcroForm? _acroForm;

  Uint8List? _documentID;

  @Deprecated('Use settings.compress')
  bool get compress => settings.deflate != null;

  /// Output a PDF document with comments and formatted data
  @Deprecated('Use settings.verbose')
  bool get verbose => settings.verbose;

  /// Generates the document ID
  Uint8List get documentID {
    if (_documentID == null) {
      final rnd = math.Random.secure();
      _documentID = Uint8List.fromList(sha256
          .convert(DateTime.now().toIso8601String().codeUnits +
              List<int>.generate(32, (_) => rnd.nextInt(256)))
          .bytes);
    }

    return _documentID!;
  }

  /// Creates a new serial number
  int genSerial() => _objser++;

  /// This returns a specific page. It's used mainly when using a
  /// Serialized template file.
  PdfPage? page(int page) {
    return pdfPageList.pages[page];
  }

  /// The root outline
  PdfOutline get outline {
    catalog.outlines ??= PdfOutline(this);
    return catalog.outlines!;
  }

  /// Atualiza os metadados (/Info) do documento.
  void updateInfo({
    String? title,
    String? author,
    String? creator,
    String? subject,
    String? keywords,
    String? producer,
  }) {
    if (_info != null) {
      _info!.inUse = false;
    }
    _info = PdfInfo(
      this,
      title: title,
      author: author,
      creator: creator,
      subject: subject,
      keywords: keywords,
      producer: producer,
    );
  }

  /// Remove uma página pelo índice (edição incremental segura).
  void removePageAt(int index) {
    if (index < 0 || index >= pdfPageList.pages.length) {
      throw RangeError.index(index, pdfPageList.pages, 'index');
    }
    final page = pdfPageList.pages.removeAt(index);
    page.inUse = false;
  }

  /// The root page labels
  PdfPageLabels get pageLabels {
    catalog.pageLabels ??= PdfPageLabels(this);
    return catalog.pageLabels!;
  }

  /// Inicializa DSS quando necessário.
  void ensureDss() {
    dss ??= PdfDssData(this);
  }

  /// Manager for signature fields (Acforms).
  /// Allows finding, renaming, removing, and modifying signature fields.
  PdfSignatureFieldEditor get signatures {
    if (_signatureEditor != null) return _signatureEditor!;
    if (prev == null) {
      _signatureEditor = PdfSignatureFieldEditor(
          document: this,
          context: const PdfSignatureFieldEditContext(
              fields: <PdfSignatureFieldObjectInfo>[]));
    } else {
      _signatureEditor = PdfSignatureFieldEditor(
          document: this, context: prev!.extractSignatureFieldEditContext());
    }
    return _signatureEditor!;
  }

  /// AcroForm manager for handling general form fields (Text, Checkbox, etc).
  PdfAcroForm get form {
    _acroForm ??= PdfAcroForm(this);
    return _acroForm!;
  }

  /// Graphic states for opacity and transfer modes
  PdfGraphicStates get graphicStates {
    _graphicStates ??= PdfGraphicStates(this);
    return _graphicStates!;
  }

  /// This document has at least one graphic state
  bool get hasGraphicStates => _graphicStates != null;

  /// This writes the document to an OutputStream.
  Future<void> output(
    PdfStream os, {
    bool enableEventLoopBalancing = false,
  }) async {
    PdfSignature? signature;

    final xref = PdfXrefTable(lastObjectId: _objser);

    for (final ob in objects.where((e) => e.inUse)) {
      ob.prepare();
      if (ob is PdfInfo) {
        xref.params['/Info'] = ob.ref();
      } else if (ob is PdfEncryption) {
        xref.params['/Encrypt'] = ob.ref();
      } else if (ob is PdfSignature) {
        assert(signature == null, 'Only one document signature is allowed');
        signature = ob;
      }
      xref.objects.add(ob);
    }

    final id =
        PdfString(documentID, format: PdfStringFormat.binary, encrypted: false);
    xref.params['/ID'] = PdfArray([id, id]);

    if (prev != null) {
      xref.params['/Prev'] = PdfNum(prev!.xrefOffset);
    }

    if (enableEventLoopBalancing) {
      await xref.outputAsync(catalog, os);
    } else {
      xref.output(catalog, os);
    }

    if (signature != null) {
      await signature.writeSignature(os);
    }
  }

  /// Generates the PDF document as a memory file.
  ///
  /// Runs in a background isolate when supported (e.g., on Dart VM),
  /// or on the main isolate when isolate support is unavailable
  /// (e.g., on the web).
  ///
  /// If [enableEventLoopBalancing] is `true`, the method yields periodically
  /// during processing to keep the event loop responsive. This helps reduce
  /// blocking when the operation runs on the main isolate.
  ///
  /// Returns a [Uint8List] containing the document data.
  Future<Uint8List> save({
    bool enableEventLoopBalancing = false,
    bool useIsolate = true,
  }) async {
    final computation = () async {
      final os = PdfStream();
      if (prev != null) {
        os.putBytes(prev!.bytes);
      }
      await output(os, enableEventLoopBalancing: enableEventLoopBalancing);
      return os.output();
    };

    if (!useIsolate) {
      return computation();
    }

    return pdfCompute(computation);
  }

  // PdfDocument addAnnotation(
  //     {required PdfAnnot annotation, required int pageNumber}) {
  //   final pageIndex = pageNumber - 1;
  //   if (pageIndex < 0 || pageIndex >= pdfPageList.pages.length) {
  //     throw RangeError.index(pageIndex, pdfPageList.pages, 'pageNumber');
  //   }
  //   final page = pdfPageList.pages[pageIndex];
  //   return this;
  // }

  PdfDocument addUriAnnotation({
    required int pageNumber,
    required PdfRect bounds,
    required String uri,
  }) {
    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, pdfPageList.pages, 'pageNumber');
    }
    final page = pdfPageList.pages[pageIndex];
    PdfAnnot(page, PdfUriAnnotation(bounds: bounds, uri: uri));
    return this;
  }

  // TODO checar se isso esta certo
  PdfDocument addSignatureField({
    required int pageNumber,
    required PdfRect bounds,
    required String fieldName,
    void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance,
  }) {
    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, pdfPageList.pages, 'pageNumber');
    }

    final page = pdfPageList.pages[pageIndex];
    final widget = PdfAnnotSign(rect: bounds, fieldName: fieldName);
    if (drawAppearance != null) {
      final g = widget.appearance(this, PdfAnnotAppearance.normal);
      drawAppearance(g, PdfRect(0, 0, bounds.width, bounds.height));
    }
    PdfAnnot(page, widget);
    return this;
  }

  PdfDocument addUriAnnotationTopLeft({
    required int pageNumber,
    required double left,
    required double top,
    required double width,
    required double height,
    required String uri,
  }) {
    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, pdfPageList.pages, 'pageNumber');
    }
    final page = pdfPageList.pages[pageIndex];
    final bounds = _rectFromTopLeft(
      page,
      left: left,
      top: top,
      width: width,
      height: height,
    );
    PdfAnnot(page, PdfUriAnnotation(bounds: bounds, uri: uri));
    return this;
  }

  PdfDocument addSignatureFieldTopLeft({
    required int pageNumber,
    required double left,
    required double top,
    required double width,
    required double height,
    required String fieldName,
    void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance,
  }) {
    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, pdfPageList.pages, 'pageNumber');
    }

    final page = pdfPageList.pages[pageIndex];
    final bounds = _rectFromTopLeft(
      page,
      left: left,
      top: top,
      width: width,
      height: height,
    );
    final widget = PdfAnnotSign(rect: bounds, fieldName: fieldName);
    if (drawAppearance != null) {
      final g = widget.appearance(this, PdfAnnotAppearance.normal);
      drawAppearance(g, PdfRect(0, 0, bounds.width, bounds.height));
    }
    PdfAnnot(page, widget);
    return this;
  }

  PdfRect _rectFromTopLeft(
    PdfPage page, {
    required double left,
    required double top,
    required double width,
    required double height,
  }) {
    final pageHeight = page.pageFormat.height;
    final bottom = pageHeight - top - height;
    return PdfRect(left, bottom, width, height);
  }
}

class PdfSignatureFieldEditor {
  PdfSignatureFieldEditor({
    required this.document,
    required this.context,
  });

  final PdfDocument document;
  final PdfSignatureFieldEditContext context;

  List<PdfSignatureFieldObjectInfo> get fields => context.fields;

  PdfSignatureFieldObjectInfo? findByName(String name) {
    for (final field in context.fields) {
      if (field.info.fieldName == name) return field;
    }
    return null;
  }

  bool renameFieldByName(String currentName, String newName) {
    final field = findByName(currentName);
    if (field == null) return false;
    return renameField(field, newName);
  }

  bool removeFieldByName(String name) {
    final field = findByName(name);
    if (field == null) return false;
    return removeField(field);
  }

  bool renameField(PdfSignatureFieldObjectInfo field, String newName) {
    final updated = PdfDict<PdfDataType>.values(
      Map<String, PdfDataType>.from(field.fieldDict.values),
    );
    updated['/T'] = PdfString.fromString(newName);
    if (field.fieldRef != null) {
      PdfObject<PdfDict<PdfDataType>>(
        document,
        objser: field.fieldRef!.obj,
        objgen: field.fieldRef!.gen,
        params: updated,
      );
      return true;
    }
    return _replaceDirectField(field, updated);
  }

  bool updateFieldMetadata(
    PdfSignatureFieldObjectInfo field, {
    String? reason,
    String? location,
    String? name,
    String? signingTimeRaw,
  }) {
    final updated = PdfDict<PdfDataType>.values(
      Map<String, PdfDataType>.from(field.fieldDict.values),
    );
    if (reason != null) {
      updated['/Reason'] = PdfString.fromString(reason);
    }
    if (location != null) {
      updated['/Location'] = PdfString.fromString(location);
    }
    if (name != null) {
      updated['/Name'] = PdfString.fromString(name);
    }
    if (signingTimeRaw != null) {
      updated['/M'] = PdfString.fromString(signingTimeRaw);
    }

    if (field.fieldRef != null) {
      PdfObject<PdfDict<PdfDataType>>(
        document,
        objser: field.fieldRef!.obj,
        objgen: field.fieldRef!.gen,
        params: updated,
      );
      return true;
    }
    return _replaceDirectField(field, updated);
  }

  bool updateFieldDict(
    PdfSignatureFieldObjectInfo field,
    PdfDict<PdfDataType> updated,
  ) {
    if (field.fieldRef != null) {
      PdfObject<PdfDict<PdfDataType>>(
        document,
        objser: field.fieldRef!.obj,
        objgen: field.fieldRef!.gen,
        params: updated,
      );
      return true;
    }
    return _replaceDirectField(field, updated);
  }

  bool clearSignatureValue(PdfSignatureFieldObjectInfo field) {
    final updated = PdfDict<PdfDataType>.values(
      Map<String, PdfDataType>.from(field.fieldDict.values),
    );
    updated['/V'] = const PdfNull();
    if (field.fieldRef != null) {
      PdfObject<PdfDict<PdfDataType>>(
        document,
        objser: field.fieldRef!.obj,
        objgen: field.fieldRef!.gen,
        params: updated,
      );
      return true;
    }
    return _replaceDirectField(field, updated);
  }

  bool removeField(PdfSignatureFieldObjectInfo field) {
    final fieldsArray = context.fieldsArray;
    if (fieldsArray == null) return false;

    final updated = PdfArray(List<PdfDataType>.from(fieldsArray.values));
    if (field.fieldRef != null) {
      updated.values.removeWhere((value) {
        return value is PdfIndirect &&
            value.ser == field.fieldRef!.obj &&
            value.gen == field.fieldRef!.gen;
      });
      _removeAnnotationFromPages(field.fieldRef!);
    } else if (field.fieldIndex != null) {
      if (field.fieldIndex! < 0 || field.fieldIndex! >= updated.values.length) {
        return false;
      }
      updated.values.removeAt(field.fieldIndex!);
    } else {
      return false;
    }

    return _writeFieldsArray(updated);
  }

  PdfAnnotSign addEmptySignatureField({
    required PdfPage page,
    required PdfRect bounds,
    required String fieldName,
  }) {
    final widget = PdfAnnotSign(rect: bounds, fieldName: fieldName);
    PdfAnnot(page, widget);
    return widget;
  }

  bool _writeFieldsArray(PdfArray fields) {
    final fieldsRef = context.fieldsRef;
    if (fieldsRef != null) {
      PdfObject<PdfArray>(
        document,
        objser: fieldsRef.obj,
        objgen: fieldsRef.gen,
        params: fields,
      );
      return true;
    }

    final acroFormDict = context.acroFormDict;
    if (acroFormDict == null) return false;

    final updatedAcroForm = PdfDict<PdfDataType>.values(
      Map<String, PdfDataType>.from(acroFormDict.values),
    );
    updatedAcroForm['/Fields'] = fields;

    final acroFormRef = context.acroFormRef;
    if (acroFormRef != null) {
      PdfObject<PdfDict<PdfDataType>>(
        document,
        objser: acroFormRef.obj,
        objgen: acroFormRef.gen,
        params: updatedAcroForm,
      );
      return true;
    }

    document.catalog.params['/AcroForm'] = updatedAcroForm;
    return true;
  }

  void _removeAnnotationFromPages(PdfIndirectRef fieldRef) {
    for (final page in document.pdfPageList.pages) {
      final annots = page.params['/Annots'];
      if (annots is PdfArray) {
        annots.values.removeWhere((value) {
          return value is PdfIndirect &&
              value.ser == fieldRef.obj &&
              value.gen == fieldRef.gen;
        });
      }
    }
  }

  bool _replaceDirectField(
    PdfSignatureFieldObjectInfo field,
    PdfDict<PdfDataType> updated,
  ) {
    final fieldsArray = context.fieldsArray;
    final index = field.fieldIndex;
    if (fieldsArray == null || index == null) return false;
    if (index < 0 || index >= fieldsArray.values.length) return false;
    final updatedArray = PdfArray(List<PdfDataType>.from(fieldsArray.values));
    updatedArray.values[index] = updated;
    return _writeFieldsArray(updatedArray);
  }
}
