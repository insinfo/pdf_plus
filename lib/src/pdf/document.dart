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

import 'dart:typed_data';

import 'package:pdf_plus/src/pdf/parsing/pdf_document_parser.dart';
import 'crypto/pdf_crypto.dart';
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
import 'package:pdf_plus/src/pdf/pdf_names.dart';

/// Display hint for the PDF viewer.
enum PdfPageMode {
  /// Opens with only the page visible (default).
  none,

  /// Opens with the outline panel visible.
  outlines,

  /// Opens with page thumbnails visible.
  thumbs,

  /// Opens in full screen mode.
  fullscreen
}

/// Core PDF document model used to create and serialize PDF files.
///
/// Create a [PdfDocument], add pages and objects, then call [save] to
/// generate the final bytes.
class PdfDocument {
  /// Creates a new PDF document.
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

  /// Parses a PDF from a random access reader.
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

  /// Parses a PDF from in-memory bytes.
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

  /// Loads a PDF using an existing parser.
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

  /// The serial number counter for new indirect objects.
  int _objser;

  /// Current object serial number.
  int get objser => _objser;

  /// All indirect objects that belong to this document.
  final Set<PdfObject> objects = <PdfObject>{};

  /// The document catalog object.
  late final PdfCatalog catalog;

  /// PDF generation settings.
  late final PdfSettings settings;

  /// PDF version to generate.
  @Deprecated('Use settings.version')
  PdfVersion get version => settings.version;

  /// The /Info dictionary if present.
  PdfInfo? _info;

  /// The /Info dictionary (deprecated).
  @Deprecated('This can safely be removed.')
  PdfInfo? get info => _info;

  /// Sets the /Info dictionary (deprecated).
  @Deprecated('This can safely be removed.')
  set info(PdfInfo? value) => _info = value;

  /// Page tree root.
  PdfPageList get pdfPageList => catalog.pdfPageList;

  /// Name tree dictionary.
  PdfNames get pdfNames {
    catalog.names ??= PdfNames(this);
    return catalog.names!;
  }

  /// Default border for annotations, used during serialization.
  PdfObject? defaultOutlineBorder;

  /// Stream compression callback (deprecated).
  ///
  /// Use `deflate: zlib.encode` if using `dart:io`. Null disables compression.
  @Deprecated('Use settings.deflate')
  DeflateCallback? get deflate => settings.deflate;

  /// Encryption configuration for the document.
  PdfEncryption? encryption;

  /// Document-level signature object.
  PdfSignature? sign;

  /// DSS data (LTV).
  PdfDssData? dss;

  /// Graphics state registry (opacity and transfer modes).
  PdfGraphicStates? _graphicStates;

  /// PDF specification version string.
  final String versionString = '1.7';

  /// Fonts registered in this document.
  final Set<PdfFont> fonts = <PdfFont>{};

  PdfSignatureFieldEditor? _signatureEditor;

  PdfAcroForm? _acroForm;

  Uint8List? _documentID;

  /// Whether compression is enabled (deprecated).
  @Deprecated('Use settings.compress')
  bool get compress => settings.deflate != null;

  /// Whether verbose output is enabled (deprecated).
  @Deprecated('Use settings.verbose')
  bool get verbose => settings.verbose;

  /// Generates or returns the document ID.
  Uint8List get documentID {
    if (_documentID == null) {
      final now = Uint8List.fromList(DateTime.now().toIso8601String().codeUnits);
      final random = PdfCrypto.randomBytes(32);
      final seed = Uint8List(now.length + random.length);
      seed.setRange(0, now.length, now);
      seed.setRange(now.length, seed.length, random);
      _documentID = PdfCrypto.sha256(seed);
    }

    return _documentID!;
  }

  /// Allocates a new indirect object serial number.
  int genSerial() => _objser++;

  /// Returns a specific page by index.
  PdfPage? page(int page) {
    return pdfPageList.pages[page];
  }

  /// The document outline root.
  PdfOutline get outline {
    catalog.outlines ??= PdfOutline(this);
    return catalog.outlines!;
  }

  /// Updates /Info metadata fields.
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

  /// Removes a page by index (safe incremental edit).
  void removePageAt(int index) {
    if (index < 0 || index >= pdfPageList.pages.length) {
      throw RangeError.index(index, pdfPageList.pages, 'index');
    }
    final page = pdfPageList.pages.removeAt(index);
    page.inUse = false;
  }

  /// Page label tree root.
  PdfPageLabels get pageLabels {
    catalog.pageLabels ??= PdfPageLabels(this);
    return catalog.pageLabels!;
  }

  /// Initializes DSS data if needed.
  void ensureDss() {
    dss ??= PdfDssData(this);
  }

  /// Signature field manager (AcroForm).
  ///
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

  /// AcroForm manager for general form fields.
  PdfAcroForm get form {
    _acroForm ??= PdfAcroForm(this);
    return _acroForm!;
  }

  /// Graphic states for opacity and transfer modes.
  PdfGraphicStates get graphicStates {
    _graphicStates ??= PdfGraphicStates(this);
    return _graphicStates!;
  }

  /// Whether this document has any graphic states.
  bool get hasGraphicStates => _graphicStates != null;

  /// Writes the document to an output stream.
  Future<void> output(
    PdfStream os, {
    bool enableEventLoopBalancing = false,
  }) async {
    PdfSignature? signature;

    final xref = PdfXrefTable(lastObjectId: _objser);

    for (final ob in objects.where((e) => e.inUse)) {
      ob.prepare();
      if (ob is PdfInfo) {
        xref.params[PdfNameTokens.info] = ob.ref();
      } else if (ob is PdfEncryption) {
        xref.params[PdfNameTokens.encrypt] = ob.ref();
      } else if (ob is PdfSignature) {
        assert(signature == null, 'Only one document signature is allowed');
        signature = ob;
      }
      xref.objects.add(ob);
    }

    final id =
        PdfString(documentID, format: PdfStringFormat.binary, encrypted: false);
    xref.params[PdfNameTokens.id] = PdfArray([id, id]);

    if (prev != null) {
      xref.params[PdfNameTokens.prev] = PdfNum(prev!.xrefOffset);
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

  /// Generates the PDF document as a memory buffer.
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

  /// Adds a URI annotation to the given page.
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

  /// Adds a signature field at the given bounds.
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

  /// Adds a URI annotation using top-left coordinates.
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

  /// Adds a signature field using top-left coordinates.
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

  /// Converts top-left coordinates into PDF user space.
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
  /// Creates a signature field editor for a document.
  PdfSignatureFieldEditor({
    required this.document,
    required this.context,
  });

  /// The owning document.
  final PdfDocument document;
  /// The edit context backing the field list.
  final PdfSignatureFieldEditContext context;

  /// All signature fields.
  List<PdfSignatureFieldObjectInfo> get fields => context.fields;

  /// Finds a signature field by name.
  PdfSignatureFieldObjectInfo? findByName(String name) {
    for (final field in context.fields) {
      if (field.info.fieldName == name) return field;
    }
    return null;
  }

  /// Renames a field by name.
  bool renameFieldByName(String currentName, String newName) {
    final field = findByName(currentName);
    if (field == null) return false;
    return renameField(field, newName);
  }

  /// Removes a field by name.
  bool removeFieldByName(String name) {
    final field = findByName(name);
    if (field == null) return false;
    return removeField(field);
  }

  /// Renames a field.
  bool renameField(PdfSignatureFieldObjectInfo field, String newName) {
    final updated = PdfDict<PdfDataType>.values(
      Map<String, PdfDataType>.from(field.fieldDict.values),
    );
    updated[PdfNameTokens.t] = PdfString.fromString(newName);
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

  /// Updates metadata stored in the field dictionary.
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
      updated[PdfNameTokens.reason] = PdfString.fromString(reason);
    }
    if (location != null) {
      updated[PdfNameTokens.location] = PdfString.fromString(location);
    }
    if (name != null) {
      updated[PdfNameTokens.name] = PdfString.fromString(name);
    }
    if (signingTimeRaw != null) {
      updated[PdfNameTokens.m] = PdfString.fromString(signingTimeRaw);
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

  /// Replaces the field dictionary with a prebuilt one.
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

  /// Clears the signature value (/V) for a field.
  bool clearSignatureValue(PdfSignatureFieldObjectInfo field) {
    final updated = PdfDict<PdfDataType>.values(
      Map<String, PdfDataType>.from(field.fieldDict.values),
    );
    updated[PdfNameTokens.v] = const PdfNull();
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

  /// Removes a field from the AcroForm fields array.
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

  /// Adds an empty signature widget to a page.
  PdfAnnotSign addEmptySignatureField({
    required PdfPage page,
    required PdfRect bounds,
    required String fieldName,
  }) {
    final widget = PdfAnnotSign(rect: bounds, fieldName: fieldName);
    PdfAnnot(page, widget);
    return widget;
  }

  /// Writes the updated fields array to the document.
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
    updatedAcroForm[PdfNameTokens.fields] = fields;

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

    document.catalog.params[PdfNameTokens.acroForm] = updatedAcroForm;
    return true;
  }

  /// Removes annotation references to a field from all pages.
  void _removeAnnotationFromPages(PdfIndirectRef fieldRef) {
    for (final page in document.pdfPageList.pages) {
      final annots = page.params[PdfNameTokens.annots];
      if (annots is PdfArray) {
        annots.values.removeWhere((value) {
          return value is PdfIndirect &&
              value.ser == fieldRef.obj &&
              value.gen == fieldRef.gen;
        });
      }
    }
  }

  /// Replaces a direct field entry in the fields array.
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





