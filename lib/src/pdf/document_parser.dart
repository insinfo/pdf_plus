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

import 'dart:typed_data';

import 'document.dart';
import 'format/object_base.dart';
import 'io/pdf_random_access_reader.dart';
import 'io/pdf_random_access_reader_cache.dart';
import 'parsing/pdf_document_info.dart';

/// Base class for loading an existing PDF document.
abstract class PdfDocumentParserBase {
  /// Create a Document loader instance
  PdfDocumentParserBase(
    PdfRandomAccessReader reader, {
    bool enableCache = true,
    int cacheBlockSize = 256 * 1024,
    int cacheMaxBlocks = 32,
  }) : reader = enableCache
            ? PdfCachedRandomAccessReader(
                reader,
                blockSize: cacheBlockSize,
                maxBlocks: cacheMaxBlocks,
              )
            : reader;

  /// Create a Document loader instance from bytes
  PdfDocumentParserBase.fromBytes(
    Uint8List bytes, {
    bool enableCache = true,
    int cacheBlockSize = 256 * 1024,
    int cacheMaxBlocks = 32,
  }) : reader = enableCache
            ? PdfCachedRandomAccessReader(
                PdfMemoryRandomAccessReader(bytes),
                blockSize: cacheBlockSize,
                maxBlocks: cacheMaxBlocks,
              )
            : PdfMemoryRandomAccessReader(bytes);

  /// Random access reader
  final PdfRandomAccessReader reader;

  /// The existing PDF document content
  Uint8List get bytes => _cachedBytes ??= reader.readAll();
  Uint8List? _cachedBytes;

  /// The objects size of the existing PDF document
  int get size;

  /// The offset of the previous cross reference table
  int get xrefOffset;

  PdfVersion get version => PdfVersion.pdf_1_4;

  /// Import the existing objects into the new PDF document
  void mergeDocument(PdfDocument pdfDocument);

  PdfSignatureFieldEditContext extractSignatureFieldEditContext() =>
      const PdfSignatureFieldEditContext(fields: []);
}
