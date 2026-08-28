/*
 * Copyright (C) 2026, Isaque Neves <insinfo2008@gmail.com>
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

/// Content stream analysis: tokenization, reserialization and text extraction
/// with position.
///
/// This is the **reading** side of phase F8 of the editing roadmap. The
/// `parse → operators → write` cycle preserves the meaning of the stream and
/// makes it possible to inspect, measure and locate what is drawn on the page.
///
/// ## Round-trip guarantee
///
/// `PdfContentWriter` re-emits every literal from the original lexeme, so
/// numbers, names, strings and the bytes of inline images come out identical.
/// What changes is the spacing between tokens, normalized to one space between
/// operands and one line break per operator. The guarantee that holds, and
/// that the tests check, is **equivalence under reparsing**:
/// `parse(write(parse(x))) == parse(x)`. It is not byte-for-byte equality, and
/// the library does not claim it is.
///
/// ## Text replacement is out of scope
///
/// There is no API here to change the text of a `Tj`/`TJ`. Doing that properly
/// requires re-encoding the new text in the font used by the operator,
/// checking whether the embedded subset has the glyphs, recomputing the
/// advances and, when it does not, embedding or replacing the whole font —
/// rewriting `/Widths`, `/W`, `/ToUnicode` and the font file itself as well.
/// That is the expensive part of phase F8 and, among the open implementations,
/// in practice only MuPDF does it in full. Shipping a partial version that
/// sometimes corrupts the stream or changes the drawing would be worse than
/// not shipping it. When that half is done, the roadmap plans two names that
/// do not hide the cost: `overlayTextReplacement` (covers and redraws) and
/// `rewriteTextOperators` (only when the font can encode the new text).
library;

export 'pdf_content_font.dart';
export 'pdf_content_lexer.dart';
export 'pdf_content_operator.dart';
export 'pdf_content_parser.dart';
export 'pdf_content_resources.dart';
export 'pdf_content_writer.dart';
export 'pdf_text_extractor.dart';
