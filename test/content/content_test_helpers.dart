import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/widgets.dart' as pw;

/// Bytes de um PDF do corpus de teste.
Uint8List contentAsset(String name) =>
    File('test/assets/pdfs/$name').readAsBytesSync();

/// Abre um PDF do corpus com reparo habilitado.
PdfDocumentParser openAsset(String name) => openBytes(contentAsset(name));

/// Abre bytes já em memória com reparo habilitado.
PdfDocumentParser openBytes(Uint8List bytes) =>
    PdfDocumentParser(bytes, allowRepair: true);

/// Gera um PDF de uma página com um texto conhecido.
Future<Uint8List> buildSingleTextPdf(
  String text, {
  double fontSize = 24,
  PdfPageFormat format = PdfPageFormat.a4,
}) async {
  final document = pw.Document();
  document.addPage(
    pw.Page(
      pageFormat: format,
      build: (context) => pw.Center(
        child: pw.Text(text, style: pw.TextStyle(fontSize: fontSize)),
      ),
    ),
  );
  return document.save();
}

/// Compara duas listas de operadores elemento a elemento.
bool sameOperators(List<PdfContentOperator> a, List<PdfContentOperator> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Descreve a primeira diferença entre duas listas de operadores.
String describeFirstDifference(
    List<PdfContentOperator> a, List<PdfContentOperator> b) {
  final limit = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < limit; i++) {
    if (a[i] != b[i]) {
      return 'operador $i: "${a[i]}" != "${b[i]}"';
    }
  }
  if (a.length != b.length) {
    return 'quantidade de operadores: ${a.length} != ${b.length}';
  }
  return 'sem diferenças';
}

/// Bytes ASCII de [text], para montar streams sintéticos.
Uint8List ascii(String text) {
  final out = Uint8List(text.length);
  for (var i = 0; i < text.length; i++) {
    out[i] = text.codeUnitAt(i) & 0xFF;
  }
  return out;
}

/// Concatena pedaços de bytes.
Uint8List joinBytes(List<List<int>> parts) {
  final builder = BytesBuilder(copy: false);
  for (final part in parts) {
    builder.add(part);
  }
  return builder.toBytes();
}
