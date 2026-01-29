import 'dart:io';

import '../lib/src/pdf/io/pdf_random_access_reader_io.dart';
import '../lib/src/pdf/parsing/pdf_document_info.dart';
import '../lib/src/pdf/parsing/pdf_document_parser.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Uso: dart tool/pdf_info.dart <arquivo.pdf>');
    exitCode = 2;
    return;
  }

  final path = args.join(' ');
  final file = File(path);
  if (!file.existsSync()) {
    stderr.writeln('Arquivo não encontrado: $path');
    exitCode = 2;
    return;
  }

  final reader = PdfRandomAccessFileReader.openSync(file);
  final parser = PdfDocumentParser.fromReader(reader);
  final info = parser.extractInfo();

  stdout.writeln('$path:');
  stdout.writeln('\nPDF-${info.version}');

  if (info.infoDict != null && info.infoDict!.isNotEmpty) {
    if (info.infoRef != null) {
      stdout.writeln('Info object (${info.infoRef}):');
    } else {
      stdout.writeln('Info object:');
    }
    stdout.writeln(_formatInfoDict(info.infoDict));
  }

  stdout.writeln('Pages: ${info.pageCount}');
  stdout.writeln('\nNot a ZUGFeRD file.');
  stdout.writeln('Retrieving info from pages 1-${info.pageCount}...');

  final mediaBoxIndex = <String, PdfPageMediaBoxInfo>{};
  for (final entry in info.mediaBoxes) {
    final key = entry.box.map(_fmtNum).join(' ');
    mediaBoxIndex.putIfAbsent(key, () => entry);
  }

  stdout.writeln('Mediaboxes (${mediaBoxIndex.length}):');
  for (final entry in mediaBoxIndex.values) {
    final box = entry.box.map(_fmtNum).join(' ');
    stdout.writeln('        ${entry.pageIndex}       (${entry.pageRef}):        [ $box ]');
  }

  stdout.writeln('\nImages (${info.images.length}):');
  for (int i = 0; i < info.images.length; i++) {
    final img = info.images[i];
    final filter = img.filter ?? '?';
    final bpc = img.bitsPerComponent?.toString() ?? '?';
    final cs = img.colorSpace ?? '?';
    final w = img.width?.toString() ?? '?';
    final h = img.height?.toString() ?? '?';
    stdout.writeln(
        '        ${i + 1}       (${img.pageRef}):        [ $filter ] ${w}x${h} ${bpc}bpc $cs (${img.imageRef})');
  }

  reader.close();
}

String _formatInfoDict(Map<String, String>? dict) {
  if (dict == null || dict.isEmpty) return '<<>>';
  final buffer = StringBuffer('<<');
  dict.forEach((k, v) {
    buffer.write('$k(${_escapeInfo(v)})');
  });
  buffer.write('>>');
  return buffer.toString();
}

String _escapeInfo(String value) {
  return value
      .replaceAll('\\', '\\\\')
      .replaceAll('(', '\\(')
      .replaceAll(')', '\\)');
}

String _fmtNum(num value) {
  if (value is int) return value.toString();
  if (value is double) {
    var s = value.toStringAsFixed(2);
    if (s.contains('.')) {
      s = s.replaceFirst(RegExp(r'(\.\d*?[1-9])0+$'), r'$1');
      s = s.replaceFirst(RegExp(r'\.0+$'), '');
    }
    return s;
  }
  return value.toString();
}