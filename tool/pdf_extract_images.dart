import 'dart:io';

import '../lib/src/pdf/io/pdf_random_access_reader_io.dart';
import '../lib/src/pdf/parsing/pdf_document_parser.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('Uso: dart tool/pdf_extract_images.dart <arquivo.pdf> [saida] [--from=N] [--to=N]');
    exitCode = 2;
    return;
  }

  final opts = _parseArgs(args);
  final inputPath = opts.inputPath;
  final file = File(inputPath);
  if (!file.existsSync()) {
    stderr.writeln('Arquivo não encontrado: $inputPath');
    exitCode = 2;
    return;
  }

  final outputDir = opts.outputDir ?? _defaultOutputDir(inputPath);

  final out = Directory(outputDir);
  if (!out.existsSync()) {
    out.createSync(recursive: true);
  }

  final reader = PdfRandomAccessFileReader.openSync(file);
  final parser = PdfDocumentParser.fromReader(reader, allowRepair: true);
  final images = parser.extractImages(
    fromPage: opts.fromPage,
    toPage: opts.toPage,
    includeUnusedXObjects: true,
  );

  int saved = 0;
  for (int i = 0; i < images.length; i++) {
    final img = images[i];
    if (opts.fromPage != null && img.pageIndex < opts.fromPage!) {
      continue;
    }
    if (opts.toPage != null && img.pageIndex > opts.toPage!) {
      continue;
    }
    final data = parser.readStreamData(img.imageRef);
    if (data == null) {
      continue;
    }

    final ext = _extensionForFilter(img.filter);
    final filename = _buildFileName(i + 1, img.pageIndex, img.imageRef, ext);
    final path = _joinPath(out.path, filename);
    File(path).writeAsBytesSync(data, flush: false);
    saved++;
  }

  reader.close();
  stdout.writeln('Extraídas $saved imagens para: ${out.path}');
}

_ExtractOptions _parseArgs(List<String> args) {
  final inputPath = args[0];
  String? outputDir;
  int? fromPage;
  int? toPage;

  for (int i = 1; i < args.length; i++) {
    final arg = args[i];
    if (arg.startsWith('--from=')) {
      fromPage = int.tryParse(arg.substring(7));
      continue;
    }
    if (arg.startsWith('--to=')) {
      toPage = int.tryParse(arg.substring(5));
      continue;
    }
    if (!arg.startsWith('--') && outputDir == null) {
      outputDir = arg;
      continue;
    }
  }

  return _ExtractOptions(
    inputPath: inputPath,
    outputDir: outputDir,
    fromPage: fromPage,
    toPage: toPage,
  );
}

class _ExtractOptions {
  const _ExtractOptions({
    required this.inputPath,
    this.outputDir,
    this.fromPage,
    this.toPage,
  });

  final String inputPath;
  final String? outputDir;
  final int? fromPage;
  final int? toPage;
}

String _defaultOutputDir(String inputPath) {
  final file = File(inputPath);
  final base = file.path;
  return '${base}_images';
}

String _extensionForFilter(String? filter) {
  switch (filter) {
    case 'DCT':
      return 'jpg';
    case 'JPX':
      return 'jp2';
    case 'JBIG2':
      return 'jb2';
    case 'CCITTFax':
      return 'tif';
    case 'Flate':
      return 'flate';
    default:
      return 'bin';
  }
}

String _buildFileName(
  int index,
  int pageIndex,
  dynamic imageRef,
  String ext,
) {
  return 'page${pageIndex}_img${index}_${imageRef.toString().replaceAll(' ', '_')}.$ext';
}

String _joinPath(String a, String b) {
  final sep = Platform.pathSeparator;
  if (a.endsWith(sep)) return '$a$b';
  return '$a$sep$b';
}
