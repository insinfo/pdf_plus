import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

Uint8List asset(String name) =>
    File('test/assets/pdfs/$name').readAsBytesSync();

void main() {
  group('propriedades de documento novo', () {
    test('grava e relê /Info', () async {
      final document = PdfDocument();
      PdfPage(document, pageFormat: PdfPageFormat.a4);

      PdfDocumentProperties(document).setInfo(
        title: 'Relatório',
        author: 'Isaque',
      );
      final bytes = await document.save(useIsolate: false);

      final reloaded = PdfDocument.parseFromBytes(bytes);
      final info = PdfDocumentProperties(reloaded).readInfo();
      expect(info['/Title'], 'Relatório');
      expect(info['/Author'], 'Isaque');
    });

    test('define modo de abertura, disposição e idioma', () async {
      final document = PdfDocument();
      PdfPage(document, pageFormat: PdfPageFormat.a4);

      PdfDocumentProperties(document)
        ..pageMode = PdfPageMode.outlines
        ..pageLayout = PdfPageLayout.twoColumnLeft
        ..language = 'pt-BR';

      final bytes = await document.save(useIsolate: false);
      final properties =
          PdfDocumentProperties(PdfDocument.parseFromBytes(bytes));

      expect(properties.pageMode, PdfPageMode.outlines);
      expect(properties.pageLayout, PdfPageLayout.twoColumnLeft);
      expect(properties.language, 'pt-BR');
    });

    test('abre em uma página escolhida', () async {
      final document = PdfDocument();
      PdfPage(document, pageFormat: PdfPageFormat.a4);
      final segunda = PdfPage(document, pageFormat: PdfPageFormat.a4);
      PdfPage(document, pageFormat: PdfPageFormat.a4);

      PdfDocumentProperties(document).openAt(segunda);
      final bytes = await document.save(useIsolate: false);

      final properties =
          PdfDocumentProperties(PdfDocument.parseFromBytes(bytes));
      expect(properties.openAtPageIndex, 1);
    });

    test('preferência do visualizador vai e volta', () async {
      final document = PdfDocument();
      PdfPage(document, pageFormat: PdfPageFormat.a4);

      PdfDocumentProperties(document)
        ..setViewerPreference('/DisplayDocTitle', true)
        ..setViewerPreference('/HideToolbar', false);

      final bytes = await document.save(useIsolate: false);
      final properties =
          PdfDocumentProperties(PdfDocument.parseFromBytes(bytes));

      expect(properties.viewerPreference('/DisplayDocTitle'), isTrue);
      expect(properties.viewerPreference('/HideToolbar'), isFalse);
      expect(properties.viewerPreference('/FitWindow'), isNull);
    });
  });

  group('propriedades de documento carregado', () {
    test('lê o que já existe no arquivo', () {
      final properties =
          PdfDocumentProperties(PdfDocument.parseFromBytes(asset('termo.pdf')));

      // O arquivo declara /Lang e /ViewerPreferences.
      expect(properties.language, isNotNull);
      expect(properties.readXmp(), isNotNull);
    });

    test('altera preferência preservando as que já estavam lá', () async {
      final document = PdfDocument.parseFromBytes(asset('termo.pdf'));
      final before = PdfDocumentProperties(document);
      final existing = before.viewerPreference('/DisplayDocTitle');

      before.setViewerPreference('/HideToolbar', true);
      final bytes = await document.save(useIsolate: false);

      final after =
          PdfDocumentProperties(PdfDocument.parseFromBytes(bytes));
      expect(after.viewerPreference('/HideToolbar'), isTrue);
      expect(after.viewerPreference('/DisplayDocTitle'), existing,
          reason: 'a preferência que já existia não pode sumir');
    });

    test('acrescenta metadados sem perder o conteúdo do documento', () async {
      final source = asset('termo.pdf');
      final document = PdfDocument.parseFromBytes(source);
      final paginas = document.pdfPageList.pages.length;

      PdfDocumentProperties(document).setInfo(title: 'Documento revisado');
      final bytes = await document.save(useIsolate: false);

      final reloaded = PdfDocument.parseFromBytes(bytes);
      expect(reloaded.pdfPageList.pages.length, paginas);
      expect(
        PdfDocumentProperties(reloaded).readInfo()['/Title'],
        'Documento revisado',
      );
    });

    test('abre em uma página de documento carregado', () async {
      final document = PdfDocument.parseFromBytes(asset('termo.pdf'));
      PdfDocumentProperties(document).openAt(
        document.pdfPageList.pages.last,
        view: PdfOpenActionView.xyz,
        top: 800,
      );

      final bytes = await document.save(useIsolate: false);
      final properties =
          PdfDocumentProperties(PdfDocument.parseFromBytes(bytes));
      expect(properties.openAtPageIndex,
          PdfDocument.parseFromBytes(bytes).pdfPageList.pages.length - 1);
    });
  });
}
