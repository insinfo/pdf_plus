import 'dart:io';
import 'dart:typed_data';
import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

void main() {
  group('PdfSignatureFieldEditor', () {
    test('renomeia campo de assinatura existente', () async {
      final Uint8List bytes = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf')
          .readAsBytesSync();
      final parser = PdfDocumentParser(bytes, allowRepair: true);
      final context = parser.extractSignatureFieldEditContext();
      expect(context.fields.isNotEmpty, isTrue);

      final doc = PdfDocument.load(parser);
      final editor = PdfSignatureFieldEditor(document: doc, context: context);

      final original = context.fields.first.info.fieldName;
      expect(original, isNotNull);

      const renamed = 'SignatureRenamed1';
      final ok = editor.renameFieldByName(original!, renamed);
      expect(ok, isTrue);

      final updatedBytes = await doc.save();
      final updatedParser = PdfDocumentParser(updatedBytes);
      final updatedFields = updatedParser.extractSignatureFields();
      expect(updatedFields.any((f) => f.fieldName == renamed), isTrue);
    });

    test('remove campo de assinatura existente', () async {
      final Uint8List bytes = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf')
          .readAsBytesSync();
      final parser = PdfDocumentParser(bytes, allowRepair: true);
      final context = parser.extractSignatureFieldEditContext();
      expect(context.fields.length, greaterThan(0));

      final doc = PdfDocument.load(parser);
      final editor = PdfSignatureFieldEditor(document: doc, context: context);

      final target = context.fields.first.info.fieldName;
      expect(target, isNotNull);

      final ok = editor.removeFieldByName(target!);
      expect(ok, isTrue);

      final updatedBytes = await doc.save();
      final updatedFields = PdfDocumentParser(updatedBytes).extractSignatureFields();
      expect(updatedFields.length, context.fields.length - 1);
    });

    test('adiciona campo de assinatura vazio', () async {
      final Uint8List bytes = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf')
          .readAsBytesSync();
      final parser = PdfDocumentParser(bytes, allowRepair: true);
      final context = parser.extractSignatureFieldEditContext();
      expect(context.fields.isNotEmpty, isTrue);

      final doc = PdfDocument.load(parser);
      final editor = PdfSignatureFieldEditor(document: doc, context: context);

      final page = doc.pdfPageList.pages.first;
      const newField = 'SignatureAdded1';
      editor.addEmptySignatureField(
        page: page,
        bounds: PdfRect.fromLTWH(40, 40, 160, 50),
        fieldName: newField,
      );

      final updatedBytes = await doc.save();
      final updatedFields = PdfDocumentParser(updatedBytes).extractSignatureFields();
      expect(updatedFields.length, context.fields.length + 1);
      expect(updatedFields.any((f) => f.fieldName == newField), isTrue);
    });

    test('atualiza metadados do campo de assinatura', () async {
      final Uint8List bytes = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf')
          .readAsBytesSync();
      final parser = PdfDocumentParser(bytes, allowRepair: true);
      final context = parser.extractSignatureFieldEditContext();
      expect(context.fields.isNotEmpty, isTrue);

      final doc = PdfDocument.load(parser);
      final editor = PdfSignatureFieldEditor(document: doc, context: context);

      final target = context.fields.first;
      final ok = editor.updateFieldMetadata(
        target,
        reason: 'Teste de razão',
        location: 'Local de teste',
        name: 'Signatário Teste',
        signingTimeRaw: 'D:20250130120000-03\'00\'',
      );
      expect(ok, isTrue);

      final updatedBytes = await doc.save();
      final updatedFields = PdfDocumentParser(updatedBytes).extractSignatureFields();
      final updated = updatedFields.firstWhere(
        (f) => f.fieldName == target.info.fieldName,
      );
      expect(updated.reason, 'Teste de razão');
      expect(updated.location, 'Local de teste');
      expect(updated.name, 'Signatário Teste');
      expect(updated.signingTimeRaw, 'D:20250130120000-03\'00\'');
    });

    test('limpa /V para reutilizar o campo de assinatura', () async {
      final Uint8List bytes = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf')
          .readAsBytesSync();
      final parser = PdfDocumentParser(bytes, allowRepair: true);
      final context = parser.extractSignatureFieldEditContext();
      expect(context.fields.isNotEmpty, isTrue);

      final doc = PdfDocument.load(parser);
      final editor = PdfSignatureFieldEditor(document: doc, context: context);

      final target = context.fields.first;
      final ok = editor.clearSignatureValue(target);
      expect(ok, isTrue);

      final updatedBytes = await doc.save();
      final updatedContext = PdfDocumentParser(updatedBytes)
          .extractSignatureFieldEditContext();
      final updated = updatedContext.fields.firstWhere(
        (f) => f.fieldRef != null && target.fieldRef != null
            ? f.fieldRef!.obj == target.fieldRef!.obj
            : f.info.fieldName == target.info.fieldName,
      );
      expect(updated.signatureDict, isNull);
    });
  });
}
