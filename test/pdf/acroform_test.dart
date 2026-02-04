import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/acroform/pdf_acroform.dart';
import 'package:pdf_plus/src/pdf/acroform/pdf_field.dart';

import 'package:test/test.dart';

void main() {
  group('PdfAcroForm', () {
    late PdfDocument document;
    late PdfAcroForm acroForm;

    setUp(() {
      document = PdfDocument();
      acroForm = PdfAcroForm(document);
    });

    test('can create and add a text field', () {
      final textField = acroForm.createTextField('user.name');
      expect(textField, isA<PdfAcroTextField>());
      expect(textField.name, 'user.name');
      expect(textField.fieldType, PdfNameTokens.tx);

      final page = PdfPage(document);
      acroForm.addField(textField, page);

      expect(acroForm.fields.containsKey('user.name'), isTrue);
      expect(acroForm.fields['user.name'], same(textField));

      final catalog = document.catalog.params;
      expect(catalog.containsKey(PdfNameTokens.acroForm), isTrue);
    });

    test('can create and add a signature field', () {
      final sigField = acroForm.createSignatureField('signature1');
      expect(sigField, isA<PdfAcroSignatureField>());
      expect(sigField.name, 'signature1');
      expect(sigField.fieldType, PdfNameTokens.sig);

      acroForm.addField(sigField, null);

      expect(acroForm.fields.containsKey('signature1'), isTrue);
    });

    test('PdfField flags', () {
      final textField = acroForm.createTextField('test');

      textField.isMultiline = true;
      expect(textField.isMultiline, isTrue);

      textField.isMultiline = false;
      expect(textField.isMultiline, isFalse);
    });

    test('PdfAcroChoiceField properties', () {
      final choiceField = acroForm.createChoiceField('options');

      choiceField.isCombo = true;
      expect(choiceField.isCombo, isTrue);

      choiceField.topIndex = 5;
      expect(choiceField.topIndex, 5);

      choiceField.indices = [1, 3];
      expect(choiceField.indices, [1, 3]);
    });

    test('flattenFields removes AcroForm from catalog', () {
      final field = acroForm.createTextField('foo');
      acroForm.addField(field, null);

      expect(
          document.catalog.params.containsKey(PdfNameTokens.acroForm), isTrue);

      acroForm.flattenFields();

      expect(
          document.catalog.params.containsKey(PdfNameTokens.acroForm), isFalse);
      expect(acroForm.fields, isEmpty);
    });
  });
}


