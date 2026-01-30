import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../format/null_value.dart';
import '../format/string.dart';
import '../obj/annotation.dart';
import '../obj/object.dart';
import '../obj/page.dart';
import '../rect.dart';
import '../parsing/pdf_document_info.dart';

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
