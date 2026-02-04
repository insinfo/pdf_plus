import 'package:pdf_plus/src/pdf/parsing/pdf_parser_constants.dart';

import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../format/name.dart';
import '../format/num.dart';
import 'pdf_acroform.dart';

class PdfAcroField {
  PdfAcroField(
      this.dictionary, this.indirectReference, this.name, this.acroForm);

  /// Factory to create the correct field type from a dictionary.
  factory PdfAcroField.create(PdfDict dictionary,
      PdfIndirect? indirectReference, String name, PdfAcroForm acroForm) {
    if (dictionary.containsKey(PdfKeys.ft)) {
      final ft = dictionary[PdfKeys.ft];
      if (ft is PdfName) {
        if (ft.value == '/Tx') {
          return PdfAcroTextField(
              dictionary, indirectReference, name, acroForm);
        } else if (ft.value == '/Btn') {
          return PdfAcroButtonField(
              dictionary, indirectReference, name, acroForm);
        } else if (ft.value == '/Ch') {
          return PdfAcroChoiceField(
              dictionary, indirectReference, name, acroForm);
        } else if (ft.value == '/Sig') {
          return PdfAcroSignatureField(
              dictionary, indirectReference, name, acroForm);
        }
      }
    }
    return PdfAcroField(dictionary, indirectReference, name, acroForm);
  }

  final PdfDict dictionary;
  final PdfIndirect? indirectReference;
  final String name;
  final PdfAcroForm acroForm;

  /// Gets the field type (/FT).
  String? get fieldType {
    if (dictionary.containsKey(PdfKeys.ft)) {
      final ft = dictionary[PdfKeys.ft];
      if (ft is PdfName) return ft.value;
    }
    return null;
  }

  /// Gets the field flags (/Ff).
  int get flags {
    if (dictionary.containsKey(PdfKeys.ff)) {
      final ff = dictionary[PdfKeys.ff];
      if (ff is PdfNum) return ff.value.toInt();
    }
    return 0;
  }

  /// Sets the field flags (/Ff).
  set flags(int value) {
    dictionary[PdfKeys.ff] = PdfNum(value);
  }

  /// Helper to set or clear a specific flag bit.
  void setFieldFlag(int flag, bool value) {
    if (value) {
      flags |= flag;
    } else {
      flags &= ~flag;
    }
  }

  /// Helper to check if a specific flag bit is set.
  bool hasFieldFlag(int flag) {
    return (flags & flag) != 0;
  }

  /// Gets the rectangle (/Rect) of the field (widget annotation).
  List<double>? get rect {
    if (dictionary.containsKey(PdfKeys.rect)) {
      final r = dictionary[PdfKeys.rect];
      if (r is PdfArray && r.values.length >= 4) {
        return r.values.map((e) => (e as PdfNum).value.toDouble()).toList();
      }
    }
    return null;
  }

  /// Sets the rectangle (/Rect) of the field (widget annotation).
  set rect(List<double>? value) {
    if (value != null && value.length >= 4) {
      dictionary[PdfKeys.rect] = PdfArray.fromNum(value);
    } else {
      dictionary.values.remove(PdfKeys.rect);
    }
  }

  @override
  String toString() => 'PdfAcroField(name: $name, type: $fieldType)';
}

class PdfAcroTextField extends PdfAcroField {
  PdfAcroTextField(
      super.dictionary, super.indirectReference, super.name, super.acroForm);

  static const int flagMultiline = 1 << 12; // Bit 13
  static const int flagPassword = 1 << 13; // Bit 14

  /// Whether the field can contain multiple lines of text.
  bool get isMultiline => hasFieldFlag(flagMultiline);
  set isMultiline(bool v) => setFieldFlag(flagMultiline, v);

  /// Whether the field is a password field.
  bool get isPassword => hasFieldFlag(flagPassword);
  set isPassword(bool v) => setFieldFlag(flagPassword, v);

  /// Gets the maximum length of the field's text (/MaxLen).
  int? get maxLength {
    if (dictionary.containsKey(PdfKeys.maxLen)) {
      final m = dictionary[PdfKeys.maxLen];
      if (m is PdfNum) return m.value.toInt();
    }
    return null;
  }

  /// Sets the maximum length of the field's text (/MaxLen).
  set maxLength(int? value) {
    if (value != null) {
      dictionary[PdfKeys.maxLen] = PdfNum(value);
    } else {
      dictionary.values.remove(PdfKeys.maxLen);
    }
  }
}

class PdfAcroButtonField extends PdfAcroField {
  PdfAcroButtonField(
      super.dictionary, super.indirectReference, super.name, super.acroForm);

  static const int flagNoToggleToOff = 1 << 14; // Bit 15
  static const int flagRadio = 1 << 15; // Bit 16
  static const int flagPushbutton = 1 << 16; // Bit 17

  bool get isRadio => hasFieldFlag(flagRadio);
  set isRadio(bool v) => setFieldFlag(flagRadio, v);

  bool get isPushButton => hasFieldFlag(flagPushbutton);
  set isPushButton(bool v) => setFieldFlag(flagPushbutton, v);
}

class PdfAcroChoiceField extends PdfAcroField {
  PdfAcroChoiceField(
      super.dictionary, super.indirectReference, super.name, super.acroForm);

  static const int flagCombo = 1 << 17; // Bit 18
  static const int flagEdit = 1 << 18; // Bit 19

  bool get isCombo => hasFieldFlag(flagCombo);
  set isCombo(bool v) => setFieldFlag(flagCombo, v);

  /// Gets the options (/Opt) for the choice field.
  List<String> get options {
    // TODO: Implement parsing of /Opt (can be array of strings or array of arrays)
    return [];
  }

  /// Gets the top index (/TI).
  int get topIndex {
    if (dictionary.containsKey(PdfKeys.ti)) {
      final t = dictionary[PdfKeys.ti];
      if (t is PdfNum) return t.value.toInt();
    }
    return 0;
  }

  set topIndex(int value) {
    dictionary[PdfKeys.ti] = PdfNum(value);
  }

  /// Gets the indices (/I) of selected items in a multi-select list.
  List<int> get indices {
    if (dictionary.containsKey(PdfKeys.i)) {
      final i = dictionary[PdfKeys.i];
      if (i is PdfArray) {
        return i.values.map((e) => (e as PdfNum).value.toInt()).toList();
      }
    }
    return [];
  }

  set indices(List<int> value) {
    dictionary[PdfKeys.i] = PdfArray.fromNum(value);
  }
}

class PdfAcroSignatureField extends PdfAcroField {
  PdfAcroSignatureField(
      super.dictionary, super.indirectReference, super.name, super.acroForm);

  /// Sets the value of the signature field.
  /// The value is typically a signature dictionary or an indirect reference to one.
  void setSignatureValue(PdfDataType signature) {
    dictionary[PdfKeys.v] = signature;
  }

  /// Gets the Lock dictionary.
  PdfDict? get lock {
    if (dictionary.containsKey(PdfKeys.lock)) {
      final l = dictionary[PdfKeys.lock];
      if (l is PdfDict) return l;
    }
    return null;
  }

  /// Sets the Lock dictionary.
  set lock(PdfDict? value) {
    if (value != null) {
      dictionary[PdfKeys.lock] = value;
    } else {
      dictionary.values.remove(PdfKeys.lock);
    }
  }
}
