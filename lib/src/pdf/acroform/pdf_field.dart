import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../format/name.dart';
import '../format/num.dart';
import 'pdf_acroform.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

class PdfAcroField {
  PdfAcroField(
      this.dictionary, this.indirectReference, this.name, this.acroForm);

  /// Factory to create the correct field type from a dictionary.
  factory PdfAcroField.create(PdfDict dictionary,
      PdfIndirect? indirectReference, String name, PdfAcroForm acroForm) {
    if (dictionary.containsKey(PdfNameTokens.ft)) {
      final ft = dictionary[PdfNameTokens.ft];
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
        } else if (ft.value == PdfNameTokens.sig) {
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
    if (dictionary.containsKey(PdfNameTokens.ft)) {
      final ft = dictionary[PdfNameTokens.ft];
      if (ft is PdfName) return ft.value;
    }
    return null;
  }

  /// Gets the field flags (/Ff).
  int get flags {
    if (dictionary.containsKey(PdfNameTokens.ff)) {
      final ff = dictionary[PdfNameTokens.ff];
      if (ff is PdfNum) return ff.value.toInt();
    }
    return 0;
  }

  /// Sets the field flags (/Ff).
  set flags(int value) {
    dictionary[PdfNameTokens.ff] = PdfNum(value);
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
    if (dictionary.containsKey(PdfNameTokens.rect)) {
      final r = dictionary[PdfNameTokens.rect];
      if (r is PdfArray && r.values.length >= 4) {
        return r.values.map((e) => (e as PdfNum).value.toDouble()).toList();
      }
    }
    return null;
  }

  /// Sets the rectangle (/Rect) of the field (widget annotation).
  set rect(List<double>? value) {
    if (value != null && value.length >= 4) {
      dictionary[PdfNameTokens.rect] = PdfArray.fromNum(value);
    } else {
      dictionary.values.remove(PdfNameTokens.rect);
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
    if (dictionary.containsKey(PdfNameTokens.maxLen)) {
      final m = dictionary[PdfNameTokens.maxLen];
      if (m is PdfNum) return m.value.toInt();
    }
    return null;
  }

  /// Sets the maximum length of the field's text (/MaxLen).
  set maxLength(int? value) {
    if (value != null) {
      dictionary[PdfNameTokens.maxLen] = PdfNum(value);
    } else {
      dictionary.values.remove(PdfNameTokens.maxLen);
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
    if (dictionary.containsKey(PdfNameTokens.ti)) {
      final t = dictionary[PdfNameTokens.ti];
      if (t is PdfNum) return t.value.toInt();
    }
    return 0;
  }

  set topIndex(int value) {
    dictionary[PdfNameTokens.ti] = PdfNum(value);
  }

  /// Gets the indices (/I) of selected items in a multi-select list.
  List<int> get indices {
    if (dictionary.containsKey(PdfNameTokens.i)) {
      final i = dictionary[PdfNameTokens.i];
      if (i is PdfArray) {
        return i.values.map((e) => (e as PdfNum).value.toInt()).toList();
      }
    }
    return [];
  }

  set indices(List<int> value) {
    dictionary[PdfNameTokens.i] = PdfArray.fromNum(value);
  }
}

class PdfAcroSignatureField extends PdfAcroField {
  PdfAcroSignatureField(
      super.dictionary, super.indirectReference, super.name, super.acroForm);

  /// Sets the value of the signature field.
  /// The value is typically a signature dictionary or an indirect reference to one.
  void setSignatureValue(PdfDataType signature) {
    dictionary[PdfNameTokens.v] = signature;
  }

  /// Gets the Lock dictionary.
  PdfDict? get lock {
    if (dictionary.containsKey(PdfNameTokens.lock)) {
      final l = dictionary[PdfNameTokens.lock];
      if (l is PdfDict) return l;
    }
    return null;
  }

  /// Sets the Lock dictionary.
  set lock(PdfDict? value) {
    if (value != null) {
      dictionary[PdfNameTokens.lock] = value;
    } else {
      dictionary.values.remove(PdfNameTokens.lock);
    }
  }
}
