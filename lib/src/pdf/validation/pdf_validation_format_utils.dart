import 'dart:typed_data';

import '../../utils/convert/hex/hex_case.dart';

DateTime? parsePdfDateLocal(String? raw) {
  final parts = _parsePdfDateParts(raw);
  if (parts == null) return null;
  return DateTime(
    parts.year,
    parts.month,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second,
  );
}

DateTime? parsePdfDateToUtc(String? raw) {
  final parts = _parsePdfDateParts(raw);
  if (parts == null) return null;
  final utc = DateTime.utc(
    parts.year,
    parts.month,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second,
  );
  if (parts.offsetSign == 0) return utc;
  final offset =
      Duration(hours: parts.offsetHours, minutes: parts.offsetMinutes);
  return utc.subtract(parts.offsetSign > 0 ? offset : -offset);
}

_ParsedPdfDate? _parsePdfDateParts(String? raw) {
  if (raw == null) return null;
  var text = raw.trim();
  if (text.isEmpty) return null;
  if (text.startsWith('D:')) {
    text = text.substring(2);
  }
  final digits = RegExp(r'^\d{4,14}').firstMatch(text)?.group(0) ?? '';
  if (digits.length < 4) return null;

  int parseOr(String source, int start, int len, int fallback) {
    if (start + len > source.length) return fallback;
    final chunk = source.substring(start, start + len);
    return int.tryParse(chunk) ?? fallback;
  }

  final year = parseOr(digits, 0, 4, 0);
  if (year <= 0) return null;
  final month = parseOr(digits, 4, 2, 1);
  final day = parseOr(digits, 6, 2, 1);
  final hour = parseOr(digits, 8, 2, 0);
  final minute = parseOr(digits, 10, 2, 0);
  final second = parseOr(digits, 12, 2, 0);

  var offsetSign = 0;
  var offsetHours = 0;
  var offsetMinutes = 0;
  final tzMatch = RegExp(r'([+\-Z])').firstMatch(text.substring(digits.length));
  if (tzMatch != null) {
    final tz = tzMatch.group(1);
    if (tz == 'Z') {
      offsetSign = 0;
    } else if (tz == '+' || tz == '-') {
      offsetSign = tz == '+' ? 1 : -1;
      final rest = text.substring(digits.length + 1);
      final hh = RegExp(r'\d{2}').firstMatch(rest)?.group(0);
      if (hh != null) offsetHours = int.tryParse(hh) ?? 0;
      final mm = RegExp(r"'?(\d{2})'?")
          .allMatches(rest)
          .map((m) => m.group(1))
          .toList(growable: false);
      if (mm.length > 1 && mm[1] != null) {
        offsetMinutes = int.tryParse(mm[1]!) ?? 0;
      } else if (mm.isNotEmpty && mm.first != null) {
        offsetMinutes = int.tryParse(mm.first!) ?? 0;
      }
    }
  }

  return _ParsedPdfDate(
    year: year,
    month: month,
    day: day,
    hour: hour,
    minute: minute,
    second: second,
    offsetSign: offsetSign,
    offsetHours: offsetHours,
    offsetMinutes: offsetMinutes,
  );
}

String maskCpfForUi(
  String? cpfDigits, {
  String placeholder = '—',
}) {
  if (cpfDigits == null) return placeholder;
  final digits = cpfDigits.replaceAll(RegExp(r'\D'), '');
  if (digits.length != 11) return placeholder;
  return '***.${digits.substring(3, 6)}.${digits.substring(6, 9)}-**';
}

String? maskCpfPreserveInvalid(String? cpfDigits) {
  if (cpfDigits == null) return null;
  final digits = cpfDigits.replaceAll(RegExp(r'\D'), '');
  if (digits.length != 11) return cpfDigits;
  return '***.${digits.substring(3, 6)}.${digits.substring(6, 9)}-**';
}

String bytesToHexLower(List<int> bytes) {
  return hexLower(bytes);
}

String bytesToHexLowerUint8(Uint8List bytes) => bytesToHexLower(bytes);

String bytesToHexUpper(List<int> bytes) => hexUpper(bytes);

String bigIntToHexUpper(BigInt value) => bigIntHexUpper(value);

final class _ParsedPdfDate {
  const _ParsedPdfDate({
    required this.year,
    required this.month,
    required this.day,
    required this.hour,
    required this.minute,
    required this.second,
    required this.offsetSign,
    required this.offsetHours,
    required this.offsetMinutes,
  });

  final int year;
  final int month;
  final int day;
  final int hour;
  final int minute;
  final int second;
  final int offsetSign;
  final int offsetHours;
  final int offsetMinutes;
}
