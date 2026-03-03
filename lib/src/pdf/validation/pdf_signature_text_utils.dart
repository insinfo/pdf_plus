import 'pdf_validation_format_utils.dart';

/// Utilitários de texto/data para metadados de assinatura.
final class PdfSignatureTextUtils {
  const PdfSignatureTextUtils._();

  /// Extrai o Common Name (CN) de subject em formato JSON-like ou RFC2253.
  static String? extractCommonName(String? subject) {
    if (subject == null || subject.trim().isEmpty) return null;
    final value = subject.trim();

    final jsonCn =
        RegExp(r'"CN"\s*:\s*"([^"]+)"').firstMatch(value)?.group(1);
    if (jsonCn != null && jsonCn.trim().isNotEmpty) {
      return jsonCn.trim();
    }

    final cn =
        RegExp(r'(?:^|,\s*)CN\s*=\s*([^,]+)').firstMatch(value)?.group(1);
    if (cn != null && cn.trim().isNotEmpty) {
      return cn.trim();
    }
    return null;
  }

  /// Remove sufixos de CPF/CNPJ que alguns emissores anexam ao nome.
  static String? sanitizeSignerName(String? raw) {
    if (raw == null) return null;
    var value = raw.trim();
    if (value.isEmpty) return null;

    final tailWithSep =
        RegExp(r'^(.+?)\s*[:\-]\s*([\d.\-/]+)$').firstMatch(value);
    if (tailWithSep != null) {
      final digits = tailWithSep.group(2)!.replaceAll(RegExp(r'\D'), '');
      if (digits.length == 11 || digits.length == 14) {
        value = tailWithSep.group(1)!.trim();
      }
    }

    final tailToken = RegExp(r'^(.+?)\s+([\d.\-/]{11,20})$').firstMatch(value);
    if (tailToken != null) {
      final digits = tailToken.group(2)!.replaceAll(RegExp(r'\D'), '');
      if (digits.length == 11 || digits.length == 14) {
        value = tailToken.group(1)!.trim();
      }
    }

    return value.isEmpty ? null : value;
  }

  /// Formata data/hora local no padrão brasileiro.
  static String? formatDateTimeBr(
    DateTime? dt, {
    bool includeSeconds = true,
  }) {
    if (dt == null) return null;
    final local = dt.toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    final base =
        '${two(local.day)}/${two(local.month)}/${local.year} ${two(local.hour)}:${two(local.minute)}';
    if (!includeSeconds) {
      return base;
    }
    return '$base:${two(local.second)}';
  }

  /// Formata string de data PDF (`D:...`) no padrão brasileiro.
  static String? formatPdfDateBr(
    String? raw, {
    bool includeSeconds = true,
  }) {
    final local = parsePdfDateLocal(raw);
    return formatDateTimeBr(local, includeSeconds: includeSeconds);
  }
}
