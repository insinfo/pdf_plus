import 'dart:typed_data';

/// `/DecodeParms` parameters that affect the decoding of a Flate or LZW
/// stream.
class PdfPredictorParams {
  const PdfPredictorParams({
    this.predictor = 1,
    this.colors = 1,
    this.bitsPerComponent = 8,
    this.columns = 1,
  });

  final int predictor;
  final int colors;
  final int bitsPerComponent;
  final int columns;

  /// Whether there is any transformation to undo.
  bool get isActive => predictor > 1;
}

/// Undoes the predictors defined in ISO 32000-1 §7.4.4.4.
///
/// A stream with `/Predictor 12` — what most PDF 1.5+ generators use for
/// cross-reference tables — comes out of inflate still filtered row by row in
/// the PNG style. Without undoing that, every byte read is garbage: object
/// offsets pointing outside the file, for example.
class PdfParserPredictor {
  /// Applies the inverse predictor over [data].
  ///
  /// Returns the original data when there is no predictor or when the
  /// parameters make no sense — never throws.
  static Uint8List apply(Uint8List data, PdfPredictorParams params) {
    if (!params.isActive) return data;
    if (params.predictor == 2) return _undoTiff(data, params);
    return _undoPng(data, params);
  }

  /// TIFF predictor (2): each component is the difference from the previous
  /// one on the same row. Only the 8 bits per component case is handled; the
  /// others are rare and returned unchanged.
  static Uint8List _undoTiff(Uint8List data, PdfPredictorParams params) {
    if (params.bitsPerComponent != 8) return data;
    final colors = params.colors;
    final rowLength = params.columns * colors;
    if (rowLength <= 0 || colors <= 0) return data;

    final out = Uint8List.fromList(data);
    for (var row = 0; row + rowLength <= out.length; row += rowLength) {
      for (var i = colors; i < rowLength; i++) {
        out[row + i] = (out[row + i] + out[row + i - colors]) & 0xFF;
      }
    }
    return out;
  }

  /// PNG predictors (10 to 15). Each row is preceded by the byte telling
  /// which filter was used on it.
  static Uint8List _undoPng(Uint8List data, PdfPredictorParams params) {
    final bpp = _bytesPerPixel(params);
    final rowLength = _rowLength(params);
    if (rowLength <= 0 || bpp <= 0) return data;

    final rowCount = data.length ~/ (rowLength + 1);
    if (rowCount == 0) return data;

    final out = Uint8List(rowCount * rowLength);
    var previous = Uint8List(rowLength);

    for (var row = 0; row < rowCount; row++) {
      final start = row * (rowLength + 1);
      final filter = data[start];
      final current = Uint8List(rowLength);
      current.setRange(0, rowLength, data, start + 1);

      switch (filter) {
        case 0: // None
          break;
        case 1: // Sub
          for (var i = bpp; i < rowLength; i++) {
            current[i] = (current[i] + current[i - bpp]) & 0xFF;
          }
          break;
        case 2: // Up
          for (var i = 0; i < rowLength; i++) {
            current[i] = (current[i] + previous[i]) & 0xFF;
          }
          break;
        case 3: // Average
          for (var i = 0; i < rowLength; i++) {
            final left = i >= bpp ? current[i - bpp] : 0;
            current[i] = (current[i] + ((left + previous[i]) >> 1)) & 0xFF;
          }
          break;
        case 4: // Paeth
          for (var i = 0; i < rowLength; i++) {
            final left = i >= bpp ? current[i - bpp] : 0;
            final up = previous[i];
            final upLeft = i >= bpp ? previous[i - bpp] : 0;
            current[i] = (current[i] + _paeth(left, up, upLeft)) & 0xFF;
          }
          break;
        default:
          // Row with an unknown filter: keep it as it came.
          break;
      }

      out.setRange(row * rowLength, (row + 1) * rowLength, current);
      previous = current;
    }

    return out;
  }

  static int _paeth(int a, int b, int c) {
    final p = a + b - c;
    final pa = (p - a).abs();
    final pb = (p - b).abs();
    final pc = (p - c).abs();
    if (pa <= pb && pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
  }

  static int _bytesPerPixel(PdfPredictorParams params) {
    final bits = params.colors * params.bitsPerComponent;
    final bytes = (bits + 7) ~/ 8;
    return bytes < 1 ? 1 : bytes;
  }

  static int _rowLength(PdfPredictorParams params) {
    final bits = params.columns * params.colors * params.bitsPerComponent;
    return (bits + 7) ~/ 8;
  }
}
