import 'dart:typed_data';

/// Parâmetros de `/DecodeParms` que afetam a decodificação de um stream Flate
/// ou LZW.
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

  /// Se há alguma transformação a desfazer.
  bool get isActive => predictor > 1;
}

/// Desfaz os preditores previstos na ISO 32000-1 §7.4.4.4.
///
/// Um stream com `/Predictor 12` — o padrão da maioria dos geradores de PDF
/// 1.5+ para tabelas de referências cruzadas — sai do inflate ainda filtrado
/// por linhas no estilo PNG. Sem desfazer isso, cada byte lido é lixo: offsets
/// de objeto apontando para fora do arquivo, por exemplo.
class PdfParserPredictor {
  /// Aplica o preditor inverso sobre [data].
  ///
  /// Devolve os dados originais quando não há preditor ou quando os parâmetros
  /// não fazem sentido — nunca lança.
  static Uint8List apply(Uint8List data, PdfPredictorParams params) {
    if (!params.isActive) return data;
    if (params.predictor == 2) return _undoTiff(data, params);
    return _undoPng(data, params);
  }

  /// Preditor TIFF (2): cada componente é a diferença para o anterior na mesma
  /// linha. Só o caso de 8 bits por componente é tratado; os demais são raros e
  /// devolvidos sem alteração.
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

  /// Preditores PNG (10 a 15). Cada linha vem precedida do byte que diz qual
  /// filtro foi usado nela.
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
          // Linha com filtro desconhecido: mantém como veio.
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
