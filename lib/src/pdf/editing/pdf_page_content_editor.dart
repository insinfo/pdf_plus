import 'dart:math' as math;

import '../color.dart';
import '../colors.dart';
import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../graphics.dart';
import '../obj/font.dart';
import '../obj/image.dart';
import '../obj/object_stream.dart';
import '../obj/page.dart';
import '../pdf_names.dart';
import '../point.dart';
import 'object_graph/pdf_object_store.dart';
import 'pdf_box.dart';
import 'pdf_coordinate_transformer.dart';

/// Em que camada o carimbo é desenhado.
enum PdfStampLayer {
  /// Depois do conteúdo original: cobre o que já estava na página.
  overlay,

  /// Antes do conteúdo original: fica por baixo, como marca-d'água.
  underlay,
}

/// Onde o carimbo se ancora na área visível da página.
enum PdfStampAnchor {
  /// Canto superior esquerdo.
  topLeft,

  /// Centro do topo.
  topCenter,

  /// Canto superior direito.
  topRight,

  /// Meio da borda esquerda.
  centerLeft,

  /// Centro da página.
  center,

  /// Meio da borda direita.
  centerRight,

  /// Canto inferior esquerdo.
  bottomLeft,

  /// Centro do rodapé.
  bottomCenter,

  /// Canto inferior direito.
  bottomRight,
}

/// Carimbo posicionado pelo [PdfCoordinateTransformer].
///
/// A subclasse informa o tamanho em [measure] e desenha em [paint] num
/// sistema local com origem no canto inferior esquerdo do carimbo, eixo `y`
/// para cima e unidade igual ao ponto de exibição. O editor cuida de girar e
/// deslocar esse sistema para o lugar certo do espaço do usuário, inclusive em
/// páginas com `/Rotate`, `/CropBox` deslocada ou `/UserUnit` diferente de 1.
abstract class PdfStamp {
  /// Configura a ancoragem, as margens e a camada do carimbo.
  const PdfStamp({
    this.anchor = PdfStampAnchor.bottomRight,
    this.marginX = 24,
    this.marginY = 24,
    this.position,
    this.rotationDegrees = 0,
    this.layer = PdfStampLayer.overlay,
  });

  /// Canto ou borda de referência dentro da área visível.
  final PdfStampAnchor anchor;

  /// Distância horizontal entre o carimbo e a borda, em pontos de exibição.
  final double marginX;

  /// Distância vertical entre o carimbo e a borda, em pontos de exibição.
  final double marginY;

  /// Canto superior esquerdo explícito, em coordenadas "top-left".
  ///
  /// Quando informado, [anchor], [marginX] e [marginY] são ignorados.
  final PdfPoint? position;

  /// Giro do próprio carimbo, em graus no sentido anti-horário da exibição.
  ///
  /// Serve para a marca-d'água na diagonal. O giro acontece em torno do centro
  /// do carimbo e não altera a área usada para ancorá-lo.
  final double rotationDegrees;

  /// Se o carimbo vai por cima ou por baixo do conteúdo original.
  final PdfStampLayer layer;

  /// Tamanho do carimbo, em pontos de exibição.
  PdfPoint measure(PdfDocument document);

  /// Desenha o carimbo no sistema local descrito na documentação da classe.
  void paint(PdfGraphics canvas, PdfPoint size);

  /// Área ocupada pelo carimbo, em coordenadas "top-left".
  PdfTopLeftRect resolveRect(
    PdfCoordinateTransformer transformer,
    PdfPoint size,
  ) {
    final origin = position;
    if (origin != null) {
      return PdfTopLeftRect(origin.x, origin.y, size.x, size.y);
    }

    final available = PdfPoint(
      transformer.displayWidth,
      transformer.displayHeight,
    );

    final double left;
    switch (anchor) {
      case PdfStampAnchor.topLeft:
      case PdfStampAnchor.centerLeft:
      case PdfStampAnchor.bottomLeft:
        left = marginX;
      case PdfStampAnchor.topCenter:
      case PdfStampAnchor.center:
      case PdfStampAnchor.bottomCenter:
        left = (available.x - size.x) / 2;
      case PdfStampAnchor.topRight:
      case PdfStampAnchor.centerRight:
      case PdfStampAnchor.bottomRight:
        left = available.x - size.x - marginX;
    }

    final double top;
    switch (anchor) {
      case PdfStampAnchor.topLeft:
      case PdfStampAnchor.topCenter:
      case PdfStampAnchor.topRight:
        top = marginY;
      case PdfStampAnchor.centerLeft:
      case PdfStampAnchor.center:
      case PdfStampAnchor.centerRight:
        top = (available.y - size.y) / 2;
      case PdfStampAnchor.bottomLeft:
      case PdfStampAnchor.bottomCenter:
      case PdfStampAnchor.bottomRight:
        top = available.y - size.y - marginY;
    }

    return PdfTopLeftRect(left, top, size.x, size.y);
  }
}

/// Cache da fonte padrão dos carimbos, por documento.
///
/// `PdfFont.helvetica` cria um objeto novo a cada chamada; sem o cache, uma
/// numeração Bates de duzentas páginas gravaria duzentas fontes iguais.
final Expando<PdfFont> _defaultStampFonts = Expando<PdfFont>('pdfStampFont');

/// Carimbo de texto em uma linha.
class PdfTextStamp extends PdfStamp {
  /// Cria o carimbo de texto.
  const PdfTextStamp({
    required this.text,
    this.font,
    this.fontSize = 10,
    this.color = PdfColors.black,
    this.background,
    this.borderColor,
    this.borderWidth = 0.5,
    this.padding = 0,
    super.anchor,
    super.marginX,
    super.marginY,
    super.position,
    super.rotationDegrees,
    super.layer,
  });

  /// O texto a carimbar.
  final String text;

  /// A fonte; quando nula, uma Helvetica compartilhada pelo documento.
  final PdfFont? font;

  /// Corpo da fonte, em pontos de exibição.
  final double fontSize;

  /// Cor do texto.
  final PdfColor color;

  /// Cor de fundo do retângulo do carimbo, ou nula para fundo transparente.
  final PdfColor? background;

  /// Cor da borda do retângulo do carimbo, ou nula para não desenhar borda.
  final PdfColor? borderColor;

  /// Espessura da borda.
  final double borderWidth;

  /// Espaço entre o texto e as bordas do retângulo.
  final double padding;

  /// A fonte efetiva deste carimbo dentro de [document].
  PdfFont resolveFont(PdfDocument document) =>
      font ?? (_defaultStampFonts[document] ??= PdfFont.helvetica(document));

  @override
  PdfPoint measure(PdfDocument document) {
    final resolved = resolveFont(document);
    final width = resolved.stringMetrics(text).advanceWidth * fontSize;
    final height = resolved.emptyLineHeight * fontSize;
    return PdfPoint(width + padding * 2, height + padding * 2);
  }

  @override
  void paint(PdfGraphics canvas, PdfPoint size) {
    final resolved = resolveFont(canvas.document);

    if (background != null) {
      canvas.setFillColor(background);
      canvas.drawRect(0, 0, size.x, size.y);
      canvas.fillPath();
    }

    if (borderColor != null && borderWidth > 0) {
      canvas.setStrokeColor(borderColor);
      canvas.setLineWidth(borderWidth);
      canvas.drawRect(0, 0, size.x, size.y);
      canvas.strokePath();
    }

    canvas.setFillColor(color);
    // A linha de base fica acima da borda inferior pela profundidade das
    // descidas da fonte, senão letras como "g" sairiam cortadas.
    canvas.drawString(
      resolved,
      fontSize,
      text,
      padding,
      padding + (-resolved.descent) * fontSize,
    );
  }
}

/// Carimbo de imagem.
class PdfImageStamp extends PdfStamp {
  /// Cria o carimbo de imagem.
  ///
  /// Sem [width] e [height], a imagem ocupa um ponto de exibição por pixel.
  /// Informando só um dos dois, o outro sai da proporção original.
  const PdfImageStamp({
    required this.image,
    this.width,
    this.height,
    super.anchor,
    super.marginX,
    super.marginY,
    super.position,
    super.rotationDegrees,
    super.layer,
  });

  /// A imagem já registrada no documento.
  final PdfImage image;

  /// Largura desejada, em pontos de exibição.
  final double? width;

  /// Altura desejada, em pontos de exibição.
  final double? height;

  @override
  PdfPoint measure(PdfDocument document) {
    final naturalWidth = image.width.toDouble();
    final naturalHeight = image.height.toDouble();
    final w = width;
    final h = height;
    if (w != null && h != null) return PdfPoint(w, h);
    if (w != null) {
      return PdfPoint(w, naturalWidth == 0 ? 0 : naturalHeight * w / naturalWidth);
    }
    if (h != null) {
      return PdfPoint(
          naturalHeight == 0 ? 0 : naturalWidth * h / naturalHeight, h);
    }
    return PdfPoint(naturalWidth, naturalHeight);
  }

  @override
  void paint(PdfGraphics canvas, PdfPoint size) {
    canvas.drawImage(image, 0, 0, size.x, size.y);
  }
}

/// Sobreposição e subposição de conteúdo em uma página, nova ou carregada.
///
/// ## A técnica
///
/// O conteúdo original **nunca é tocado**. O editor acrescenta dois streams à
/// página e monta o `/Contents` nesta ordem:
///
/// ```text
/// [ subposições ] [ "q" ] [ conteúdo original ] [ "Q" + sobreposições ]
/// ```
///
/// O `q` na frente e o `Q` atrás isolam o estado gráfico: qualquer `cm`, cor,
/// recorte ou espessura de linha que a página tenha deixado aberta no nível
/// externo é descartada antes do carimbo, e o carimbo não vaza estado para o
/// que vem depois. É a mesma técnica do `AppendMode` do PDFBox e a que o SEI
/// usa nos PDFs de processo (roteiro de merge, §10, item 7), e ela preserva a
/// fidelidade byte a byte do stream original — importante para um documento
/// que ainda vá ser conferido contra a origem.
///
/// ## O que exigiu cuidado
///
/// `PdfPage.prepare()` sempre coloca o `/Contents` já existente **antes** dos
/// streams criados por `getGraphics()`, então não há como obter um stream de
/// prefixo só empilhando conteúdo novo. O editor resolve isso reescrevendo o
/// `/Contents` da página como um array com a referência do prefixo na frente;
/// como o `prepare()` reinsere esse array no começo e depois chama `uniq()`,
/// que preserva a primeira ocorrência, a ordem final é a desejada e salvar
/// duas vezes não duplica nem reordena nada. Numa página nova, que ainda não
/// tem `/Contents`, a ordem é a da própria lista `PdfPage.contents` e o editor
/// apenas move o stream de prefixo para o início dela.
///
/// A consequência é que o desenho feito diretamente com `page.getGraphics()`
/// **antes** de criar o editor fica dentro do bloco isolado, junto com o
/// conteúdo original; o desenho feito **depois** vai parar após o carimbo.
/// Quem precisa de ordem previsível deve fazer todo o desenho pelo editor.
///
/// ## Limites conhecidos
///
/// - **Recursos.** A mesclagem de `/Resources` continua sendo a de
///   `PdfGraphicStream.prepare()`. O editor apenas garante que ela tenha um
///   dicionário direto para mesclar (ver `_ensureDirectResources`); ele ainda
///   não resolve colisão de nome em `/Font`, `/XObject`, `/ExtGState`,
///   `/Pattern`, `/Shading`, `/ColorSpace` e `/Properties`. Na prática a
///   colisão é improvável, porque o nome dos recursos novos deriva do número
///   do objeto, que em documento carregado começa depois do último do arquivo.
///   O tratamento completo é o `PdfResourceManager` da F4.
/// - **Transparência.** Um carimbo com opacidade exigiria registrar um
///   `/ExtGState` na página, e hoje `prepare()` **substitui** um `/ExtGState`
///   direto já existente pela referência do registro do documento, quebrando o
///   conteúdo original. Por isso não há opção de opacidade: a marca-d'água se
///   faz com cor clara e [PdfStamp.rotationDegrees].
/// - **`replaceContent`.** Trocar o conteúdo da página exige descartar o
///   `/Contents` carregado e depende da coleção de páginas da F3.
class PdfPageContentEditor {
  /// Cria o editor para [page].
  ///
  /// [reference] escolhe a caixa que define a área visível usada para
  /// posicionar carimbos; o padrão é a `/CropBox`, que é o que o leitor mostra.
  PdfPageContentEditor(
    this.page, {
    this.reference = PdfBoxType.crop,
  }) : transformer =
            PdfCoordinateTransformer.forPage(page, reference: reference);

  /// A página editada.
  final PdfPage page;

  /// A caixa usada como área visível.
  final PdfBoxType reference;

  /// Conversor de coordenadas desta página.
  final PdfCoordinateTransformer transformer;

  /// O documento dono da página.
  PdfDocument get document => page.pdfDocument;

  PdfObjectStream? _suffix;
  PdfGraphics? _suffixGraphics;
  int _underlayCount = 0;

  /// Desenha por cima do conteúdo original.
  ///
  /// O callback recebe um [PdfGraphics] no espaço do usuário da página, já
  /// dentro de um `q ... Q` próprio. Para posicionar pelo alto da página,
  /// use [transformer].
  void drawOverlay(void Function(PdfGraphics canvas) build) {
    _ensureWrap();
    final canvas = _suffixGraphics!;
    canvas.saveContext();
    build(canvas);
    canvas.restoreContext();
    page.altered = true;
  }

  /// Desenha por baixo do conteúdo original.
  ///
  /// Útil para marca-d'água: o conteúdo da página continua legível por cima.
  /// Chamadas sucessivas empilham na ordem em que foram feitas, a primeira
  /// mais ao fundo.
  void drawUnderlay(void Function(PdfGraphics canvas) build) {
    _ensureWrap();
    final canvas = page.getGraphics();
    final stream = page.contents.last as PdfObjectStream;
    canvas.saveContext();
    build(canvas);
    canvas.restoreContext();
    _insertContent(stream, _underlayCount);
    _underlayCount++;
    page.altered = true;
  }

  /// Aplica [stamp] na página, na camada que ele declara.
  void drawStamp(PdfStamp stamp) {
    final size = stamp.measure(document);
    final rect = stamp.resolveRect(transformer, size);
    final matrix = transformer.displayTransform(rect);

    if (stamp.rotationDegrees != 0) {
      // Gira em torno do centro do carimbo, sem mover a âncora.
      final cx = size.x / 2;
      final cy = size.y / 2;
      matrix
        ..translateByDouble(cx, cy, 0, 1)
        ..rotateZ(stamp.rotationDegrees * math.pi / 180)
        ..translateByDouble(-cx, -cy, 0, 1);
    }

    void build(PdfGraphics canvas) {
      canvas.setTransform(matrix);
      stamp.paint(canvas, size);
    }

    if (stamp.layer == PdfStampLayer.underlay) {
      drawUnderlay(build);
    } else {
      drawOverlay(build);
    }
  }

  /// As páginas distintas de [document], na ordem do documento.
  ///
  /// Um documento carregado registra cada página duas vezes em
  /// `pdfPageList.pages`: uma pelo construtor de `PdfPage` e outra pelo
  /// `mergeDocument` do parser. Enquanto a coleção de páginas da fase F3 não
  /// existir, carimbar direto sobre a lista desenharia duas vezes na mesma
  /// página e ignoraria metade do documento.
  static List<PdfPage> distinctPages(PdfDocument document) {
    final seen = <PdfPage>[];
    for (final page in document.pdfPageList.pages) {
      if (seen.any((e) => identical(e, page))) continue;
      seen.add(page);
    }
    return seen;
  }

  /// Traz o `/Resources` da página para dentro do dicionário dela quando ele
  /// está em um objeto indireto que ninguém materializou.
  ///
  /// `PdfGraphicStream.prepare()` sabe mesclar os recursos novos em um
  /// dicionário direto e em um objeto indireto **já materializado**; quando o
  /// alvo é uma referência que continua só nos bytes originais — o caso da
  /// maioria dos PDFs carregados — ele substitui a referência pelo dicionário
  /// novo e a página perde as fontes e imagens que tinha. Copiar o dicionário
  /// original para dentro da página, preservando as referências indiretas dos
  /// recursos em si, evita a perda sem tocar no objeto original, que pode ser
  /// compartilhado com outras páginas.
  ///
  /// É um remendo local: o lugar definitivo disso é o `PdfResourceManager`
  /// previsto na F4, que ainda exige mudar `PdfGraphicStream`.
  void _ensureDirectResources() {
    final resources = page.params[PdfNameTokens.resources];
    if (resources is! PdfIndirect) return;

    final store = PdfObjectStore.forDocument(document);
    if (store.containsId(PdfObjectId.fromIndirect(resources))) return;

    final original = store.resolveDict(resources);
    if (original == null) return;

    // Cópia rasa: os valores continuam apontando para os mesmos objetos.
    page.params[PdfNameTokens.resources] =
        PdfDict<PdfDataType>.values(Map<String, PdfDataType>.of(original.values));
  }

  /// Cria o par de streams que envolve o conteúdo original.
  void _ensureWrap() {
    if (_suffix != null) return;

    _ensureDirectResources();

    // Sem isto, `prepare()` descarta os streams novos de uma página cujo
    // conteúdo ainda não foi alterado por nenhuma operação de desenho.
    page.altered = true;

    page.getGraphics();
    final prefix = page.contents.last as PdfObjectStream;
    prefix.buf.putString('q\n');

    final suffixGraphics = page.getGraphics();
    final suffix = page.contents.last as PdfObjectStream;
    suffix.buf.putString('Q\n');

    _suffix = suffix;
    _suffixGraphics = suffixGraphics;

    _insertContent(prefix, _underlayCount);
  }

  /// Coloca [stream] na posição [position] do conteúdo da página, contando a
  /// partir do começo — isto é, antes do conteúdo original.
  void _insertContent(PdfObjectStream stream, int position) {
    final existing = page.params[PdfNameTokens.contents];

    if (existing == null) {
      // Página nova: quem manda na ordem é a lista de conteúdos.
      page.contents.remove(stream);
      page.contents.insert(math.min(position, page.contents.length), stream);
      return;
    }

    final values = <PdfDataType>[];
    if (existing is PdfArray) {
      values.addAll(existing.values);
    } else {
      values.add(existing);
    }
    values.removeWhere((e) => e is PdfIndirect && e == stream.ref());
    values.insert(math.min(position, values.length), stream.ref());
    page.params[PdfNameTokens.contents] = PdfArray<PdfDataType>(values);
  }
}
