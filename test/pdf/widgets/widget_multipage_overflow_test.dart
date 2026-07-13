/*
 * Copyright (C) 2017, David PHAM-VAN <dev.nfet.net@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/widgets.dart';
import 'package:test/test.dart';

// Regressao: um bloco de Text mais alto que o espaco disponivel abaixo do
// header, porem menor que uma pagina inteira, fazia o MultiPage entrar em
// loop infinito de criacao de paginas ate estourar TooManyPagesException
// (travando aplicacoes web). Ver caso real: solicitacao e-SIC com texto longo.
//
// Um paragrafo longo o suficiente para render ~700pt de altura (maior que a
// area util de uma A4 abaixo de um header de 80pt).
String _tallText() {
  // Alvo: altura renderizada dentro da "faixa impossivel" — maior que a area
  // util sob um header de 80pt (~648pt numa A4 sem margem) e menor que uma
  // pagina nua (~728pt). Linhas curtas dao altura previsivel (~1 linha cada).
  final b = StringBuffer();
  for (var i = 0; i < 48; i++) {
    b.writeln('Linha $i de texto para exercitar a quebra de pagina.');
  }
  return b.toString();
}

MultiPage _buildPage(Widget textWidget) {
  return MultiPage(
    maxPages: 30,
    // A4 SEM margens amplifica a diferenca entre pagina-nua e pagina-com-header.
    pageFormat: PdfPageFormat.a4,
    header: (Context context) => SizedBox(height: 80, width: 150),
    build: (Context context) => [textWidget],
  );
}

void main() {
  setUpAll(() {
    Document.debug = true;
    RichText.debug = true;
  });

  test(
      'Text nao-divisivel maior que a area util sob o header NAO entra em loop '
      '(erro claro em vez de TooManyPagesException)', () {
    final pdf = Document();

    // O layout ocorre em addPage. Deve falhar rapido com um erro descritivo,
    // e nunca com TooManyPagesException (sintoma do loop de paginas).
    expect(
      () => pdf.addPage(_buildPage(Text(_tallText()))),
      throwsA(
        allOf(
          isA<Exception>(),
          isNot(isA<TooManyPagesException>()),
          predicate((Object e) => e.toString().contains('available space')),
        ),
      ),
    );
  });

  test('Text com overflow: TextOverflow.span quebra entre paginas sem erro',
      () async {
    final pdf = Document();
    pdf.addPage(_buildPage(Text(_tallText(), overflow: TextOverflow.span)));

    final bytes = await pdf.save();
    expect(bytes, isNotEmpty);
  });
}
