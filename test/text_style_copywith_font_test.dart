// Regression: `copyWith(font: X)` used to be a silent no-op on styles that
// already carried a non-null fontNormal (any theme/inherited style), because
// the constructor only routes `font` into a variant slot when that slot is
// null. This bit quill_to_pdf: onRequestFontFamily responses were ignored for
// the regular weight and text stayed in the theme font.

import 'package:pdf_plus/widgets.dart';
import 'package:test/test.dart';

void main() {
  test('copyWith(font:) replaces the regular typeface of a themed style', () {
    final themed = TextStyle.defaultStyle(); // fontNormal = Helvetica
    final courier = Font.courier();

    final restyled = themed.copyWith(font: courier);

    expect(restyled.fontNormal, same(courier));
    expect(restyled.font, same(courier),
        reason: 'the resolved regular font must be the new typeface');
    expect(restyled.fontBold, same(themed.fontBold),
        reason: 'variants not passed must be preserved');
  });

  test('copyWith(fontNormal:) still wins over font:', () {
    final themed = TextStyle.defaultStyle();
    final courier = Font.courier();
    final times = Font.times();

    final restyled = themed.copyWith(font: courier, fontNormal: times);

    expect(restyled.fontNormal, same(times));
  });

  test('copyWith() without font keeps the current typefaces', () {
    final themed = TextStyle.defaultStyle();
    final restyled = themed.copyWith(fontSize: 8);

    expect(restyled.fontNormal, same(themed.fontNormal));
    expect(restyled.fontBold, same(themed.fontBold));
    expect(restyled.fontSize, 8);
  });

  test('apply(font:) replaces the regular typeface as well', () {
    final themed = TextStyle.defaultStyle();
    final courier = Font.courier();

    final restyled = themed.apply(font: courier);

    expect(restyled.fontNormal, same(courier));
  });
}
