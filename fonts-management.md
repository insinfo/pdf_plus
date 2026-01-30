Fonts Management

Fonts management
Standard PDF fonts
The PDF standard defines 14 standard Type1 fonts that can always be used in a document, without any overhead added to the file. The 3 first comes in 4 variants for regular, bold, italic, and bold/italic. The two last are special characters.

The Courier family is a fixed-width font: all characters have the same width. It can be used to print source-code examples.

The Helvetica family is a sans-serif font, probably most used on screens and headings.

The Times family is a serif font where small strokes are attached to the letters to improve readability. They are used for large text blocks, like books.

Symbol is mainly used for mathematical expressions with Greek letters.

Zapf Dingbats contains a list of icons like check-marks, arrows, phone.

This list of fonts works well if you plan to only use US or West-European characters, but as soon as you need specific accents or Asian characters, you have to switch to a Unicode font.

TrueType and OpenType fonts
To print letters like Ł or € you need to load a font that supports this. By default, the library uses the standard fonts and let the developer decide which font is the best for his design.

To load a font, use:

var myFont = Font.ttf(data);
Then you can use it in a text style:

var myStyle = TextStyle(font: myFont);
Finally, this style can be passed to a Text widget:

pdf.addPage(
  Page(
    pageFormat: PdfPageFormat.a4,
    build: (Context context) {
      return Center(
        child: Text('Hello World', style: myStyle),
      ); // Center
    },
  ), // Page
);
To load the data from disk, use:

var Uint8List fontData = File('open-sans.ttf').readAsBytesSync();
var data = fontData.buffer.asByteData();
If your font is available as a Flutter asset, use:

var data = await rootBundle.load("assets/open-sans.ttf");
and the file must be added to the assets in your pubspec.yaml:

flutter:
  assets:
    - assets/open-sans.ttf
Using a font globally
It is possible to create a theme for the entire document. This way, all the elements in the document will use your specific font and you will have no issues with untrusted text sources, like user inputs.

In your pubspec.yaml add all the required fonts:

flutter:
  assets:
    - assets/OpenSans-Regular.ttf
    - assets/OpenSans-Bold.ttf
    - assets/OpenSans-Italic.ttf
    - assets/OpenSans-BoldItalic.ttf
In your PDF generation function, create the document with a theme:

var myTheme = ThemeData.withFont(
  base: Font.ttf(await rootBundle.load("assets/OpenSans-Regular.ttf")),
  bold: Font.ttf(await rootBundle.load("assets/OpenSans-Bold.ttf")),
  italic: Font.ttf(await rootBundle.load("assets/OpenSans-Italic.ttf")),
  boldItalic: Font.ttf(await rootBundle.load("assets/OpenSans-BoldItalic.ttf")),
);

var pdf = Document(
  theme: myTheme,
);
Google Fonts
It's possible to use Google Fonts directly. The library will cache the files in memory by default.

final font = await PdfGoogleFonts.nunitoExtraLight();

pdf.addPage(
  Page(
    build: (context) {
      return Text('Hello, style: TextStyle(font: font));
    },
  ),
);
Caching
class PdfFileCache extends PdfBaseCache {
  PdfFileCache({
    String? base,
  }) : base = base ?? '.';

  final String base;

  @override
  Future<void> add(String key, Uint8List bytes) async {
    await File('$base/$key').writeAsBytes(bytes);
  }

  @override
  Future<Uint8List?> get(String key) async {
    return await File('$base/$key').readAsBytes();
  }

  @override
  Future<void> clear() async {}

  @override
  Future<bool> contains(String key) async {
    return File('$base/$key').existsSync();
  }

  @override
  Future<void> remove(String key) async {
    File('$base/$key').deleteSync();
  }
}