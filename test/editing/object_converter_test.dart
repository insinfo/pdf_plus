import 'dart:typed_data';

import 'package:pdf_plus/src/pdf/editing/object_graph/pdf_object_converter.dart';
import 'package:pdf_plus/src/pdf/format/array.dart';
import 'package:pdf_plus/src/pdf/format/base.dart';
import 'package:pdf_plus/src/pdf/format/bool.dart';
import 'package:pdf_plus/src/pdf/format/dict.dart';
import 'package:pdf_plus/src/pdf/format/indirect.dart';
import 'package:pdf_plus/src/pdf/format/name.dart';
import 'package:pdf_plus/src/pdf/format/null_value.dart';
import 'package:pdf_plus/src/pdf/format/num.dart';
import 'package:pdf_plus/src/pdf/format/string.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

/// Um valor que o modelo tokenizado nunca produz, para exercitar o caminho
/// "tipo desconhecido".
class _Alien {}

/// Estrutura com um exemplar de cada tipo do modelo tokenizado.
PdfDictToken _sampleDict() => PdfDictToken(<String, dynamic>{
      '/Type': PdfNameToken('/Page'),
      '/Flag': true,
      '/Count': 3,
      '/Size': 4.5,
      '/Nothing': null,
      '/Title': PdfStringToken(
        Uint8List.fromList(<int>[0x6F, 0x69]),
        PdfStringFormat.literal,
      ),
      '/Digest': PdfStringToken(
        Uint8List.fromList(<int>[0xDE, 0xAD]),
        PdfStringFormat.binary,
      ),
      '/Parent': PdfRefToken(7, 2),
      '/Kids': PdfArrayToken(<dynamic>[PdfRefToken(8, 0), 1, null]),
      '/Sub': PdfDictToken(<String, dynamic>{'/A': PdfNameToken('/B')}),
    });

void main() {
  group('PdfObjectConverter — tipos', () {
    const converter = PdfObjectConverter.preserving;

    test('null do PDF vira PdfNull', () {
      expect(converter.convert(null), const PdfNull());
    });

    test('booleano', () {
      expect((converter.convert(true) as PdfBool).value, isTrue);
      expect((converter.convert(false) as PdfBool).value, isFalse);
    });

    test('inteiro e real', () {
      expect((converter.convert(42) as PdfNum).value, 42);
      expect((converter.convert(1.5) as PdfNum).value, 1.5);
    });

    test('nome', () {
      final value = converter.convert(PdfNameToken('/Widget'));
      expect(value, isA<PdfName>());
      expect((value as PdfName).value, '/Widget');
    });

    test('string literal e binária mantêm bytes, formato e encrypted false',
        () {
      final literal = converter.convert(
        PdfStringToken(
          Uint8List.fromList(<int>[0x61, 0x62]),
          PdfStringFormat.literal,
        ),
      ) as PdfString;
      expect(literal.value, <int>[0x61, 0x62]);
      expect(literal.format, PdfStringFormat.literal);
      expect(literal.encrypted, isFalse);

      final binary = converter.convert(
        PdfStringToken(
          Uint8List.fromList(<int>[0x00, 0xFF]),
          PdfStringFormat.binary,
        ),
      ) as PdfString;
      expect(binary.value, <int>[0x00, 0xFF]);
      expect(binary.format, PdfStringFormat.binary);
      expect(binary.encrypted, isFalse);
    });

    test('referência indireta preserva número e geração', () {
      final value = converter.convert(PdfRefToken(12, 3));
      expect(value, const PdfIndirect(12, 3));
    });

    test('array converte cada item', () {
      final array = converter.convert(
        PdfArrayToken(<dynamic>[1, PdfNameToken('/X'), null]),
      ) as PdfArray;
      expect(array.values, hasLength(3));
      expect((array.values[0] as PdfNum).value, 1);
      expect((array.values[1] as PdfName).value, '/X');
      expect(array.values[2], const PdfNull());
    });

    test('dicionário converte cada valor, inclusive aninhado', () {
      final dict = converter.convert(_sampleDict()) as PdfDict;
      expect((dict['/Type'] as PdfName).value, '/Page');
      expect(dict['/Parent'], const PdfIndirect(7, 2));
      expect(dict['/Nothing'], const PdfNull());
      final sub = dict['/Sub'] as PdfDict;
      expect((sub['/A'] as PdfName).value, '/B');
    });

    test('dicionário respeita ignoreKeys', () {
      final dict = converter.convertDict(
        _sampleDict(),
        ignoreKeys: const <String>{'/Type', '/Parent'},
      );
      expect(dict.containsKey('/Type'), isFalse);
      expect(dict.containsKey('/Parent'), isFalse);
      expect(dict.containsKey('/Count'), isTrue);
    });

    test('tipo desconhecido devolve null', () {
      expect(converter.convert(_Alien()), isNull);
    });

    test('mergeDictInto escreve no destino e ignora as chaves pedidas', () {
      final target = PdfDict<PdfDataType>.values(<String, PdfDataType>{
        '/Keep': const PdfName('/Old'),
      });
      converter.mergeDictInto(
        target,
        _sampleDict(),
        ignoreKeys: const <String>{'/Type'},
      );
      expect((target['/Keep'] as PdfName).value, '/Old');
      expect(target.containsKey('/Type'), isFalse);
      expect(target['/Parent'], const PdfIndirect(7, 2));
    });
  });

  group('PdfObjectConverter — política de referência injetável', () {
    test('PdfReferencePolicy.preserve mantém o par (obj, gen)', () {
      expect(PdfReferencePolicy.preserve(PdfRefToken(4, 1)),
          const PdfIndirect(4, 1));
    });

    test('política de remapeamento troca os números', () {
      final converter = PdfObjectConverter(
        referencePolicy:
            PdfReferencePolicy.remap((ref) => PdfIndirect(ref.obj + 100, 0)),
      );
      final dict = converter.convert(_sampleDict()) as PdfDict;
      expect(dict['/Parent'], const PdfIndirect(107, 0));
      final kids = dict['/Kids'] as PdfArray;
      expect(kids.values.first, const PdfIndirect(108, 0));
    });

    test('referência descartada some do dicionário', () {
      final converter = PdfObjectConverter(
        referencePolicy: PdfReferencePolicy.remap((ref) => null),
      );
      final dict = converter.convert(_sampleDict()) as PdfDict;
      expect(dict.containsKey('/Parent'), isFalse);
      expect(dict.containsKey('/Count'), isTrue);
    });

    test('withReferencePolicy preserva a política de lacunas', () {
      const base = PdfObjectConverter(arrayGapPolicy: PdfArrayGapPolicy.keepNull);
      final derived =
          base.withReferencePolicy(PdfReferencePolicy.remap((ref) => null));
      expect(derived.arrayGapPolicy, PdfArrayGapPolicy.keepNull);
    });
  });

  group('PdfObjectConverter — lacunas de array', () {
    final dropped = PdfArrayToken(<dynamic>[
      PdfRefToken(1, 0),
      2,
      PdfRefToken(3, 0),
    ]);

    test('drop remove o item descartado', () {
      final converter = PdfObjectConverter(
        referencePolicy: PdfReferencePolicy.remap((ref) => null),
      );
      final array = converter.convertArray(dropped);
      expect(array.values, hasLength(1));
      expect((array.values.single as PdfNum).value, 2);
    });

    test('keepNull preserva a posição dos demais', () {
      final converter = PdfObjectConverter(
        referencePolicy: PdfReferencePolicy.remap((ref) => null),
        arrayGapPolicy: PdfArrayGapPolicy.keepNull,
      );
      final array = converter.convertArray(dropped);
      expect(array.values, hasLength(3));
      expect(array.values[0], const PdfNull());
      expect((array.values[1] as PdfNum).value, 2);
      expect(array.values[2], const PdfNull());
    });

    test('gapPolicy da chamada sobrescreve o do conversor', () {
      final converter = PdfObjectConverter(
        referencePolicy: PdfReferencePolicy.remap((ref) => null),
        arrayGapPolicy: PdfArrayGapPolicy.keepNull,
      );
      final array = converter.convertArray(
        dropped,
        gapPolicy: PdfArrayGapPolicy.drop,
      );
      expect(array.values, hasLength(1));
    });
  });

  group('PdfParserObjects delega ao conversor', () {
    test('toPdfDataType produz a mesma saída do núcleo', () {
      final sample = _sampleDict();
      expect(
        PdfParserObjects.toPdfDataType(sample).toString(),
        PdfObjectConverter.preserving.convert(sample).toString(),
      );
    });

    test('toPdfDict continua honrando ignoreKeys', () {
      final dict = PdfParserObjects.toPdfDict(
        _sampleDict(),
        ignoreKeys: const <String>{'/Kids'},
      );
      expect(dict.containsKey('/Kids'), isFalse);
      expect(dict['/Parent'], const PdfIndirect(7, 2));
    });

    test('toPdfArray continua descartando valores impossíveis', () {
      final array = PdfParserObjects.toPdfArray(
        PdfArrayToken(<dynamic>[1, _Alien(), PdfNameToken('/Z')]),
      );
      expect(array.values, hasLength(2));
      expect((array.values[0] as PdfNum).value, 1);
      expect((array.values[1] as PdfName).value, '/Z');
    });

    test('toPdfDataType de tipo desconhecido continua devolvendo null', () {
      expect(PdfParserObjects.toPdfDataType(_Alien()), isNull);
    });

    test('mergeDictIntoPdfDict mantém o comportamento anterior', () {
      final target = PdfDict<PdfDataType>();
      PdfParserObjects.mergeDictIntoPdfDict(
        target,
        _sampleDict(),
        ignoreKeys: const <String>{'/Type', '/Sub'},
      );
      expect(target.containsKey('/Type'), isFalse);
      expect(target.containsKey('/Sub'), isFalse);
      expect((target['/Count'] as PdfNum).value, 3);
    });
  });
}
