import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  test('parse ICP-Brasil IDs from otherName OIDs', () {
    final otherNames = <PdfSignatureOtherName>[
      const PdfSignatureOtherName('2.16.76.1.3.1', '01012000 12345678909'),
      const PdfSignatureOtherName('2.16.76.1.3.2', 'JOAO RESPONSAVEL'),
      const PdfSignatureOtherName('2.16.76.1.3.3', '12.345.678/0001-95'),
      const PdfSignatureOtherName('2.16.76.1.3.4', '02022010 00000000123'),
      const PdfSignatureOtherName('2.16.76.1.3.5', '465555610469001047700000000000municipioRS'),
      const PdfSignatureOtherName('2.16.76.1.3.6', '253764977686'),
    ];

    final ids = PdfSignatureIcpBrasilIds.fromOtherNames(otherNames);
    expect(ids, isNotNull);
    expect(ids!.cpf, '12345678909');
    expect(ids.cnpj, '12345678000195');
    expect(ids.responsavelCpf, '00000000123');
    expect(ids.responsavelNome, 'JOAO RESPONSAVEL');
    expect(ids.tituloEleitor, isNotNull);
    expect(ids.cei, '253764977686');
    expect(ids.dateOfBirth, DateTime(2000, 1, 1));
  });
}
