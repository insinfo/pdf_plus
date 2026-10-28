# TODO

## Não implementar: raízes ICP-Brasil v4 e v13 (cadeia de passaporte eletrônico, não de PDF)

As raízes ICP-Brasil v4 (23/04/2015 a 23/04/2035) e v13 (14/02/2025 a
14/02/2045) têm uma única AC abaixo, a do Ministério das Relações Exteriores
(AC MRE na v4, AC MRE v1 na v13), de uso exclusivo para assinar o chip de
passaportes brasileiros (eMRTD) e a própria LCR (DPC da AC MRE, item 1.4.1;
Nota Técnica nº 10/2024 do ITI). Os titulares são selos eletrônicos de pessoa
jurídica, não pessoas: servidor do Itamaraty assina PDF com e-CPF RSA comum,
das raízes v2/v5/v10. Nenhuma assinatura de PDF fecha nessas raízes.

A chave é de curva elíptica com a curva escrita por extenso (512 bits, ao que
parece a brainpoolP512r1). Não é defeito: o perfil de passaporte da ICAO
(Doc 9303, Parte 12) exige parâmetros explícitos, enquanto o perfil PKIX
(RFC 5480) exige curva nomeada. Por isso os validadores de uso geral recusam a
cadeia:

- pdf_plus: em `lib/src/pdf/validation/pdf_signature_validator.dart`, o segundo
  elemento do `AlgorithmIdentifier` é uma `SEQUENCE`, não um OID; `curveOid`
  fica nulo, `_curveNameFromOid` devolve `null` e a verificação da assinatura
  do certificado retorna `false`;
- dart_pdf: `Unsupported EC public key parameters (expected named curve OID)`;
- OpenSSL 3: `error 94: Certificate public key has explicit ECC parameters`;
- Java (SunEC): recusa a loja inteira (`Only named ECParameters supported`) —
  por isso o ITI deixa essas raízes fora do JKS dele.

Se um dia fizer sentido: comparar os parâmetros explícitos (p, a, b, G, n, h)
com os das curvas conhecidas e tratar a coincidência como a curva nomeada
correspondente. As curvas Brainpool com OID nomeado já são conferidas desde a
4.0.3.

Não implementar: a cadeia assina passaporte, não documento. Testado em
28/10/2026 com os certificados do pacote de cadeias ICP-Brasil do ITI.
