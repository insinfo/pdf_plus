# TODO

## Não vale a pena implementar: chave EC com parâmetros explícitos (raízes ICP-Brasil v4 e v13)

As raízes ICP-Brasil v4 (23/04/2015 a 23/04/2035) e v13 (14/02/2025 a
14/02/2045) usam chave de curva elíptica com a curva escrita por extenso no
certificado (corpo primo, 512 bits, ao que parece a brainpoolP512r1), em vez de
um OID de curva nomeada. A RFC 5480 proíbe isso, e ninguém confere essas
cadeias:

- pdf_plus: em `lib/src/pdf/validation/pdf_signature_validator.dart`, o segundo
  elemento do `AlgorithmIdentifier` é uma `SEQUENCE`, não um OID; `curveOid`
  fica nulo, `_curveNameFromOid` devolve `null` e a verificação da assinatura
  do certificado retorna `false`;
- dart_pdf: `Unsupported EC public key parameters (expected named curve OID)`;
- OpenSSL 3: `error 94: Certificate public key has explicit ECC parameters`;
- Java: recusa a loja inteira (`Only named ECParameters supported`) — por isso
  o ITI deixa essas raízes fora do JKS dele.

Debaixo delas só existe a AC do Ministério das Relações Exteriores (AC MRE na
v4, AC MRE v1 na v13); nenhuma AC de e-CPF ou e-CNPJ do mercado. Um PDF
assinado com certificado do MRE aparece com cadeia não confiável.

Se um dia for preciso: comparar os parâmetros explícitos (p, a, b, G, n, h) com
os das curvas conhecidas e tratar a coincidência como a curva nomeada
correspondente.

Não vale a pena: o defeito é dos certificados, e documento assinado pelo MRE é
raríssimo para quem usa esta biblioteca. Testado em 28/10/2026 com os
certificados do pacote de cadeias ICP-Brasil do ITI.
