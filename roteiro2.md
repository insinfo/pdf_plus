# Roteiro Técnico Detalhado: Implementação de Assinatura Eletrônica e Edição de PDF no `pdf_plus`

Z:\desenvolvimento\DIGITALIZADOS_SEMFAZ\14_34074_Vol 5.pdf
C:\Program Files\gs\gs10.06.0\bin\

qpdf --check "Z:\desenvolvimento\DIGITALIZADOS_SEMFAZ\14_34074_Vol 5.pdf"
mutool info "Z:\desenvolvimento\DIGITALIZADOS_SEMFAZ\14_34074_Vol 5.pdf" 

mutool info "Z:\desenvolvimento\DIGITALIZADOS_SEMFAZ\14_34074_Vol. 4_Fls. 2649 à 2891.pdf"

qpdf --check "Z:\desenvolvimento\DIGITALIZADOS_SEMFAZ\14_34074_Vol. 4_Fls. 2649 à 2891.pdf"

mutool info '.\tmp\14_34074_Vol 5.pdf'
.\tool\pdf_info.exe '.\tmp\14_34074_Vol 5.pdf'
dart .\tool\pdf_info.dart '.\tmp\14_34074_Vol 5.pdf'


dart compile exe .\tool\pdf_info.dart -o .\tool\pdf_info.exe --target-os windows

Measure-Command -Expression { mutool info '.\tmp\14_34074_Vol 5.pdf' }
Measure-Command -Expression { dart .\tool\pdf_info.dart '.\tmp\14_34074_Vol 5.pdf' }

Measure-Command -Expression { .\tool\pdf_info.exe '.\tmp\14_34074_Vol 5.pdf'}

Foco na robustez e na correção
Reduzindo dependências
a ideia é eliminar na medida do possivel dependecia de 

pointycastle: ^4.0.0
asn1lib: ^1.6.5
collection: ^1.19.1
convert: ^3.1.2

mais antes de eliminar estas dependencias tenho que reimplementar varias coisas que tem nestas dependecias 
e testar bastante 

Este documento apresenta um plano técnico detalhado para a evolução do pacote `pdf_plus`, focando prioritariamente na **Assinatura Eletrônica (PAdES/CAdES)** e posteriormente na **Edição de PDF**. O roteiro baseia-se na análise do código fonte existente (`lib/src/pdf`) e nas referências do projeto `insinfo_dart_pdf` (incluindo `itext-dotnet` e `pdfbox`).

# Roteiro Técnico Completo: Assinatura Eletrônica (PAdES/CAdES) e Edição de PDF no `pdf_plus`

Este documento consolida um roteiro completo e acionável para evoluir o `pdf_plus` com foco **prioritário em PAdES** e, na sequência, **edição incremental de PDF**. O plano considera:

* Estado atual do código em `lib/src/pdf` (assinatura, catálogo, widgets e salvamento incremental parcial).
* Referências e soluções já maduras no projeto `insinfo_dart_pdf` (validação, assinatura externa, DSS/LTV, policy ICP‑Brasil, parser seguro, etc.).
* Boas práticas de PDFBox/iText para assinatura visível, incremental update e LTV.

---

## 1. Diagnóstico Consolidado do Estado Atual (pdf_plus)

### 1.1 Pontos que já existem e podem ser reutilizados
* **Estrutura de baixo nível**: objetos PDF, dicionários e streams em `lib/src/pdf/obj/`.
* **Assinatura básica**: `PdfSignature` + `PdfSignatureBase` (pré‑reserva e escrita pós‑xref).
* **AcroForm e widgets**: criação e montagem de campos de formulário e assinatura em `PdfCatalog` e `PdfAnnot`.
* **Salvamento incremental parcial**: `PdfDocument.save()` já concatena `prev.bytes` e escreve novos objetos/xref.

### 1.2 Lacunas críticas
* **Criptografia CMS/PKCS#7**: não há construtor de SignedData (DER/ASN.1) nem pipeline integrado.
* **Parser de PDF existente**: `PdfDocumentParserBase` é abstrata (sem leitura de xref/stream/trailer).
* **Assinatura externa (A3)**: falta API clara para digest → assinatura → embed.
* **Validação**: inexistente no pdf_plus (ByteRange/CMS/chain/revogação/LTV).
* **Compliance ICP‑Brasil**: ausência de policy engine, LPA e regras PBAD.

---

## 2. Visão de Arquitetura Alvo

### 2.1 Módulos propostos
1. **Assinatura (Signing)**
    * CMS/PKCS#7 (Detached)
    * ByteRange/placeholder
    * Assinador interno (A1) + externo (A3)
    * Aparência visual (AP)

2. **Validação (Validation)**
    * Parser seguro para ByteRange/Contents
    * Validação CMS (assinatura, atributos, cadeia, revogação)
    * PAdES‑T/LT/LTA (DSS/VRI, TSA)
    * Policy ICP‑Brasil (LPA)

3. **Parser e Edição Incremental**
    * Leitura de xref/trailer/objects
    * Escrita incremental robusta e controle de `/Prev`
    * Operações de edição seguras (append‑only quando necessário)

---

## 3. Roteiro Completo por Fases

### Fase 0 — Preparação e fundação técnica
**Objetivo:** estabelecer estrutura mínima e dependências.

1. **Dependências mínimas** (pubspec):
    * `asn1lib` (DER/ASN.1)
    * `pointycastle` ou `cryptography` (RSA, SHA‑256)
    * `intl` (datas em metadados)

2. **Organização de módulos**:
    * `lib/src/pdf/signing/` (assinatura)
    * `lib/src/pdf/validation/` (validação)
    * `lib/src/pdf/parsing/` (parser e leitura)

3. **API pública mínima**:
    * `PdfSigner.sign(...)`
    * `PdfExternalSigner` (A3)
    * `PdfSignatureAppearance` (aparência)
    * `PdfSignatureValidator.validateAllSignatures(...)`

**Critério de aceite:** projeto compila com stubs e testes base (sem assinatura real).

---

### Fase 1 — Assinatura PAdES básica (núcleo)
**Objetivo:** assinar PDF com CMS Detached + ByteRange correto.

1. **CMS/PKCS#7 (SignedData)**
    * Implementar `PdfCmsSigner` com:
      * `SignedAttributes` mínimos: `contentType`, `messageDigest`, `signingTime`.
      * Suporte a RSA + SHA‑256.
      * Embedding da cadeia de certificados.

2. **ByteRange e placeholder**
    * Ajustar `PdfSignature.writeSignature()` para:
      * Reservar espaço fixo para `/Contents`.
      * Calcular ByteRange correto.
      * Preencher `/Contents` com hex do CMS.

3. **Classe concreta de assinatura**
    * `PdfPadesSigner extends PdfSignatureBase`:
      * `preSign()` escreve `/Filter`, `/SubFilter`, `/ByteRange`, `/Contents`.
      * `sign()` calcula hash e injeta CMS.

**Critério de aceite:** PDF assinado é validado no Acrobat/Adobe Reader e PDFBox (assinatura válida).

---

### Fase 2 — Assinatura externa (A3/Token)
**Objetivo:** permitir assinatura com hardware e serviços externos.

1. **Interface externa**
    * `PdfExternalSigner.signDigest(Uint8List digest)`.

2. **Fluxo de assinatura externa**
    * Preparar PDF → extrair ByteRange → calcular hash → chamar callback externo → embed.
    * Referência: fluxo `PdfExternalSigning` no `insinfo_dart_pdf`.

**Critério de aceite:** assinatura com token via callback, PDF validado.

---

### Fase 3 — Aparência visual (Signature Appearance)
**Objetivo:** assinatura visível interoperável.

1. **AP (Appearance Stream)**
    * Gerar `Form XObject` para `/AP` no widget de assinatura.
    * Compatibilidade com rotação e escalas.

2. **API de aparência**
    * Texto, imagem, data, selo.
    * Layout básico (camada de texto + imagem).

**Critério de aceite:** assinatura visível exibida corretamente em leitores comuns.

---

### Fase 4 — Validação PAdES (nível básico)
**Objetivo:** validar assinatura e integridade.

1. **Parser seguro de ByteRange/Contents**
    * Evitar regex por padrão (modelo de `insinfo_dart_pdf`).

2. **Validação CMS**
    * Verificar assinatura criptográfica.
    * Verificar `messageDigest` vs hash real.
    * Reportar por assinatura: `cms`, `digest`, `intact`.

3. **Cadeia e datas**
    * Validar notBefore/notAfter com `signingTime`.

**Critério de aceite:** relatório por assinatura e validação cruzada com PDFs reais.

---

### Fase 5 — Revogação, TSA e LTV (PAdES‑T/LT/LTA)
**Objetivo:** expandir validação e gerar DSS/VRI.

1. **Revogação (CRL/OCSP)**
    * Implementar clientes e parsing ASN.1 (CRL/OCSP).
    * Inserir dados de revogação no DSS.

2. **TSA (RFC 3161)**
    * Gerar request e validar response (TimeStampToken).

3. **DSS/VRI**
    * DSS com CRL/OCSP/certs.
    * VRI por assinatura com hash correto.

**Critério de aceite:** PDFs gerados passam em validadores PAdES‑LT.

---

### Fase 6 — Compliance ICP‑Brasil (PBAD)
**Objetivo:** validação jurídica no padrão ICP‑Brasil.

1. **LPA (Lista de Políticas de Assinatura)**
    * Parser oficial e cache local.
    * Verificar OID + digest.

2. **Constraints por política**
    * Algoritmos permitidos por período.
    * Atributos obrigatórios (signed/unsigned).

3. **Relatório de compliance**
    * Diferenciar “policy ausente” vs “policy inválida”.

**Critério de aceite:** validações ICP‑Brasil reproduzem resultados de validadores oficiais.

---

### Fase 7 — Parser de PDF e atualização incremental robusta
**Objetivo:** leitura de PDFs existentes e edição segura.

1. **Parser completo**
    * Header, xref (table/stream), trailer, objetos.
    * Resolver objetos indiretos e streams.

2. **Edição incremental correta**
    * Nova xref apenas com objetos alterados.
    * Trailer com `/Prev`.
    * Respeitar DocMDP e permissões.

**Critério de aceite:** PDFs editados preservam assinaturas anteriores.

---

### Fase 8 — Operações de edição (MVP)
**Objetivo:** entregar valor prático sem quebrar assinaturas.

1. **Operações mínimas**
    * Inserir/remover páginas.
    * Adicionar anotações e campos.
    * Carimbar texto/imagem.
    * Atualizar metadata.

2. **Operações avançadas (opcionais)**
    * Edição de content streams.
    * OCR/reflow (fora do escopo inicial).

**Critério de aceite:** mudanças persistem sem corromper PDF nem invalidar assinaturas (quando permitido).

---

### Fase 9 — Testes, ferramentas e validação cruzada
**Objetivo:** garantir confiabilidade e regressão controlada.

1. **Testes unitários**
    * ByteRange, CMS, parser, LTV.

2. **Testes de integração**
    * Validar com PDFBox/iText.
    * PDFs reais de Gov.br/ICP‑Brasil.

3. **Ferramentas**
    * CLI para validar assinaturas.
    * Scripts de geração de PDFs de teste.

**Critério de aceite:** pipeline automatizado com outputs consistentes em validadores externos.

---

### Fase 10 — Performance e segurança
**Objetivo:** robustez e eficiência em escala.

1. **Parser seguro**
    * Mitigar “shadow attacks” e manipulações de incremental updates.

2. **Performance**
    * Evitar múltiplas cópias de buffers.
    * Streaming em ByteRange.

3. **Hardening**
    * Limites de tamanho para `/Contents` e objetos suspeitos.

---

## 4. Tabela de Porting (pdf_plus ⇄ insinfo_dart_pdf)

| Funcionalidade | pdf_plus (alvo) | insinfo_dart_pdf | Observação |
| :--- | :--- | :--- | :--- |
| Assinatura externa | `PdfExternalSigner` | `PdfExternalSigning` | fluxo digest→sign→embed |
| Parser seguro ByteRange | `PdfSignatureUtils` | `PdfSignatureUtils` | evitar regex |
| Validador PAdES | `PdfSignatureValidator` | `pdf_signature_validator.dart` | relatório por assinatura |
| LTV/DSS | `PdfLtvManager` | `pdf_ltv_manager.dart` | VRI + DSS |
| Policy ICP‑Brasil | `PolicyEngine` | `icp_brasil/` | LPA + constraints |

---

## 5. Entregáveis por Marcos

* **M1 (Fase 1‑2):** Assinatura PAdES básica + assinatura externa A3.
* **M2 (Fase 3):** Aparência visual interoperável.
* **M3 (Fase 4‑5):** Validação PAdES + revogação + TSA + LTV.
* **M4 (Fase 6):** Compliance ICP‑Brasil (PBAD).
* **M5 (Fase 7‑8):** Parser completo + edição incremental + operações MVP.

---

## 6. Status de Implementação (atualizado)

Implementado (PAdES núcleo):

* **CMS Detached RSA/SHA‑256** com `signedAttrs` (contentType, messageDigest, signingTime).
* **ByteRange com placeholder fixo** e preenchimento em-place.
* **/Contents** com reserva binária e embed de CMS em hex.
* **Signer RSA** com PEM (PKCS#1/PKCS#8 não criptografado) para A1.
* **Fachada de assinatura** (`PdfSigner.signDocument`) para documentos gerados pelo pdf_plus.
* **Validador básico**: ByteRange + integridade via `messageDigest` do CMS.
* **Parser mínimo**: leitura de `startxref` e tamanho de objetos para suporte inicial.

Limitações atuais (a endereçar nas próximas fases):

* Validação ainda não verifica assinatura criptográfica (apenas ByteRange + `messageDigest`).
* Parser ainda não reconstrói objetos antigos para edição incremental completa.

Arquivos atualizados/criados:

* [lib/src/pdf/signing/pdf_cms_signer.dart](lib/src/pdf/signing/pdf_cms_signer.dart)
* [lib/src/pdf/signing/pdf_pades_signer.dart](lib/src/pdf/signing/pdf_pades_signer.dart)
* [lib/src/pdf/signing/pdf_signer.dart](lib/src/pdf/signing/pdf_signer.dart)
* [lib/src/pdf/signing/pdf_rsa_signer.dart](lib/src/pdf/signing/pdf_rsa_signer.dart)
* [lib/src/pdf/signing/pem_utils.dart](lib/src/pdf/signing/pem_utils.dart)
* [lib/src/pdf/validation/pdf_signature_validator.dart](lib/src/pdf/validation/pdf_signature_validator.dart)
* [lib/src/pdf/parsing/pdf_document_parser.dart](lib/src/pdf/parsing/pdf_document_parser.dart)

---

## 6. Próximos Passos Imediatos (ações curtas)

1. Criar esqueleto dos módulos `signing`, `validation` e `parsing`.
2. Implementar `PdfCmsSigner` mínimo e `PdfPadesSigner`.
3. Criar fluxo externo (digest → callback → embed).
4. Criar teste base de assinatura e validação em PDFBox/iText.

