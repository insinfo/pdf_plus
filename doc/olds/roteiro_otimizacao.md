Atualização 2026-01-29 (status real no pdf_plus)

Implementado:
- Parser robusto com xref table/stream e cadeia /Prev.
- Reconstrução de catálogo e pages via xref, com suporte a ObjStm.
- Fallback de reparo por varredura: detecta “N N obj”, registra offsets e pula streams usando /Length quando possível (estilo MuPDF).
- Correção de offsets negativos (overflow 32-bit) via +2^32 ao validar objetos.
- Busca dirigida de objetos em head/tail antes de varrer o arquivo todo.
- Limite de decode de streams (cap de 256MB) para evitar alocação excessiva.

Próximos passos imediatos:
- Leitura randômica (RandomAccess + cache LRU) para não carregar o PDF todo na RAM.
- Scan parcial com early-stop (Root/Pages/1ª Page) e indexação sob demanda.
- Limites de alocação por stream + decode em chunks.
- Heurística de busca dirigida para /Root quando startxref faltar.

Compatibilidade Web + Dart VM (estratégia recomendada)
- Criar uma interface única de leitura randômica: PdfRandomAccessReader.
- Implementação Dart VM: RandomAccessFile + cache LRU de blocos.
- Implementação Web: Uint8List/Blob + cache de janelas (sem dart:io), leitura por slice.
- Usar import condicional (if dart.library.io / dart.library.js_interop) para escolher a implementação.
- Evitar duplicar lógica de parsing: o parser deve depender apenas da interface de reader.


Analisei o pdf‑repair.c. Ele é bem “lean”: só parseia dicionário para achar /Length e /Type, pula stream via seek quando tem /Length, e usa um scan simples de “endstream” quando não tem. Também evita resolver indiretos e mantém Root/Encrypt/ID durante o scan. Veja pdf-repair.c.

No Dart já está bem próximo, mas ainda vale melhorar:

Scan leve de dicionário no repair: substituir _readDict por um parser mínimo que só busca /Length (direto) e /Type para /Catalog. Isso corta alocações e CPU.
Reaproveitar maxObjId do repair: já que o scan percorre objetos, dá para capturar o maior ID e evitar _maxObjectIdFromReader depois.
BMH para busca de tokens curtos (endstream, xref, trailer) durante scan: reduz custo de O(n*m).
Janela menor no startxref (2–4KB) e buffer reutilizável no reader para reduzir GC.

motor nativo tolerante a falhas (Foxit/Acrobat/Sumatra) e um viewer JS (pdf.js) que roda dentro das limitações do navegador.

SumatraPDF é extremamente rápido porque ele é “casca fina” em cima do MuPDF (engine C muito otimizada).

O MuPDF tem um caminho explícito de “reparar xref” varrendo o arquivo e reconstruindo a tabela de objetos (“scan file for objects and reconstruct xref table”).

O pdf.js pode morrer com allocation size overflow (exatamente o erro do seu print) e, em PDFs grandes, também pode ficar muito mais pesado que Acrobat porque tende a usar muita memória/cache de render.

Abaixo vai um roteiro de parser/loader otimizado (estilo Foxit/Sumatra), focado em abrir rápido PDFs enormes e “tortos” (xref quebrado, trailer ruim, offsets >2GB etc.), sem tentar “consertar” o arquivo.

Roteiro: “Fast Open” + “Fallback Repair” (sem varrer 3GB de cara)
0) Princípios de performance (essenciais)

Nunca carregue o arquivo todo na RAM. Use leitura randômica + cache por janelas (ex.: 64KB/256KB).

Offsets sempre em 64-bit (int64). PDF de 3GB vai passar de 2^31.

Abrir ≠ validar: abra com um índice mínimo (Root + Pages + 1ª página).

Streams nunca podem alocar por /Length sem limite: implemente “cap” e decode por blocos (evita “allocation overflow” estilo pdf.js).

Fase A — “Fast Open” (tentar caminho normal, tolerante)
A1) Ler header e detectar linearização (barato)

Leia os primeiros ~4KB:

validar %PDF-1.x

procurar /Linearized (se existir, dá pra abrir super rápido sem precisar do xref final)

A2) Ler o “tail” e achar startxref do jeito mais robusto possível

Leia só o final (ex.: últimos 1MB; se não achar, 8MB/32MB).

Procure de trás pra frente:

%%EOF

startxref

número logo após startxref

Valide o offset: 0 <= startxref < fileSize.

Se inválido, não morra: marque xrefBroken=true e vá para a Fase B.

A3) Parser de xref “tolerante”

Suporte:

xref “tabela” (xref ... trailer)

xref “stream” (/Type /XRef em um objeto stream)

incremental updates (/Prev no trailer): seguir cadeia até quebrar, guardando o trailer mais novo “válido”.

Validações rápidas:

offsets fora do arquivo → ignore a entrada (não explode).

obj repetido → mantenha a entrada “mais nova” (incremental).

A4) Obter /Root e caminhar a árvore de páginas sem resolver tudo

Com /Root:

pega /Pages

caminha /Kids recursivamente

só coleta referências (objNum/gen) das páginas

não resolve /Resources, /Contents, fontes etc. ainda.

Isso dá “abriu em 1–4s” porque você só tocou em dezenas/centenas de objetos, não em milhões de bytes de imagem.

Fase B — Fallback quando xrefBroken (estilo MuPDF, mas “mínimo para abrir”)

Aqui é onde Sumatra/MuPDF brilham: quando xref falha, eles têm modo de reconstrução por varredura.
Só que pra abrir rápido, você não precisa reconstruir tudo.

B1) Reparar “local” (sem varrer o arquivo inteiro)

Tente primeiro sem scan completo:

No tail que você já leu, procure:

trailer + << ... >>

/Root <n> <g> R

/Prev (se existir)

Se achou /Root n g R, tente localizar o objeto por busca dirigida:

procurar a string \n{n} {g} obj em janelas grandes (ex.: 8MB) começando:

perto do startxref (se semi-válido),

e depois em regiões prováveis (próximo ao fim, em caso de incremental).

Achou o objeto Root → a partir daí, o resto vira Fase A4 (walk do page tree).

Isso evita scan de 3GB.

B2) Scan parcial (quando o Root não aparece fácil)

Se a busca dirigida falhar:

Faça scan sequencial por blocos (ex.: 16MB):

procure padrões (\d+)\s+(\d+)\s+obj

e dentro do objeto procure:

/Type /Catalog → candidato a Root

/Type /Pages → candidato a Pages

Pare assim que conseguir montar:

Root → Pages → primeira Page

O MuPDF tem exatamente a ideia de “scan do arquivo para achar objetos e reconstruir xref”.
Você só está fazendo uma versão “early stop”.

B3) Só depois (se precisar), indexe o resto

Se o usuário navegar para página X e você não tiver índice suficiente:

ou faz “on demand scan” até achar os objetos necessários,

ou monta um índice mais completo (aí sim pode custar tempo).

Proteções anti-“pdf.js explode” (o seu caso)

O erro do seu print (allocation size overflow) é típico de:

número gigante/corrompido virando tamanho de array/string,

ou stream com /Length absurdo levando a alocação enorme.

Então no seu parser:

limite máximo de alocação (ex.: 256MB por stream, configurável)

decode de stream em chunks

sanity-check de inteiros (se Length < 0 ou Length > fileSize, trate como “unknown length” e leia até endstream com limite)

Por que Acrobat/Foxit parecem “sem background”

Mesmo quando não tem CPU depois, eles podem ter feito:

só o “mínimo” (Root + Pages + 1ª página),

e deixado o resto completamente lazy.
Isso bate com a observação do pdf.js: Acrobat tende a re-renderizar conforme precisa, e pdf.js pode ser bem mais pesado em memória/tempo em PDFs grandes.

Implementação prática em Dart (estrutura sugerida)

RandomAccessReader com cache de janelas:

readAt(int64 offset, int length) -> Uint8List

cache LRU de blocos (ex.: 256KB)

Lexer incremental (sem regex) que opera em “slice”

XrefIndex:

modo normal: Map<int objNum, (int64 off, int gen, bool inUse)>

modo fallback: índice parcial (só objetos críticos)

ObjectCache (LRU) para objetos já parseados

OpenStrategy:

tenta linearized → tenta xref normal → fallback repair local → scan parcial → (opcional) scan total

A função principal é a pdf_repair_xref_base (linha 475).
Aqui está a análise técnica do algoritmo do MuPDF e, em seguida, a implementação otimizada para Dart para obter a velocidade que você deseja.
O Algoritmo do MuPDF (pdf-repair.c)
O algoritmo não é "inteligente" no sentido de IA, ele é bruto e linear, mas otimizado para pular dados irrelevantes.
Ignora o XREF original: Ele assume que a tabela de endereços está lixo.
Scan Sequencial (Linha 530+): Ele começa do byte 0 e lê o arquivo inteiro, token por token (pdf_lex_no_string).
Busca de Padrão (Linha 557+): Ele procura a sequência de tokens:
INTEIRO (Número do Objeto)
INTEIRO (Número de Geração)
KEYWORD 'obj'
Mapeamento: Quando encontra esse padrão, ele grava a posição (offset) em um array (list[listlen]).
Pulo de Conteúdo (Fast Skip): Dentro de pdf_repair_obj (linha 81), se ele encontrar um dicionário, ele lê o /Length. Se encontrar um stream, ele pula Length bytes à frente em vez de ler byte a byte. Isso é crucial para a performance em arquivos de 3GB cheios de imagens.
Como implementar isso em Dart (Alta Performance)
Para abrir um arquivo de 3GB em segundos em Dart, você não pode converter bytes para String o tempo todo e não pode usar Regex no arquivo todo.
Aqui está o FastPdfRepair em Dart, traduzindo a lógica do C para Dart Assíncrono e Bufferizado.
Estratégia "Híbrida" (Recomendada)
Tentativa Matemática (Ouro): Como seu erro é "offset negativo", o arquivo provavelmente está estruturalmente intacto, apenas os números da tabela xref estouraram o limite de 32-bit (Bug do iText). O código abaixo tenta corrigir isso matematicamente sem escanear o arquivo todo.
Scan Otimizado (Fallback): Se a matemática falhar, roda o scan estilo MuPDF.
code
Dart
import 'dart:io';
import 'dart:typed_data';
import 'dart:math';

class PdfFastRepair {
  final RandomAccessFile _raf;
  final int _fileLength;
  
  // Mapa de Objetos Recuperados: ID -> Offset
  final Map<int, int> _xref = {};
  int? rootObject;

  PdfFastRepair._(this._raf, this._fileLength);

  static Future<PdfFastRepair> open(File file) async {
    final raf = await file.open(mode: FileMode.read);
    final len = await file.length();
    return PdfFastRepair._(raf, len);
  }

  /// 1. Tenta a correção "Mágica" do iText (Sem scan completo)
  /// O Bug do iText grava offsets negativos quando passa de 2GB.
  /// Simplesmente converter de Int32 assinado para Int64 não assinado resolve.
  Future<bool> tryItextOffsetRepair() async {
    // Lê o trailer (últimos 2KB)
    final tailSize = min(2048, _fileLength);
    await _raf.setPosition(_fileLength - tailSize);
    final tailBytes = await _raf.read(tailSize);
    
    // Converte para string (safe porque é só o finalzinho)
    // Usando Latin1 para evitar exceções de UTF8 em binário
    final tailStr = String.fromCharCodes(tailBytes);

    // Procura startxref
    final startXrefRegex = RegExp(r'startxref\s+(\d+)', multiLine: true);
    final match = startXrefRegex.allMatches(tailStr).lastOrNull;

    if (match == null) return false;

    // Se o startxref apontar para algo válido, tenta ler a tabela XREF lá
    int startXref = int.parse(match.group(1)!);
    
    // Validação básica
    if (startXref > _fileLength) return false;

    print("Tentativa iText: Lendo XRef em $startXref");
    
    // Aqui você tentaria ler a tabela Xref. 
    // SE encontrar offsets negativos dentro da tabela (ex: -1157262503):
    // A correção é: offsetReal = offsetLido + 4294967296 (2^32);
    
    // Como não temos o parser completo aqui, vamos assumir que falhou
    // e ir para o Scan, que é o que você queria ver.
    return false;
  }

  /// 2. O Algoritmo do MuPDF (pdf-repair.c) portado para Dart
  /// Varre o arquivo procurando "d d obj"
  Future<void> scanForObjects() async {
    print("Iniciando Scan Rápido (Estilo MuPDF)...");
    
    final bufferSize = 1024 * 1024; // 1MB de buffer
    final buffer = Uint8List(bufferSize);
    int filePos = 0;
    
    // Padrão ' obj' em bytes: [32, 111, 98, 106] ou [13, 111...], etc.
    // Simplificação: procurando bytes 'obj'
    
    // Estado do parser simplificado
    int lastInt = -1;
    int secondLastInt = -1;
    
    while (filePos < _fileLength) {
      int readBytes = await _raf.readInto(buffer);
      if (readBytes == 0) break;

      // Percorre o buffer
      for (int i = 0; i < readBytes; i++) {
        final b = buffer[i];

        // Lógica de Tokenizer ultra-rápida (State Machine)
        // No C, eles usam pdf_lex. Aqui simplificamos para achar "N N obj".
        
        // Se encontramos 'o' (111), verificamos se é "obj"
        if (b == 111) {
          if (i + 2 < readBytes && buffer[i+1] == 98 && buffer[i+2] == 106) {
             // Achamos "obj". Validar se temos dois inteiros antes.
             // Isso requer um buffer de contexto ou parser mais complexo.
             // Para simplificar o exemplo, assumimos sucesso se acharmos o padrão.
             
             // Em um parser real, você capturaria os números anteriores.
             // Vamos simular que recuperamos o objeto X no offset FilePos + i
             
             // A GRANDE OTIMIZAÇÃO DO MUPDF (Linha 138 de pdf-repair.c):
             // Se detectarmos "stream", lemos o "/Length" e pulamos bytes!
             // _raf.setPosition(posAtual + length);
          }
        }
      }
      
      filePos += readBytes;
      // Ajuste para não quebrar tokens entre buffers
      if (filePos < _fileLength) {
        filePos -= 20; 
        await _raf.setPosition(filePos);
      }
    }
    print("Scan finalizado.");
  }
  
  /// OTIMIZAÇÃO SUPREMA (Foxit/Sumatra):
  /// Em vez de escanear o arquivo todo, escaneia APENAS o trailer para achar o /Root.
  /// E depois busca objetos sob demanda.
  Future<void> fastOpenHeuristic() async {
    // 1. Achar o /Root no final do arquivo
    // 2. O Root diz onde estão as páginas (Objeto "Pages")
    // 3. Se precisamos renderizar a Página 1, procuramos APENAS o objeto da página 1.
    
    // Exemplo de busca reversa por "N 0 obj" se soubermos o ID
    // Isso é muito mais rápido que ler 3GB.
  }

  void close() {
    _raf.close();
  }
}
Explicação da Otimização do stream (O segredo do MuPDF)
No código C que você mandou, olhe a linha 175 do pdf-repair.c:
code
C
obj = pdf_dict_get(ctx, dict, PDF_NAME(Length));
		if (!pdf_is_indirect(ctx, obj) && pdf_is_int(ctx, obj))
			stm_len = pdf_to_int64(ctx, obj);
E depois na linha 213:
code
C
if (stm_len > 0)
		{
			fz_seek(ctx, file, *stmofsp + stm_len, 0);
            // ... verifica se caiu no endstream ...
        }
O que isso faz:
Se ele encontra um objeto de imagem de 50MB:
Ele lê o dicionário: << /Length 52428800 ... >> stream.
Ele lê o valor de Length.
Ele dá um seek (pula) 50MB para frente.
O erro do PDF.js: O PDF.js (e parsers ingênuos) tentam ler o conteúdo do stream para validar ou procurar o endstream byte a byte. Em um arquivo de 3GB, isso mata o processo.
A solução: Apenas confie no /Length e pule. Se o /Length estiver errado, aí sim você faz o fallback para o scan lento.
Resumo para seu Dart
Não use readAsBytesSync ou carregue tudo na memória. Use RandomAccessFile e buffers pequenos (64kb - 1MB).
Use int64 para offsets: O Dart faz isso nativamente, o C precisa de int64_t. O bug do iText é porque usaram int32. Se você ler um offset negativo, some 4294967296 e tente dar um setPosition nesse novo valor. Se achar um objeto lá, bingo! Você "consertou" o arquivo em 0.01ms.
Implemente o "Pulo de Stream": Ao escanear, se ver stream, tente ler o /Length e pular os bytes. Isso fará seu scan voar sobre as imagens gigantes.

Pelo seu log do mutool, esse PDF está sem startxref (“cannot find startxref”), então o leitor precisa entrar em modo de reparo: reconstruir um xref válido varrendo o arquivo e “redescobrindo” os objetos. Isso é exatamente o tipo de coisa que o MuPDF faz bem — e o SumatraPDF herda isso porque usa o MuPDF como motor de PDF.
Já o pdf.js costuma quebrar nesses casos porque, sem xref confiável, ele pode acabar tentando criar estruturas gigantes (por exemplo, por causa de /Size/offsets/larguras inválidas), e aí explode com erro de alocação.

Abaixo vai um roteiro de parser/loader otimizado (fast-path + fallback de reparo) e, depois, um “mapa” bem objetivo de onde se inspirar no MuPDF/Sumatra (funções/fluxo).

1) Roteiro otimizado para abrir PDFs grandes (inclusive quebrados)
Fase A — Fast-path (abrir “instantâneo” quando dá)

Objetivo: mostrar a página 1 rápido sem “varrer o mundo”.

Abrir em modo streaming/mmap

Use memory mapping quando disponível (Windows: CreateFileMapping; Linux: mmap) para leitura randômica barata.

Tenha um RandomAccessReader com:

readRange(offset, len) (pequenas leituras)

findBackward(pattern, from, maxScan)

findForward(pattern, from, to)

Buscar startxref no final

Leia os últimos 64 KiB e procure startxref.

Se não achar, aumente para 1–4 MiB (sem ler o arquivo todo).

Quando achar, parseie o número (offset do xref) e valide 0 <= off < fileSize.

Tentar carregar XRef

Tente ler o xref (tabela clássica xref ou xref stream de PDFs 1.5+).

Do trailer, pegue o mínimo:

/Root (Catalog)

/Size (tamanho da tabela de referência)

(opcional) /Info, /Encrypt, /ID

Observação: o ecossistema PDF gira em torno de xref + trailer + startxref.

Index mínimo de páginas (sem expandir tudo)

Resolva /Root → /Pages.

Construa apenas um índice de páginas:

Percorra a árvore /Kids sob demanda.

Evite materializar 528 páginas logo de cara; materialize “page refs” (obj id + geração) e metadados essenciais (MediaBox/Rotate).

Render/extração sob demanda

Para PDF digitalizado típico (uma imagem por página):

Ao abrir: parseie só a Page 1 + Resources + XObject da imagem.

Não decodifique JPEG das outras 527 páginas.

Resultado: abre em < 1s em leitores tipo Sumatra porque ele não “processa o PDF inteiro”, só o suficiente para exibir algo.

Fase B — Fallback de Reparo (quando falta startxref / xref inválido)

Objetivo: reconstruir um xref funcional com uma varredura linear eficiente.

B1) Varrredura linear para “descobrir objetos”

Faça um scan byte-a-byte (em blocos) procurando cabeçalhos do tipo:

<objNum> <genNum> obj


Heurísticas para ser rápido e evitar falso positivo:

Procure o token " obj" (espaço + obj) e valide para trás:

Deve haver 2 inteiros ASCII imediatamente antes.

Valide o contexto:

objNum razoável (ex.: 0 < objNum < 50_000_000, com limite configurável)

genNum razoável (0..65535)

Registre no índice: objNum -> offset.

Estrutura de dados recomendada:

Map<int, int> objOffset (obj -> offset) enquanto varre

int maxObjNum para depois criar um /Size = maxObjNum+1 (ou manter em mapa se quiser evitar array gigante).

B2) Identificar streams sem explodir tempo/memória

Quando encontrar um objeto:

Parseie rapidamente o dicionário inicial (até stream ou endobj).

Se aparecer stream, pule o corpo do stream:

Preferencial: se /Length for um inteiro direto e “sensato”, pule len bytes e confirme endstream.

Caso /Length seja indireto ou suspeito, faça busca por endstream com um scanner eficiente (ex.: memchr por e e confirmação do token).

Importante: isso impede o scan de “quadruplicar” o custo em PDFs com streams gigantes.

B3) Recuperar o Trailer mínimo

Sem startxref, você precisa inferir:

Quem é o Catalog (/Type /Catalog)

Quem é o Pages root (/Type /Pages)

Quem é o Root (referência ao Catalog)

Estratégia prática:

Após B1, escolha alguns candidatos “prováveis”:

Objetos pequenos (offsets perto do início)

Objetos com dicionário contendo /Type /Catalog

Parseie esses poucos objetos completamente (sem streams) até achar o Catalog.

B4) Tratar objetos comprimidos (ObjStm)

Se o PDF tiver /Type /ObjStm:

Depois de ter um xref básico (obj -> offset), percorra objetos do tipo ObjStm:

Leia o stream, parseie o cabeçalho (pares objNum objOff internos) e crie um mapeamento “objeto comprimido”.

Isso é crucial para PDFs 1.5+.

B5) Construir um xref “virtual”

Você pode:

Manter internamente um índice obj -> offset (sem reescrever o arquivo), ou

Opcionalmente gerar um xref/trailer novo (útil se você quiser exportar um “repaired.pdf”).

2) Onde se inspirar no MuPDF (funções e fluxo)

Mesmo sem abrir o startxref, o MuPDF segue a ideia: tentar xref normal → se falhar, reparar.

Os pontos-chave (nomes exatos) que você quer “espelhar”:

pdf_repair_xref(...): coração do reparo do xref (varredura/recuperação).

pdf_repair_obj_stms(...): reconstrução/expansão de objetos em object streams (ObjStm).

O seu log (“cannot find startxref” + “trying to repair broken xref” + “repairing PDF document”) é exatamente o caminho em que o MuPDF decide: “não dá para confiar no xref → roda repair”.

Como transformar isso em design no seu parser (Dart):

Tenha um open() que chama:

tryOpenWithXref()

se falhar → repairXrefByScan() (equivalente conceitual de pdf_repair_xref)

depois → repairObjStreamsIfNeeded() (conceitual de pdf_repair_obj_stms)

3) Onde se inspirar no SumatraPDF (fluxo)

O Sumatra abre rápido por dois motivos práticos:

Ele usa MuPDF como engine (logo, herda o repair e o parsing incremental).

Ele é agressivo em “lazy everything”: constrói o mínimo para renderizar a primeira página e deixa o resto sob demanda.

Então, no seu projeto Dart, a “lição Sumatra” é menos “rodar repair em background” e mais:

Index mínimo

Page tree lazy

Não decodificar 528 JPEGs na abertura

Cache pequeno e inteligente (objeto e dicionário; stream só quando necessário)

4) Guard-rails indispensáveis (pra não cair no erro do pdf.js)

Quando o arquivo é quebrado, você precisa impor limites defensivos:

Limite máximo de /Size aceito sem confirmação (ex.: se /Size > alguns milhões, não aloque array direto; use Map).

Limite de /Length e validação de endstream.

Detecção de loops na árvore /Pages (Kids recursivo).

Parsing tolerante a \r\n e variações de whitespace.

Isso evita justamente “alocações absurdas” quando algum número do PDF vem corrompido.

Se você quiser, eu te devolvo isso já como um esqueleto de implementação em Dart (um arquivo único tipo pdf_open_pipeline.dart com tryOpenWithXref() + repairXrefByScan() + buildLazyPageIndex()), pronto pra você plugar no pdf_plus.


Aqui está a implementação otimizada do PdfDocumentParser focada em performance para arquivos gigantes (3GB+) e reparo de bugs do iText (offsets negativos).
Esta versão substitui o uso de Uint8List (memória RAM) por RandomAccessFile (Disco) com um sistema de Buffering Inteligente, e implementa a lógica do pdf-repair.c do MuPDF, incluindo o "Pulo de Stream" (Stream Skipping) para não ler o conteúdo de imagens durante o reparo.
Principais Alterações:
RandomAccessFile: Não carrega o PDF na memória.
BufferedRandomAccess: Uma classe interna para fazer leitura eficiente (chunks de 64KB) em vez de ler byte a byte do disco.
Correção Matemática (iText Bug): A função _fixOffset detecta overflows de 32-bit e corrige o endereço instantaneamente.
Reparo Otimizado (_repairXrefByScan): Implementa a lógica do MuPDF de ler o /Length do dicionário e pular o stream, tornando o scan de gigabytes questão de segundos.
code
Dart
import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'package:archive/archive.dart';

// --- Classes auxiliares do seu projeto (Mockadas para compilação neste exemplo) ---
import '../document.dart'; // Assumindo existência
import '../page_format.dart'; // Assumindo existência
// ... outros imports do seu projeto ...

/// Parser Otimizado para Grandes Arquivos e Reparo Automático
class PdfDocumentParser {
  final RandomAccessFile _file;
  late final int _fileSize;
  final BufferedRandomAccess _reader;

  // Cache de Xref: ObjId -> Offset/Gen/Type
  final Map<int, _XrefEntry> _xrefEntries = {};
  
  // Cache de Objetos já parseados para não ler do disco 2 vezes
  final Map<int, dynamic> _objectCache = {};

  _TrailerInfo? _trailerInfo;
  bool _isRepairing = false;

  PdfDocumentParser(this._file) : _reader = BufferedRandomAccess(_file);

  Future<void> initialize() async {
    _fileSize = await _file.length();
    await _parseXrefChain();
  }

  /// Tenta carregar a tabela XREF. Se falhar (ex: bug do iText), inicia o reparo.
  Future<void> _parseXrefChain() async {
    try {
      int offset = await _computeXrefOffset();
      final visited = <int>{};

      while (offset > 0 && offset < _fileSize && !visited.contains(offset)) {
        visited.add(offset);
        final info = await _parseXrefAtOffset(offset);
        if (info != null) {
          _trailerInfo = _mergeTrailerInfo(_trailerInfo, info);
          if (info.prev != null && info.prev! > 0) {
            offset = info.prev!;
            continue;
          }
        }
        break;
      }
    } catch (e) {
      print("Erro lendo XRef padrão: $e. Iniciando reparo...");
    }

    // Se falhou ou não achou Root, roda o algoritmo de reparo do MuPDF
    if (_xrefEntries.isEmpty || _trailerInfo?.rootObj == null) {
      await _repairXrefByScan();
    }
  }

  // --- LÓGICA DO MUPDF: REPAIR SCAN COM STREAM SKIPPING ---

  /// O algoritmo "Mágico" do pdf-repair.c traduzido para Dart.
  /// Varre o arquivo procurando "d d obj", lê o dicionário, pega o /Length e PULA o stream.
  Future<void> _repairXrefByScan() async {
    if (_isRepairing) return;
    _isRepairing = true;
    print("Iniciando Scan de Reparo Otimizado...");

    // 1. Tenta achar o Root no final do arquivo (Fast Track)
    await _findRootFromTail();

    // Reset buffer para o inicio
    await _reader.seek(0);
    
    // Variáveis de estado do parser simples (State Machine)
    int? lastInt;
    int? lastIntPos;
    int? prevInt;
    int? prevIntPos;

    // Buffer temporário para checagens locais
    final tempBuff = Uint8List(20); 

    while (await _reader.position < _fileSize) {
      // Pula espaços em branco eficientemente
      if (await _reader.skipWhitespace()) break;

      final pos = await _reader.position;
      final b = await _reader.peekByte();

      // Se for dígito: <num>
      if (_isDigit(b)) {
        final numInfo = await _reader.readInt();
        prevInt = lastInt;
        prevIntPos = lastIntPos;
        lastInt = numInfo.value;
        lastIntPos = pos;
        continue;
      }

      // Se for "obj": <num> <gen> obj
      // 0x6F = 'o'
      if (b == 0x6F) {
        // Verifica se é realmente "obj"
        if (await _reader.match(const [0x6F, 0x62, 0x6A])) { // obj
           if (prevInt != null && lastInt != null && prevIntPos != null) {
             final objId = prevInt;
             final gen = lastInt;
             
             // Registra na XREF recuperada
             _xrefEntries[objId] = _XrefEntry(
               offset: prevIntPos!, 
               gen: gen, 
               type: _XrefType.inUse
             );

             // --- O SEGREDO DA PERFORMANCE: STREAM SKIPPING ---
             // Lê o dicionário para ver se tem /Length
             final dictInfo = await _scanObjectDictAndGetStreamLength();
             
             if (dictInfo.isCatalog && _trailerInfo?.rootObj == null) {
               _trailerInfo = _TrailerInfo(rootObj: objId);
             }

             if (dictInfo.streamLength != null && dictInfo.streamLength! > 0) {
                // Se achou 'stream' e sabe o tamanho, PULA!
                // Verifica se o tamanho é seguro para pular
                final jumpPos = await _reader.position + dictInfo.streamLength!;
                if (jumpPos < _fileSize) {
                   await _reader.seek(jumpPos);
                }
             }
           }
           // Reseta estado
           prevInt = null; lastInt = null;
        }
        continue;
      }

      // Avança um byte se nada casou
      await _reader.readByte();
    }
    print("Scan finalizado. Objetos recuperados: ${_xrefEntries.length}");
  }

  /// Lê o dicionário do objeto atual, extrai /Length e verifica se é /Catalog
  Future<({int? streamLength, bool isCatalog})> _scanObjectDictAndGetStreamLength() async {
    await _reader.skipWhitespace();
    
    // Se não começar com <<, não é dicionário, retorna
    if (!await _reader.match(const [0x3C, 0x3C])) { // <<
      return (streamLength: null, isCatalog: false);
    }

    // Parser simplificado de dicionário apenas para achar /Length e /Type
    // Não parseia tudo para economizar CPU
    int? length;
    bool isCatalog = false;
    
    // Lê chaves até achar >>
    while (true) {
        await _reader.skipWhitespace();
        final b = await _reader.peekByte();
        
        if (b == 0x3E) { // >
           await _reader.readByte();
           if (await _reader.peekByte() == 0x3E) { // >>
             await _reader.readByte();
             break; // Fim do dicionário
           }
           continue;
        }

        if (b == 0x2F) { // /
           final name = await _reader.readName();
           
           if (name == '/Length') {
             await _reader.skipWhitespace();
             // Tenta ler o inteiro direto. Se for referência (R), ignoramos no modo scan rápido.
             try {
               final val = await _reader.readInt();
               // Verifica se não é seguido de 'R' (Reference)
               await _reader.skipWhitespace();
               if (await _reader.peekByte() != 0x52) { // 'R'
                 length = val.value;
               }
             } catch (_) {}
           } else if (name == '/Type') {
             await _reader.skipWhitespace();
             if (await _reader.match(const [0x2F, 0x43, 0x61, 0x74, 0x61, 0x6C, 0x6F, 0x67])) { // /Catalog
               isCatalog = true;
             }
           }
        } else {
          // Pula qualquer outra coisa (string, array, etc) de forma rudimentar
          await _reader.readByte(); 
        }
    }

    // Procura a palavra 'stream' logo após o dicionário
    await _reader.skipWhitespace();
    if (await _reader.match(const [0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) { // stream
       // Pula CRLF
       var c = await _reader.peekByte();
       if (c == 0x0D) { await _reader.readByte(); c = await _reader.peekByte(); }
       if (c == 0x0A) { await _reader.readByte(); }
       
       return (streamLength: length, isCatalog: isCatalog);
    }

    return (streamLength: null, isCatalog: isCatalog);
  }

  // --- CORREÇÃO MATEMÁTICA (iText Bug) ---

  /// Verifica se o objeto está no offset. Se falhar, tenta a correção de overflow 32-bit.
  Future<int> _fixOffset(int objId, int gen, int offset) async {
    // 1. Tenta offset original
    if (await _isValidObjAtOffset(objId, gen, offset)) return offset;

    // 2. Tenta correção de overflow (Bug do iText antigo em arquivos > 2GB)
    // Se o offset for negativo (interpretado como int32), soma 2^32
    if (offset < 0) {
      final corrected = offset + 0x100000000; // + 4294967296
      if (await _isValidObjAtOffset(objId, gen, corrected)) {
        return corrected;
      }
    }
    
    // 3. Fallback: Procura num raio de 4KB (Pequenos erros de alinhamento)
    // (Omitido para brevidade, mas segue a lógica do raio do seu código original)
    return offset;
  }

  Future<bool> _isValidObjAtOffset(int objId, int gen, int offset) async {
    if (offset < 0 || offset >= _fileSize) return false;
    
    final oldPos = await _reader.position;
    try {
      await _reader.seek(offset);
      await _reader.skipWhitespace();
      
      final idCheck = await _reader.readInt();
      if (idCheck.value != objId) return false;
      
      await _reader.skipWhitespace();
      final genCheck = await _reader.readInt();
      if (genCheck.value != gen) return false;
      
      await _reader.skipWhitespace();
      return await _reader.match(const [0x6F, 0x62, 0x6A]); // obj
    } catch (_) {
      return false;
    } finally {
      await _reader.seek(oldPos);
    }
  }

  // --- LÓGICA DE STARTXREF (Leitura Reversa) ---

  Future<int> _computeXrefOffset() async {
    // Lê os últimos 2KB do arquivo
    final int tailSize = min(2048, _fileSize);
    await _reader.seek(_fileSize - tailSize);
    final tailBytes = await _reader.readBytes(tailSize);
    
    // Procura 'startxref' do fim para o começo
    final token = const [0x73, 0x74, 0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66]; // startxref
    int pos = _lastIndexOf(tailBytes, token);
    
    if (pos == -1) throw Exception("startxref not found");
    
    // Parseia o número após startxref
    // Precisamos ajustar a posição relativa do buffer para absoluta do arquivo
    final absPos = (_fileSize - tailSize) + pos + token.length;
    await _reader.seek(absPos);
    await _reader.skipWhitespace();
    return (await _reader.readInt()).value;
  }

  Future<void> _findRootFromTail() async {
     // Implementação similar ao computeXrefOffset, mas procurando /Root
     // e atualizando _trailerInfo se encontrar.
  }

  // --- Parsing XREF (Simplificado para o exemplo) ---
  
  Future<_TrailerInfo?> _parseXrefAtOffset(int offset) async {
    // Aqui entra a lógica de ler Xref Table ou Xref Stream
    // Usando _reader.seek(offset) e lendo os dados.
    // É crucial usar _fixOffset(obj, gen, readOffset) ao popular _xrefEntries
    return null; // Placeholder
  }

  // ... (Restante da lógica de parsing de objetos on-demand usando _reader) ...
}


/// Wrapper eficiente para RandomAccessFile com Buffer de Leitura
/// Evita chamadas de sistema (I/O) para cada byte lido.
class BufferedRandomAccess {
  final RandomAccessFile _file;
  static const int _bufferSize = 64 * 1024; // 64KB Buffer
  final Uint8List _buffer = Uint8List(_bufferSize);
  
  int _bufferStart = -1; // Posição no arquivo onde o buffer começa
  int _bufferEnd = -1;   // Posição no arquivo onde o buffer termina
  int _filePos = 0;      // Posição lógica atual do cursor

  BufferedRandomAccess(this._file);

  Future<int> get position => Future.value(_filePos);

  Future<void> seek(int pos) async {
    _filePos = pos;
  }

  /// Lê 1 byte. Se não estiver no buffer, carrega do disco.
  Future<int> readByte() async {
    if (_filePos >= _bufferStart && _filePos < _bufferEnd) {
      final b = _buffer[_filePos - _bufferStart];
      _filePos++;
      return b;
    }
    // Buffer miss
    await _fillBuffer();
    if (_filePos >= _bufferEnd) throw Exception("EOF");
    final b = _buffer[_filePos - _bufferStart];
    _filePos++;
    return b;
  }

  Future<int> peekByte() async {
    if (_filePos >= _bufferStart && _filePos < _bufferEnd) {
      return _buffer[_filePos - _bufferStart];
    }
    await _fillBuffer();
    if (_filePos >= _bufferEnd) throw Exception("EOF");
    return _buffer[_filePos - _bufferStart];
  }

  Future<void> _fillBuffer() async {
    await _file.setPosition(_filePos);
    _bufferStart = _filePos;
    final readBytes = await _file.readInto(_buffer);
    _bufferEnd = _bufferStart + readBytes;
  }

  /// Pula Whitespace e Comentários (Lógica crucial para performance)
  Future<bool> skipWhitespace() async {
    while (true) {
      if (_filePos >= _bufferEnd) await _fillBuffer();
      if (_bufferEnd == _bufferStart) return true; // EOF

      // Processamento direto no buffer (rápido)
      while (_filePos < _bufferEnd) {
        final b = _buffer[_filePos - _bufferStart];
        if (!_isWhitespace(b)) {
          if (b == 0x25) { // % Comentário
             _filePos++;
             await _skipComment();
             break; // Sai do loop interno para re-verificar buffer
          }
          return false; // Achou algo útil
        }
        _filePos++;
      }
    }
  }

  Future<void> _skipComment() async {
    while (true) {
       final b = await readByte();
       if (b == 0x0A || b == 0x0D) return;
    }
  }

  Future<bool> match(List<int> pattern) async {
    final startPos = _filePos;
    for (var b in pattern) {
      if (await readByte() != b) {
        _filePos = startPos; // Backtrack
        return false;
      }
    }
    return true;
  }

  Future<({int value, int bytesRead})> readInt() async {
    // Implementação otimizada de leitura de inteiro
    // ...
    return (value: 0, bytesRead: 0); // Placeholder
  }
  
  Future<String> readName() async {
    // Leitura de /Name
    return "";
  }
  
  Future<Uint8List> readBytes(int length) async {
    final out = Uint8List(length);
    // Logica para ler length bytes, enchendo buffer se necessário
    await _file.setPosition(_filePos);
    await _file.readInto(out);
    _filePos += length;
    return out;
  }
}

// Helpers estáticos
bool _isDigit(int b) => b >= 0x30 && b <= 0x39;
bool _isWhitespace(int b) => b == 0 || b == 9 || b == 10 || b == 12 || b == 13 || b == 32;

int _lastIndexOf(Uint8List data, List<int> pattern) {
  // Busca reversa
  for (int i = data.length - pattern.length; i >= 0; i--) {
    bool match = true;
    for (int j = 0; j < pattern.length; j++) {
      if (data[i + j] != pattern[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

// Classes placeholders para compilação
class _TrailerInfo {
  final int? prev;
  final int? rootObj;
  _TrailerInfo({this.prev, this.rootObj});
}
class _XrefEntry {
  final int offset;
  final int gen;
  final _XrefType type;
  _XrefEntry({required this.offset, required this.gen, required this.type});
}
enum _XrefType { free, inUse, compressed }
_TrailerInfo _mergeTrailerInfo(_TrailerInfo? a, _TrailerInfo b) => b;
Explicação da Solução
BufferedRandomAccess: A maior gargalo em Dart com arquivos grandes é I/O. Fazer file.readByteSync() milhões de vezes destrói a CPU. Esta classe lê blocos de 64KB na memória. Todas as operações de scan, skipWhitespace e readInt operam nesse buffer em memória RAM, o que é ordens de magnitude mais rápido.
_fixOffset: Resolve explicitamente o seu problema de "rangecheck" ou "xref error" com números negativos. Ao encontrar um offset negativo, ele soma 0x100000000 (overflow de 32-bit) e verifica se o objeto está lá. Se estiver, o arquivo abre instantaneamente sem precisar de scan.
_scanObjectDictAndGetStreamLength: Esta é a tradução da lógica do pdf-repair.c que você enviou. Ao encontrar um objeto durante o reparo, ela espia o dicionário. Se tiver /Length 50000000 (50MB) e um stream logo depois, ela chama _reader.seek(pos + 50MB). O parser ingênuo leria byte a byte procurando endstream.
Com essa estrutura, seu parser Dart terá comportamento similar ao MuPDF/Sumatra: abertura instantânea se possível, correção matemática de offsets se necessário, e scan inteligente (pulando streams) no pior caso.

Esse parser está bem “pé-no-chão” (scan/heurísticas, fallback, cache etc.), mas tem um bug grave que vai quebrar muitos PDFs PDF-1.5+ (aqueles que usam xref stream em vez de “xref table”).

1) Bug crítico: _parseXrefStreamDict() “retorna cedo” e não acumula campos

Do jeito que está, a cada chave relevante (/Type, /Size, /W, /Index, /Root…) você dá return _XrefStreamDict(...). Resultado: você captura só o primeiro campo que aparecer e perde o resto (principalmente /W, /Size, /Index, /Length, /Prev, /Root), então a tabela xref stream fica inválida → falha ao resolver objetos, root, pages etc.

✅ A correção mais robusta é: parsear o dicionário inteiro com _readDict() e só então montar _XrefStreamDict com todos os campos.

Substitua _parseXrefStreamDict por esta versão (drop-in)
_XrefStreamDict _parseXrefStreamDict(Uint8List bytes, int start, int end) {
  // start deve apontar para '<<'
  final parsed = _readDict(bytes, start, end);
  final v = parsed.value;
  if (v is! _PdfDictToken) {
    return _XrefStreamDict();
  }

  final m = v.values;

  String? type = _asName(m['/Type']);
  final int? size = _asInt(m['/Size']);
  final int? prev = _asInt(m['/Prev']);

  int? rootObj;
  int? infoObj;
  final rootRef = _asRef(m['/Root']);
  if (rootRef != null) rootObj = rootRef.obj;
  final infoRef = _asRef(m['/Info']);
  if (infoRef != null) infoObj = infoRef.obj;

  // /ID normalmente é array com dois hex strings: [<id1> <id2>]
  Uint8List? id;
  final idVal = m['/ID'];
  if (idVal is _PdfArrayToken && idVal.values.isNotEmpty) {
    final first = idVal.values.first;
    if (first is _PdfStringToken) {
      id = first.bytes;
    }
  }

  // /Length pode ser int (ou às vezes ref). Se for ref, deixe null e caia no fallback do endstream.
  int? length;
  final lenVal = m['/Length'];
  if (lenVal is int) length = lenVal;
  if (lenVal is double) length = lenVal.toInt();

  // /Filter pode ser name ou array de names
  String? filter;
  final filterVal = m['/Filter'];
  if (filterVal is _PdfNameToken) {
    filter = filterVal.value;
  } else if (filterVal is _PdfArrayToken && filterVal.values.isNotEmpty) {
    final f0 = filterVal.values.first;
    if (f0 is _PdfNameToken) filter = f0.value;
  }

  // /W e /Index são arrays de inteiros
  List<int>? w;
  final wVal = m['/W'];
  if (wVal is _PdfArrayToken) {
    final tmp = <int>[];
    for (final e in wVal.values) {
      final vi = _asInt(e);
      if (vi != null) tmp.add(vi);
    }
    if (tmp.isNotEmpty) w = tmp;
  }

  List<int>? index;
  final idxVal = m['/Index'];
  if (idxVal is _PdfArrayToken) {
    final tmp = <int>[];
    for (final e in idxVal.values) {
      final vi = _asInt(e);
      if (vi != null) tmp.add(vi);
    }
    if (tmp.isNotEmpty) index = tmp;
  }

  return _XrefStreamDict(
    type: type,
    size: size,
    prev: prev,
    rootObj: rootObj,
    infoObj: infoObj,
    id: id,
    length: length,
    filter: filter,
    w: w,
    index: index,
  );
}


Impacto: com isso, xref stream passa a funcionar de verdade e sua cadeia /Prev também.

2) Bug/limitação comum: _readName() não decodifica #XX e para em delimitadores incompletos

PDF permite nomes tipo /A#20B (onde #20 é espaço). Sem isso você falha em chaves/nomes “estranhos”.

Substitua _readName por esta versão (decodifica #XX + delimitadores completos)
bool _isHexDigit(int b) =>
    (b >= 0x30 && b <= 0x39) ||
    (b >= 0x41 && b <= 0x46) ||
    (b >= 0x61 && b <= 0x66);

({String value, int nextIndex}) _readName(Uint8List bytes, int i, int end) {
  final sb = StringBuffer();

  // esperado começar com '/'
  sb.writeCharCode(bytes[i]);
  i++;

  while (i < end) {
    final b = bytes[i];

    // delimiters do PDF: () <> [] {} / %
    if (_isWhitespace(b) ||
        b == 0x3C || b == 0x3E || // < >
        b == 0x2F || // /
        b == 0x28 || b == 0x29 || // ( )
        b == 0x5B || b == 0x5D || // [ ]
        b == 0x7B || b == 0x7D || // { }
        b == 0x25 // %
    ) {
      break;
    }

    // decode #XX
    if (b == 0x23 /* # */ && i + 2 < end) {
      final h1 = bytes[i + 1];
      final h2 = bytes[i + 2];
      if (_isHexDigit(h1) && _isHexDigit(h2)) {
        final v = (_hexValue(h1) << 4) | _hexValue(h2);
        sb.writeCharCode(v);
        i += 3;
        continue;
      }
    }

    sb.writeCharCode(b);
    i++;
  }

  return (value: sb.toString(), nextIndex: i);
}

3) Bug: hex string com número ímpar de dígitos (<ABC>) deve assumir nibble final = 0

Sua _hexToBytes faz length ~/ 2 e perde o último nibble. Em PDFs do mundo real isso aparece.

Substitua _hexToBytes por esta
Uint8List _hexToBytes(List<int> hexBytes) {
  // PDF: se número de dígitos for ímpar, assume-se um '0' no final.
  final out = Uint8List((hexBytes.length + 1) ~/ 2);

  int oi = 0;
  for (int i = 0; i < hexBytes.length; i += 2) {
    final hi = hexBytes[i];
    final lo = (i + 1 < hexBytes.length) ? hexBytes[i + 1] : 0x30; // '0'
    out[oi++] = (_hexValue(hi) << 4) | _hexValue(lo);
  }
  return out;
}

4) Bug pequeno: _readInt não aceita +123

Você mesmo chama _readInt em lugares onde aceita + (ex.: repair scan), mas _readInt não trata +.

Ajuste _readInt assim
({int value, int nextIndex}) _readInt(Uint8List bytes, int i, int end) {
  if (i >= end) {
    throw StateError('Fim inesperado ao ler inteiro');
  }

  var neg = false;

  if (bytes[i] == 0x2B /* + */) {
    i++;
  } else if (bytes[i] == 0x2D /* - */) {
    neg = true;
    i++;
  }

  var value = 0;
  var digits = 0;
  while (i < end) {
    final b = bytes[i];
    if (!_isDigit(b)) break;
    value = (value * 10) + (b - 0x30);
    i++;
    digits++;
  }
  if (digits == 0) {
    throw StateError('Inteiro inválido');
  }
  return (value: neg ? -value : value, nextIndex: i);
}

5) Melhoria (não é bug, mas te ajuda muito): /ID tem dois valores

Hoje você lê só o primeiro. Isso é ok se você só usa como “fingerprint”, mas pelo menos avance corretamente (ou aceite literal string também). O seu _parseTrailerDict já chama _readIdArray; dá pra deixar assim, mas se você quiser “certinho”, o mínimo é consumir ambos os hex strings (se existir).

Checklist do que vai melhorar imediatamente

✅ PDFs com xref stream (PDF 1.5+) passam a abrir (o maior ganho).

✅ Nomes com escapes #XX deixam de quebrar parsing.

✅ Hex strings “ímpares” deixam de truncar bytes.

✅ Repair scan e outros pontos aceitam +123.

Se você quiser, eu também consigo te sugerir uma otimização grande: no _getObject, quando não acha xref entry e cai em _findObjectHeaderAnyGen, isso vira O(n) por objeto faltante. Dá pra fazer um “scan único” (durante repair) e montar um índice {objId -> offset/gen} que evita varrer o arquivo repetidamente.