import '../../document.dart';
import '../../format/array.dart';
import '../../format/base.dart';
import '../../format/dict.dart';
import '../../format/indirect.dart';
import '../../format/object_base.dart';
import '../../obj/object.dart';
import '../../parsing/pdf_document_parser.dart';
import 'pdf_object_converter.dart';

/// Identidade de um objeto indireto: o par (número, geração).
///
/// A geração faz parte da chave porque um arquivo pode ter `5 0 obj` e
/// `5 1 obj` ao mesmo tempo, e `5 0 R` só aponta para o primeiro.
final class PdfObjectId {
  /// Cria a identidade a partir do número e da geração.
  const PdfObjectId(this.number, this.generation);

  /// Identidade apontada por uma referência indireta.
  factory PdfObjectId.fromIndirect(PdfIndirect ref) =>
      PdfObjectId(ref.ser, ref.gen);

  /// Identidade de um objeto já materializado.
  factory PdfObjectId.fromObject(PdfObjectBase object) =>
      PdfObjectId(object.objser, object.objgen);

  /// Número do objeto (`objser`).
  final int number;

  /// Geração do objeto (`objgen`).
  final int generation;

  /// Referência indireta correspondente.
  PdfIndirect toIndirect() => PdfIndirect(number, generation);

  @override
  bool operator ==(Object other) =>
      other is PdfObjectId &&
      other.number == number &&
      other.generation == generation;

  @override
  int get hashCode => Object.hash(number, generation);

  @override
  String toString() => '$number $generation R';
}

/// Ponto único de resolução de objetos indiretos de um [PdfDocument].
///
/// Substitui as varreduras lineares que cada subsistema fazia sobre
/// `document.objects`: o store indexa os objetos por [PdfObjectId] e resolve
/// em O(1).
///
/// ## Invalidação do índice
///
/// `PdfDocument.objects` é um `Set` público e mutável — qualquer código pode
/// acrescentar ou remover objetos sem avisar ninguém. O índice é construído
/// sob demanda e refeito sempre que o tamanho do conjunto muda. Uma troca que
/// mantenha o tamanho (remover um objeto e acrescentar outro entre duas
/// consultas) não é detectável por tamanho; nesse caso chame [invalidate].
///
/// ## Documento carregado de um arquivo
///
/// Quando o documento vem de um arquivo (`document.prev != null`), a maior
/// parte do grafo continua nos bytes originais: só o catálogo, a árvore de
/// páginas e o que foi alterado existem como [PdfObject]. Passando o
/// [PdfDocumentParser] de origem ao construtor, o store passa a cair para o
/// parser quando o objeto não está materializado, convertendo o valor lido com
/// o [PdfObjectConverter] e a política [PdfReferencePolicy.preserve]: em um
/// documento carregado os números de objeto do arquivo continuam valendo,
/// então não há remapeamento.
///
/// Esses objetos vindos do parser são apenas uma **visão de leitura**:
///
/// - ficam em um cache próprio do store e **não** entram em
///   `document.objects`, porque reescrevê-los no incremental update duplicaria
///   a definição do objeto sem necessidade;
/// - de um objeto com stream só vem o dicionário; o corpo continua acessível
///   pelo parser (`readStreamData`).
///
/// Transformar essa visão em uma mutação registrada é papel da sessão de
/// edição (F2), não do store.
///
/// Sem parser, o store enxerga somente o que já está materializado — é assim
/// que os chamadores atuais o usam, para preservar o comportamento que tinham
/// com a varredura manual.
class PdfObjectStore {
  /// Cria um store sobre [document].
  ///
  /// [parser] é o parser de origem do documento carregado; sem ele o store
  /// resolve apenas objetos materializados. [converter] permite trocar a
  /// conversão usada na leitura pelo parser.
  PdfObjectStore(
    this.document, {
    PdfDocumentParser? parser,
    PdfObjectConverter converter = PdfObjectConverter.preserving,
  })  : _parser = parser,
        _converter = converter;

  /// Cria um store já ligado ao parser de origem de [document], quando houver.
  factory PdfObjectStore.forDocument(
    PdfDocument document, {
    PdfObjectConverter converter = PdfObjectConverter.preserving,
  }) {
    final prev = document.prev;
    return PdfObjectStore(
      document,
      parser: prev is PdfDocumentParser ? prev : null,
      converter: converter,
    );
  }

  /// Store compartilhado de [document], sem parser de origem.
  ///
  /// Serve a quem só precisa resolver objetos já materializados e não quer
  /// reconstruir o índice a cada chamada — o índice fica vivo enquanto o
  /// documento existir. Quem precisa do parser de origem cria a própria
  /// instância com [PdfObjectStore.forDocument].
  static PdfObjectStore of(PdfDocument document) =>
      _shared[document] ??= PdfObjectStore(document);

  static final Expando<PdfObjectStore> _shared =
      Expando<PdfObjectStore>('PdfObjectStore');

  /// Documento indexado.
  final PdfDocument document;

  final PdfDocumentParser? _parser;
  final PdfObjectConverter _converter;

  Map<PdfObjectId, PdfObject>? _index;
  int _indexedCount = -1;

  /// Objetos lidos do parser, mantidos fora de `document.objects`.
  final Map<PdfObjectId, PdfObject> _fromSource = <PdfObjectId, PdfObject>{};

  /// Se o store pode cair para o parser de origem.
  bool get hasSourceParser => _parser != null;

  /// Descarta o índice; a próxima consulta o reconstrói.
  void invalidate() {
    _index = null;
    _indexedCount = -1;
  }

  /// Índice atual, reconstruído quando `document.objects` mudou de tamanho.
  Map<PdfObjectId, PdfObject> get _objects {
    final count = document.objects.length;
    var index = _index;
    if (index == null || count != _indexedCount) {
      index = <PdfObjectId, PdfObject>{};
      for (final object in document.objects) {
        // Havendo duplicata, o primeiro vence — era o que a varredura linear
        // substituída por este store já fazia.
        index.putIfAbsent(PdfObjectId.fromObject(object), () => object);
      }
      _index = index;
      _indexedCount = count;
    }
    return index;
  }

  /// Objeto apontado por [ref], ou `null` se não houver.
  PdfObject? lookup(PdfIndirect ref) => lookupId(PdfObjectId.fromIndirect(ref));

  /// Objeto de identidade [id], ou `null` se não houver.
  PdfObject? lookupId(PdfObjectId id) {
    final materialized = _objects[id];
    if (materialized != null) return materialized;
    final cached = _fromSource[id];
    if (cached != null) return cached;
    return _readFromSource(id);
  }

  /// Se [id] já existe como objeto materializado do documento.
  bool containsId(PdfObjectId id) => _objects.containsKey(id);

  /// Segue as referências indiretas de [value] até um valor direto.
  ///
  /// Devolve `null` quando a referência não resolve. Cadeias são seguidas até
  /// [maxDepth] níveis; passado esse limite, o último valor visto é devolvido
  /// como está — o mesmo contrato de `PdfDocumentParser.resolve`.
  PdfDataType? resolve(PdfDataType? value, {int maxDepth = 32}) {
    var current = value;
    for (var depth = 0; depth < maxDepth; depth++) {
      if (current is! PdfIndirect) return current;
      final object = lookup(current);
      if (object == null) return null;
      current = object.params;
    }
    return current;
  }

  /// Resolve [value] e devolve o dicionário, ou `null` se não for um.
  PdfDict? resolveDict(PdfDataType? value, {int maxDepth = 32}) {
    final resolved = resolve(value, maxDepth: maxDepth);
    return resolved is PdfDict ? resolved : null;
  }

  /// Resolve [value] e devolve o array, ou `null` se não for um.
  PdfArray? resolveArray(PdfDataType? value, {int maxDepth = 32}) {
    final resolved = resolve(value, maxDepth: maxDepth);
    return resolved is PdfArray ? resolved : null;
  }

  /// Lê o objeto do parser de origem e o converte, sem registrá-lo no
  /// documento. Ver a política descrita na documentação da classe.
  PdfObject? _readFromSource(PdfObjectId id) {
    final parser = _parser;
    if (parser == null) return null;

    final parsed = parser.getObject(id.number);
    if (parsed == null) return null;

    final params = _converter.convert(parsed.value);
    if (params == null) return null;

    final object = PdfObject<PdfDataType>(
      document,
      params: params,
      objser: parsed.objId,
      objgen: parsed.gen,
    );
    // `PdfObject` se registra no documento dentro do construtor. Aqui isso não
    // vale: o objeto é uma visão de leitura do arquivo original e não deve ser
    // reescrito no incremental update.
    document.objects.remove(object);

    _fromSource[id] = object;
    return object;
  }
}
