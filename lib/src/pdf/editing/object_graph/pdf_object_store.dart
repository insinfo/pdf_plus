import '../../document.dart';
import '../../format/array.dart';
import '../../format/base.dart';
import '../../format/dict.dart';
import '../../format/indirect.dart';
import '../../format/object_base.dart';
import '../../obj/object.dart';
import '../../parsing/pdf_document_parser.dart';
import 'pdf_object_converter.dart';

/// Identity of an indirect object: the (number, generation) pair.
///
/// The generation is part of the key because a file can hold `5 0 obj` and
/// `5 1 obj` at the same time, and `5 0 R` points only to the first.
final class PdfObjectId {
  /// Creates the identity from the number and the generation.
  const PdfObjectId(this.number, this.generation);

  /// Identity pointed to by an indirect reference.
  factory PdfObjectId.fromIndirect(PdfIndirect ref) =>
      PdfObjectId(ref.ser, ref.gen);

  /// Identity of an already materialized object.
  factory PdfObjectId.fromObject(PdfObjectBase object) =>
      PdfObjectId(object.objser, object.objgen);

  /// Object number (`objser`).
  final int number;

  /// Object generation (`objgen`).
  final int generation;

  /// Matching indirect reference.
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

/// Single resolution point for the indirect objects of a [PdfDocument].
///
/// Replaces the linear scans each subsystem used to run over
/// `document.objects`: the store indexes the objects by [PdfObjectId] and
/// resolves in O(1).
///
/// ## Index invalidation
///
/// `PdfDocument.objects` is a public, mutable `Set` — any code can add or
/// remove objects without telling anyone. The index is built on demand and
/// rebuilt whenever the size of the set changes. A swap that keeps the size
/// (removing one object and adding another between two lookups) is not
/// detectable by size; call [invalidate] in that case.
///
/// ## Document loaded from a file
///
/// When the document comes from a file (`document.prev != null`), most of the
/// graph stays in the original bytes: only the catalog, the page tree and what
/// was changed exist as [PdfObject]. By passing the source
/// [PdfDocumentParser] to the constructor, the store starts falling back to
/// the parser when the object is not materialized, converting the value read
/// with the [PdfObjectConverter] and the [PdfReferencePolicy.preserve] policy:
/// in a loaded document the object numbers from the file still hold, so there
/// is no remapping.
///
/// These objects coming from the parser are only a **read view**:
///
/// - they live in a cache owned by the store and do **not** enter
///   `document.objects`, because rewriting them in the incremental update
///   would duplicate the object definition needlessly;
/// - from an object with a stream only the dictionary comes; the body stays
///   reachable through the parser (`readStreamData`).
///
/// Turning that view into a recorded mutation is the job of the editing
/// session (F2), not of the store.
///
/// Without a parser, the store sees only what is already materialized — that
/// is how the current callers use it, to preserve the behavior they had with
/// the manual scan.
class PdfObjectStore {
  /// Creates a store over [document].
  ///
  /// [parser] is the source parser of the loaded document; without it the
  /// store resolves only materialized objects. [converter] allows swapping
  /// the conversion used when reading through the parser.
  PdfObjectStore(
    this.document, {
    PdfDocumentParser? parser,
    PdfObjectConverter converter = PdfObjectConverter.preserving,
  })  : _parser = parser,
        _converter = converter;

  /// Creates a store already bound to the source parser of [document], if any.
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

  /// Shared store of [document], without a source parser.
  ///
  /// Serves whoever only needs to resolve already materialized objects and
  /// does not want to rebuild the index on every call — the index stays alive
  /// as long as the document exists. Whoever needs the source parser creates
  /// their own instance with [PdfObjectStore.forDocument].
  static PdfObjectStore of(PdfDocument document) =>
      _shared[document] ??= PdfObjectStore(document);

  static final Expando<PdfObjectStore> _shared =
      Expando<PdfObjectStore>('PdfObjectStore');

  /// The indexed document.
  final PdfDocument document;

  final PdfDocumentParser? _parser;
  final PdfObjectConverter _converter;

  Map<PdfObjectId, PdfObject>? _index;
  int _indexedCount = -1;

  /// Objects read from the parser, kept out of `document.objects`.
  final Map<PdfObjectId, PdfObject> _fromSource = <PdfObjectId, PdfObject>{};

  /// Whether the store can fall back to the source parser.
  bool get hasSourceParser => _parser != null;

  /// Discards the index; the next lookup rebuilds it.
  void invalidate() {
    _index = null;
    _indexedCount = -1;
  }

  /// Current index, rebuilt when `document.objects` changed size.
  Map<PdfObjectId, PdfObject> get _objects {
    final count = document.objects.length;
    var index = _index;
    if (index == null || count != _indexedCount) {
      index = <PdfObjectId, PdfObject>{};
      for (final object in document.objects) {
        // On a duplicate, the first one wins — that is what the linear scan
        // this store replaced already did.
        index.putIfAbsent(PdfObjectId.fromObject(object), () => object);
      }
      _index = index;
      _indexedCount = count;
    }
    return index;
  }

  /// Object pointed to by [ref], or `null` if there is none.
  PdfObject? lookup(PdfIndirect ref) => lookupId(PdfObjectId.fromIndirect(ref));

  /// Object with identity [id], or `null` if there is none.
  PdfObject? lookupId(PdfObjectId id) {
    final materialized = _objects[id];
    if (materialized != null) return materialized;
    final cached = _fromSource[id];
    if (cached != null) return cached;
    return _readFromSource(id);
  }

  /// Whether [id] already exists as a materialized object of the document.
  bool containsId(PdfObjectId id) => _objects.containsKey(id);

  /// Follows the indirect references of [value] down to a direct value.
  ///
  /// Returns `null` when the reference does not resolve. Chains are followed
  /// for up to [maxDepth] levels; past that limit, the last value seen is
  /// returned as is — the same contract as `PdfDocumentParser.resolve`.
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

  /// Resolves [value] and returns the dictionary, or `null` if it is not one.
  PdfDict? resolveDict(PdfDataType? value, {int maxDepth = 32}) {
    final resolved = resolve(value, maxDepth: maxDepth);
    return resolved is PdfDict ? resolved : null;
  }

  /// Resolves [value] and returns the array, or `null` if it is not one.
  PdfArray? resolveArray(PdfDataType? value, {int maxDepth = 32}) {
    final resolved = resolve(value, maxDepth: maxDepth);
    return resolved is PdfArray ? resolved : null;
  }

  /// Reads the object from the source parser and converts it, without
  /// registering it in the document. See the policy described in the class
  /// documentation.
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
    // `PdfObject` registers itself in the document inside the constructor.
    // That does not apply here: the object is a read view of the original file
    // and must not be rewritten in the incremental update.
    document.objects.remove(object);

    _fromSource[id] = object;
    return object;
  }
}
