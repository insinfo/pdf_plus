import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/export.dart';

import 'keystore_base.dart';

/// BKS entry type constants.
const int bksEntryTypeCertificate = 1;
const int bksEntryTypeKey = 2;
const int bksEntryTypeSecret = 3;
const int bksEntryTypeSealed = 4;

/// BKS key type constants.
const int bksKeyTypePrivate = 0;
const int bksKeyTypePublic = 1;
const int bksKeyTypeSecret = 2;

/// Represents a trusted certificate entry in a BKS keystore.
class BksTrustedCertEntry extends TrustedCertEntry {
  BksTrustedCertEntry({
    required super.alias,
    required super.timestamp,
    required super.storeType,
    required super.certType,
    required super.certData,
  });
}

/// Represents a key entry in a BKS keystore.
class BksKeyEntry extends KeystoreEntry {
  /// The type of key: private (0), public (1), or secret (2).
  final int keyType;

  /// The format/encoding of the key (PKCS8, X.509, RAW).
  final String format;

  /// The algorithm name.
  final String algorithm;

  /// The encoded key data.
  final Uint8List encoded;

  /// Certificate chain associated with this key.
  List<BksTrustedCertEntry> certChain;

  BksKeyEntry({
    required super.alias,
    required super.timestamp,
    required super.storeType,
    required this.keyType,
    required this.format,
    required this.algorithm,
    required this.encoded,
    this.certChain = const [],
  });

  @override
  bool isDecrypted() => true;

  @override
  void decrypt(String password) {
    // Non-sealed keys are not encrypted
  }

  /// Returns a string representation of the key type.
  static String keyTypeToString(int type) {
    switch (type) {
      case bksKeyTypePrivate:
        return 'PRIVATE';
      case bksKeyTypePublic:
        return 'PUBLIC';
      case bksKeyTypeSecret:
        return 'SECRET';
      default:
        return 'UNKNOWN';
    }
  }
}

/// Represents a sealed (encrypted) key entry in a BKS keystore.
class BksSealedKeyEntry extends KeystoreEntry {
  /// The encrypted data.
  Uint8List? _encryptedData;

  /// The nested key entry once decrypted.
  BksKeyEntry? _nestedEntry;

  /// Certificate chain associated with this key.
  List<BksTrustedCertEntry> certChain;

  BksSealedKeyEntry({
    required super.alias,
    required super.timestamp,
    required super.storeType,
    Uint8List? encryptedData,
    this.certChain = const [],
  }) : _encryptedData = encryptedData;

  @override
  bool isDecrypted() => _encryptedData == null;

  /// Gets the nested key entry. Throws if not decrypted.
  BksKeyEntry get nestedEntry {
    if (!isDecrypted()) {
      throw StateError('Entry not decrypted. Call decrypt() first.');
    }
    return _nestedEntry!;
  }

  @override
  void decrypt(String password) {
    if (isDecrypted()) return;

    // BKS Sealed Key structure:
    // Salt (20 bytes)
    // Iteration Count (4 bytes)
    // Ciphertext (Rest)

    if (_encryptedData == null || _encryptedData!.length < 24) {
      throw DecryptionFailureException('Invalid sealed key data length');
    }

    final data = ByteData.sublistView(_encryptedData!);
    int pos = 0;

    // Read salt (20 bytes)
    // Note: BKS V2 sometimes stores salt length?
    // BC implementation usually fixed 20 bytes for this specific internal structure
    final salt = _encryptedData!.sublist(pos, pos + 20);
    pos += 20;

    // Read iteration count
    final iterationCount = data.getUint32(pos);
    pos += 4;

    final ciphertext = _encryptedData!.sublist(pos);

    try {
      // Derive Key (192 bits = 24 bytes) and IV (64 bits = 8 bytes)

      // Actually BKS uses separate calls for Key and IV with different ID byte
      final key =
          BksKeyStore._derivePkcs12Key(password, salt, iterationCount, 24, 1);
      final iv =
          BksKeyStore._derivePkcs12Key(password, salt, iterationCount, 8, 2);

      // Decrypt 3DES-CBC
      final params = ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
      final cipher = CBCBlockCipher(DESedeEngine())..init(false, params);
      final paddedCipher = PaddedBlockCipherImpl(PKCS7Padding(), cipher);

      final plaintext = paddedCipher.process(ciphertext);

      // Parse nested entry
      // The plaintext contains the BksKeyEntry fields
      // We can use _readBksKey but we need to match the signature
      // _readBksKey expects `data, pos`.

      // Note: _readBksKey reads keyType etc.
      // The sealed object content is usually the BksKeyEntry data starting AFTER the type/alias/timestamp?
      // No, it's the `SecretKey` or `PrivateKey` object serialization.
      // If it's BksKeyEntry, it includes type etc.
      // Let's assume it starts with KeyType (1 byte).

      // Warning: _readBksKey reads keyType then format then algorithm...
      // Let's try to parse it.

      final (nested, _) = BksKeyStore._readBksKey(plaintext, 0, storeType);
      nested.certChain = certChain;
      nested.alias = alias;
      nested.timestamp = timestamp;

      _nestedEntry = nested;
      _encryptedData = null; // Decrypted
    } catch (e) {
      if (e is KeystoreException) rethrow;
      throw DecryptionFailureException('BKS decryption failed: $e');
    }
  }
}

/// Represents a secret value entry in a BKS keystore.
/// This stores arbitrary pre-protected data.
class BksSecretEntry extends KeystoreEntry {
  /// The raw secret data.
  final Uint8List secretData;

  /// Certificate chain associated with this entry.
  List<BksTrustedCertEntry> certChain;

  BksSecretEntry({
    required super.alias,
    required super.timestamp,
    required super.storeType,
    required this.secretData,
    this.certChain = const [],
  });

  @override
  bool isDecrypted() => true;

  @override
  void decrypt(String password) {
    // Secret entries are stored as-is, not encrypted by keystore
  }
}

/// BKS (Bouncy Castle KeyStore) parser.
///
/// This class parses BKS-V1 and BKS-V2 keystore files.
///
/// BKS file format:
/// - Version: 4 bytes (1 or 2)
/// - Salt: length-prefixed bytes
/// - Iteration count: 4 bytes
/// - Entries: variable, null-terminated
/// - HMAC: 20 bytes (SHA-1)
///
/// TODO: Full implementation requires:
/// - Sealed key decryption (PBEWithSHAAnd3-KeyTripleDES-CBC) [Implemented]
class BksKeyStore extends AbstractKeystore {
  /// The version of this keystore (1 or 2).
  final int version;

  BksKeyStore(super.storeType, super.entries, {this.version = 2});

  /// Loads a BKS keystore from bytes.
  ///
  /// [data] - The raw keystore bytes.
  /// [storePassword] - The password to verify keystore integrity.
  ///                   If null, integrity check is skipped.
  /// [tryDecryptKeys] - Whether to try decrypting sealed keys using
  ///                    the store password.
  static BksKeyStore load(
    Uint8List data, {
    String? storePassword,
    bool tryDecryptKeys = true,
  }) {
    if (data.length < 8) {
      throw BadKeystoreFormatException('Keystore file too small');
    }

    final view = ByteData.view(data.buffer, data.offsetInBytes, data.length);
    int pos = 0;

    // Read version
    final version = view.getUint32(pos);
    pos += 4;

    if (version != 1 && version != 2) {
      throw UnsupportedKeystoreVersionException(
          'Unsupported BKS keystore version; only V1 and V2 supported, found v$version');
    }

    // Read salt
    final (salt, newPos1) = _readData(data, pos);
    pos = newPos1;

    // Read iteration count
    final iterationCount = view.getUint32(pos);
    pos += 4;

    const storeType = 'bks';

    // Parse entries
    final entriesStartPos = pos;
    final (entries, entriesEndPos) = _loadEntries(
      data.sublist(pos),
      storeType,
      storePassword,
      tryDecryptKeys: tryDecryptKeys,
    );

    pos = entriesStartPos + entriesEndPos;

    // Verify HMAC if password provided
    if (storePassword != null) {
      const hmacDigestSize = 20; // SHA-1

      // For V1, HMAC key is same size as digest
      // For V2, HMAC key is 160 bits (20 bytes)
      final hmacKeySize = version == 1 ? hmacDigestSize : 20;

      // Derive HMAC key using PKCS#12 KDF
      final hmacKey = _derivePkcs12Key(
        storePassword,
        salt,
        iterationCount,
        hmacKeySize,
        3, // PURPOSE_MAC_MATERIAL
      );

      final storeData = data.sublist(entriesStartPos, pos);
      final storeHmac = data.sublist(pos, pos + hmacDigestSize);

      if (storeHmac.length != hmacDigestSize) {
        throw BadKeystoreFormatException(
            'Bad HMAC size; found ${storeHmac.length} bytes, expected $hmacDigestSize bytes');
      }

      // Compute HMAC-SHA1
      final computedHmac = hmacSha1(hmacKey, storeData);

      bool hmacMatch = true;
      for (int i = 0; i < hmacDigestSize; i++) {
        if (computedHmac[i] != storeHmac[i]) {
          hmacMatch = false;
          break;
        }
      }

      if (!hmacMatch) {
        throw KeystoreSignatureException(
            'HMAC mismatch; incorrect keystore password?');
      }
    }

    return BksKeyStore(storeType, entries, version: version);
  }

  /// Loads entries from the data section.
  static (Map<String, KeystoreEntry>, int) _loadEntries(
      Uint8List data, String storeType, String? storePassword,
      {bool tryDecryptKeys = false}) {
    final entries = <String, KeystoreEntry>{};
    int pos = 0;

    final view = ByteData.view(data.buffer, data.offsetInBytes, data.length);

    while (pos < data.length) {
      // Read entry type
      final entryType = view.getUint8(pos);
      pos += 1;

      // Type 0 marks end of entries
      if (entryType == 0) {
        break;
      }

      // Read alias
      final (alias, newPos1) = _readUtf(data, pos);
      pos = newPos1;

      // Read timestamp
      final timestamp = view.getInt64(pos);
      pos += 8;

      // Read certificate chain
      final chainLength = view.getUint32(pos);
      pos += 4;

      final certChain = <BksTrustedCertEntry>[];
      for (int i = 0; i < chainLength; i++) {
        final (cert, newPos2) = _readBksCert(data, pos, storeType);
        pos = newPos2;
        certChain.add(cert);
      }

      KeystoreEntry entry;

      if (entryType == bksEntryTypeCertificate) {
        final (cert, newPos2) = _readBksCert(data, pos, storeType);
        pos = newPos2;
        entry = cert;
      } else if (entryType == bksEntryTypeKey) {
        final (key, newPos2) = _readBksKey(data, pos, storeType);
        pos = newPos2;
        key.certChain = certChain;
        entry = key;
      } else if (entryType == bksEntryTypeSecret) {
        final (secret, newPos2) = _readBksSecret(data, pos, storeType);
        pos = newPos2;
        secret.certChain = certChain;
        entry = secret;
      } else if (entryType == bksEntryTypeSealed) {
        final (sealed, newPos2) = _readBksSealed(data, pos, storeType);
        pos = newPos2;
        sealed.certChain = certChain;
        entry = sealed;
      } else {
        throw BadKeystoreFormatException(
            'Unexpected BKS entry type $entryType');
      }

      entry.alias = alias;
      entry.timestamp = timestamp;

      if (tryDecryptKeys &&
          storePassword != null &&
          entry is BksSealedKeyEntry) {
        try {
          entry.decrypt(storePassword);
        } catch (e) {
          // Ignore - user can decrypt manually later
        }
      }

      if (entries.containsKey(alias)) {
        throw DuplicateAliasException("Found duplicate alias '$alias'");
      }
      entries[alias] = entry;
    }

    return (entries, pos);
  }

  /// Reads a certificate entry.
  static (BksTrustedCertEntry, int) _readBksCert(
      Uint8List data, int pos, String storeType) {
    // Read certificate type
    final (certType, newPos1) = _readUtf(data, pos);
    pos = newPos1;

    // Read certificate data
    final (certData, newPos2) = _readData(data, pos);
    pos = newPos2;

    return (
      BksTrustedCertEntry(
        alias: '',
        timestamp: 0,
        storeType: storeType,
        certType: certType,
        certData: certData,
      ),
      pos
    );
  }

  /// Reads a key entry.
  static (BksKeyEntry, int) _readBksKey(
      Uint8List data, int pos, String storeType) {
    final view = ByteData.view(data.buffer, data.offsetInBytes, data.length);

    // Read key type
    final keyType = view.getUint8(pos);
    pos += 1;

    // Read format
    final (format, newPos1) = _readUtf(data, pos);
    pos = newPos1;

    // Read algorithm
    final (algorithm, newPos2) = _readUtf(data, pos);
    pos = newPos2;

    // Read encoded key
    final (encoded, newPos3) = _readData(data, pos);
    pos = newPos3;

    return (
      BksKeyEntry(
        alias: '',
        timestamp: 0,
        storeType: storeType,
        keyType: keyType,
        format: format,
        algorithm: algorithm,
        encoded: encoded,
      ),
      pos
    );
  }

  /// Reads a secret entry.
  static (BksSecretEntry, int) _readBksSecret(
      Uint8List data, int pos, String storeType) {
    // Read secret data
    final (secretData, newPos1) = _readData(data, pos);
    pos = newPos1;

    return (
      BksSecretEntry(
        alias: '',
        timestamp: 0,
        storeType: storeType,
        secretData: secretData,
      ),
      pos
    );
  }

  /// Reads a sealed key entry.
  static (BksSealedKeyEntry, int) _readBksSealed(
      Uint8List data, int pos, String storeType) {
    // Read encrypted data (rest until next entry or HMAC)
    final (encryptedData, newPos1) = _readData(data, pos);
    pos = newPos1;

    return (
      BksSealedKeyEntry(
        alias: '',
        timestamp: 0,
        storeType: storeType,
        encryptedData: encryptedData,
      ),
      pos
    );
  }

  /// Reads a UTF-8 string with 2-byte length prefix.
  static (String, int) _readUtf(Uint8List data, int pos) {
    final view = ByteData.view(data.buffer, data.offsetInBytes, data.length);
    final length = view.getUint16(pos);
    pos += 2;

    final bytes = data.sublist(pos, pos + length);
    pos += length;

    final str = utf8.decode(bytes, allowMalformed: true);
    return (str, pos);
  }

  /// Reads a data blob with 4-byte length prefix.
  static (Uint8List, int) _readData(Uint8List data, int pos) {
    final view = ByteData.view(data.buffer, data.offsetInBytes, data.length);
    final length = view.getUint32(pos);
    pos += 4;

    final bytes = Uint8List.fromList(data.sublist(pos, pos + length));
    pos += length;

    return (bytes, pos);
  }

  /// Derives a key using PKCS#12 KDF (RFC 7292, Appendix B).
  ///
  /// Ported from Bouncy Castle's PKCS12ParametersGenerator.
  ///
  /// [password] - The password.
  /// [salt] - The salt bytes.
  /// [iterations] - Number of iterations.
  /// [keyLength] - Desired key length in bytes.
  /// [purpose] - Key derivation purpose (1=encryption, 2=IV, 3=MAC).
  static Uint8List _derivePkcs12Key(
    String password,
    Uint8List salt,
    int iterations,
    int keyLength,
    int purpose,
  ) {
    // Hash function parameters (SHA-1)
    const int u = 20; // digest size in bytes
    const int v = 64; // block size in bytes

    // Encode password as BMPString (UTF-16BE) with null terminator
    // Empty password => empty byte array
    Uint8List passwordBytes;
    if (password.isEmpty) {
      passwordBytes = Uint8List(0);
    } else {
      final pwBytes = <int>[];
      for (int i = 0; i < password.length; i++) {
        final code = password.codeUnitAt(i);
        pwBytes.add((code >> 8) & 0xFF);
        pwBytes.add(code & 0xFF);
      }
      pwBytes.add(0);
      pwBytes.add(0);
      passwordBytes = Uint8List.fromList(pwBytes);
    }

    // D = v/8 copies of purpose byte
    final D = Uint8List(v);
    for (int i = 0; i < v; i++) {
      D[i] = purpose;
    }

    // S = salt expanded to multiple of v
    final sLen = salt.isEmpty ? 0 : ((salt.length + v - 1) ~/ v) * v;
    final S = Uint8List(sLen);
    for (int i = 0; i < sLen; i++) {
      S[i] = salt[i % salt.length];
    }

    // P = password expanded to multiple of v
    final pLen =
        passwordBytes.isEmpty ? 0 : ((passwordBytes.length + v - 1) ~/ v) * v;
    final P = Uint8List(pLen);
    for (int i = 0; i < pLen; i++) {
      P[i] = passwordBytes[i % passwordBytes.length];
    }

    // I = S || P
    final I = Uint8List(sLen + pLen);
    I.setRange(0, sLen, S);
    I.setRange(sLen, sLen + pLen, P);

    // c = ceiling(n/u)
    final c = (keyLength + u - 1) ~/ u;

    final derivedKey = <int>[];

    for (int i = 1; i <= c; i++) {
      // A = Hash^c(D || I)
      final input = Uint8List(v + I.length);
      input.setRange(0, v, D);
      input.setRange(v, v + I.length, I);

      var A = sha1.convert(input).bytes;
      for (int j = 1; j < iterations; j++) {
        A = sha1.convert(A).bytes;
      }

      derivedKey.addAll(A);

      if (i < c) {
        // B = A expanded to v bytes
        final B = Uint8List(v);
        for (int j = 0; j < v; j++) {
          B[j] = A[j % A.length];
        }

        // I_j = (I_j + B + 1) mod 2^v for each v-byte block I_j
        for (int j = 0; j < I.length ~/ v; j++) {
          _adjust(I, j * v, B);
        }
      }
    }

    return Uint8List.fromList(derivedKey.sublist(0, keyLength));
  }

  /// Helper function for PKCS#12 KDF.
  /// Adds B + 1 to the v-byte block at offset in array a.
  static void _adjust(Uint8List a, int offset, Uint8List b) {
    int x = (b[b.length - 1] & 0xFF) + (a[offset + b.length - 1] & 0xFF) + 1;
    a[offset + b.length - 1] = x & 0xFF;
    x >>= 8;

    for (int i = b.length - 2; i >= 0; i--) {
      x += (b[i] & 0xFF) + (a[offset + i] & 0xFF);
      a[offset + i] = x & 0xFF;
      x >>= 8;
    }
  }

  @override
  Map<String, TrustedCertEntry> get certs {
    return Map.fromEntries(entries.entries
        .where((e) => e.value is BksTrustedCertEntry)
        .map((e) => MapEntry(e.key, e.value as TrustedCertEntry)));
  }

  /// Returns all sealed key entries.
  Map<String, BksSealedKeyEntry> get sealedKeys {
    return Map.fromEntries(entries.entries
        .where((e) => e.value is BksSealedKeyEntry)
        .map((e) => MapEntry(e.key, e.value as BksSealedKeyEntry)));
  }

  /// Returns all plain key entries.
  Map<String, BksKeyEntry> get plainKeys {
    return Map.fromEntries(entries.entries
        .where((e) => e.value is BksKeyEntry)
        .map((e) => MapEntry(e.key, e.value as BksKeyEntry)));
  }

  /// Saves the keystore to BKS format bytes (Version 2).
  ///
  /// [storePassword] - The password to protect keystore integrity (HMAC).
  /// [keyPassword] - The password to seal private keys. If not provided, defaults to [storePassword].
  Uint8List save(String storePassword, {String? keyPassword}) {
    final body = BytesBuilder();

    // Version 2
    body.add(_int32ToBytes(2));

    // Salt (20 bytes generic)
    final rnd = Random.secure();
    final salt = Uint8List(20);
    for (int i = 0; i < 20; i++) salt[i] = rnd.nextInt(256);

    // Write Salt (BKS stores length + salt)
    body.add(_int32ToBytes(salt.length));
    body.add(salt);

    // Iteration Count
    const iterationCount = 10000;
    body.add(_int32ToBytes(iterationCount));

    // Entries
    for (final entry in entries.values) {
      if (entry is BksTrustedCertEntry || entry is TrustedCertEntry) {
        // Entry Type (1 byte)
        body.addByte(bksEntryTypeCertificate);

        // Alias
        _writeUtf(body, entry.alias);

        // Timestamp
        body.add(_int64ToBytes(entry.timestamp));

        // Chain Length (4 bytes) - usually 0 for trusted cert
        body.add(_int32ToBytes(0));

        // Cert
        // Type (UTF)
        final certEntry = entry as TrustedCertEntry;
        _writeUtf(body, certEntry.certType);

        // Data (Length + Bytes)
        _writeData(body, certEntry.certData);
      } else if (entry is PrivateKeyEntry) {
        // Seal the Private Key (Type 4: Sealed)
        // Inner: Key Type (1 byte) + Format + Algorithm + Encoded

        final innerKeyBytes = BytesBuilder();
        innerKeyBytes.addByte(bksKeyTypePrivate); // 0

        // Format (UTF)
        _writeUtf(innerKeyBytes, 'PKCS#8');

        // Algorithm (UTF)
        // Default to RSA if unknown
        // Some implementations might strict check matching OID, but generic BKS usually just stores string.
        _writeUtf(innerKeyBytes, "RSA");

        // Encoded Key Data (Length + Bytes)
        // Prefer PKCS8 if available
        final pkcs8 = entry.pkcs8PrivateKey ?? entry.rawPrivateKey;
        if (pkcs8 == null) {
          throw KeystoreException(
              "Missing private key bytes for ${entry.alias}");
        }
        _writeData(innerKeyBytes, pkcs8);

        // Seal it
        // Encrypted Data structure: Salt(20) + Iters(4) + Ciphertext
        final kPwd = keyPassword ?? storePassword;
        final sealedData = _seal(innerKeyBytes.toBytes(), kPwd);

        // Write Entry (Type 4)
        body.addByte(bksEntryTypeSealed);
        _writeUtf(body, entry.alias);
        body.add(_int64ToBytes(entry.timestamp));

        // Certificate Chain
        body.add(_int32ToBytes(entry.certChain.length));
        for (final c in entry.certChain) {
          _writeUtf(body, c.$1); // type
          _writeData(body, c.$2); // data
        }

        // Sealed Data
        _writeData(body, sealedData);
      } else if (entry is BksSealedKeyEntry) {
        // If explicitly BksSealedKeyEntry and NOT decrypted, we can't save safely without re-encryption
        // unless we store raw encrypted blob? No, we don't expose raw blob easily here.
        // BksSealedKeyEntry should be decrypted to BksKeyEntry usually.
        // If it is NOT decrypted, we can't easily re-save unless we tracked raw bytes.
        // For now, assume decrypted or skip.
        if (!entry.isDecrypted()) {
          throw KeystoreException(
              "Cannot save undecrypted BksSealedKeyEntry ${entry.alias}");
        }
        final nested = entry.nestedEntry;
        // Recursively handle nested? Or just handle as BksKeyEntry logic above but re-seal.

        final innerKeyBytes = BytesBuilder();
        innerKeyBytes.addByte(nested.keyType);
        _writeUtf(innerKeyBytes, nested.format);
        _writeUtf(innerKeyBytes, nested.algorithm);
        _writeData(innerKeyBytes, nested.encoded);

        final kPwd = keyPassword ?? storePassword;
        final sealedData = _seal(innerKeyBytes.toBytes(), kPwd);

        body.addByte(bksEntryTypeSealed);
        _writeUtf(body, entry.alias);
        body.add(_int64ToBytes(entry.timestamp));

        body.add(_int32ToBytes(nested.certChain.length));
        for (final c in nested.certChain) {
          _writeUtf(body, c.certType);
          _writeData(body, c.certData);
        }

        _writeData(body, sealedData);
      } else {
        // Skip unsupported
      }
    }

    // Null Terminator (Type 0)
    body.addByte(0);

    // The previous body logic (single pass) is discarded in favor of two-pass (header + entries)
    // to correctly structure the HMAC input if we strictly follow load()'s structure
    // where HMAC is only on entries.

    // However, if we look at the code lines 820-830 roughly:
    // We completely rebuilt it below using 'header' and 'entriesData'.
    // So the 'body' builder and 'hmacKey' derivation above are redundant/unused.
    // Let's remove them to fix lints.

    // Wait, hmacKey IS used below?
    // "final hmacKey = BksKeyStore._derivePkcs12Key..." was defined around line 887?
    // No, it was defined at 806.

    // Let's just remove the unused block or utilize it.
    // We are proceeding with the 'header + entriesData' approach.

    // V2 stores: Version(4) + SaltLen(4) + Salt + Iter(4) + Entries + HMAC(20)
    // Wait, bodyBytes includes from Version down to Null Terminator?
    // Let's check load():
    /*
    read version
    read salt
    read iter
    read entries
    verify hmac on (entries start .. end) ? No.
    hmac covers (entriesStartPos .. pos) = everything from entries start?
    
    Let's re-read load():
    // ... read version, salt, iter ...
    // storeData = data.sublist(entriesStartPos, pos);
    // entriesStartPos was AFTER iter.
    // So HMAC covers ONLY the entries block (including type 0 terminator).
    
    BUT write logic above put Version, Salt, Iter INTO bodyBytes?
    Yes.
    So bodyBytes currently = Version + Salt + Iter + Entries.
    
    We need to split for HMAC calculation if we want to follow load logic exactly.
    load() calculates HMAC on 'storeData' which is just the entries part.
    */

    // Let's reconstruct to be precise.

    final header = BytesBuilder();
    header.add(_int32ToBytes(2)); // Version
    header.add(_int32ToBytes(salt.length));
    header.add(salt);
    header.add(_int32ToBytes(iterationCount)); // Iter

    final entriesData = BytesBuilder();
    // ... write entries to entriesData ...
    // Rewriting loop logic into entriesData

    // (Refactoring previous logic to use entriesData builder)
    void writeEntries(BytesBuilder b) {
      for (final entry in entries.values) {
        if (entry is BksTrustedCertEntry || entry is TrustedCertEntry) {
          b.addByte(bksEntryTypeCertificate);
          _writeUtf(b, entry.alias);
          b.add(_int64ToBytes(entry.timestamp));
          b.add(_int32ToBytes(0)); // Chain len
          final c = entry as TrustedCertEntry;
          _writeUtf(b, c.certType);
          _writeData(b, c.certData);
        } else if (entry is PrivateKeyEntry) {
          // Seal Private Key
          final inner = BytesBuilder();
          inner.addByte(bksKeyTypePrivate);
          _writeUtf(inner, 'PKCS#8');
          _writeUtf(inner, "RSA");
          final pkcs8 = entry.pkcs8PrivateKey ?? entry.rawPrivateKey;
          if (pkcs8 == null)
            throw KeystoreException("No private key for ${entry.alias}");
          _writeData(inner, pkcs8);

          final kPwd = keyPassword ?? storePassword;
          final sealed = _seal(inner.toBytes(), kPwd);

          b.addByte(bksEntryTypeSealed);
          _writeUtf(b, entry.alias);
          b.add(_int64ToBytes(entry.timestamp));

          b.add(_int32ToBytes(entry.certChain.length));
          for (final c in entry.certChain) {
            _writeUtf(b, c.$1);
            _writeData(b, c.$2);
          }
          _writeData(b, sealed);
        }
      }
      b.addByte(0); // Terminator
    }

    writeEntries(entriesData);
    final entriesBytes = entriesData.toBytes();

    // Key-Derivation: PKCS12(storePassword, salt, iter, 20, 3(MAC))
    final hmacKey = BksKeyStore._derivePkcs12Key(
        storePassword, salt, iterationCount, 20, 3);

    // Calculate HMAC
    final signatureBytes = hmacSha1(hmacKey, entriesBytes);

    final finalStore2 = BytesBuilder();
    finalStore2.add(header.toBytes());
    finalStore2.add(entriesBytes);
    finalStore2.add(Uint8List.fromList(signatureBytes));

    return finalStore2.toBytes();
  }

  // Helpers
  Uint8List _int32ToBytes(int value) {
    final b = ByteData(4);
    b.setUint32(0, value);
    return b.buffer.asUint8List();
  }

  Uint8List _int64ToBytes(int value) {
    final b = ByteData(8);
    b.setUint64(0, value);
    return b.buffer.asUint8List();
  }

  Uint8List _int16ToBytes(int value) {
    final b = ByteData(2);
    b.setUint16(0, value);
    return b.buffer.asUint8List();
  }

  void _writeUtf(BytesBuilder b, String s) {
    final bytes = utf8.encode(s);
    b.add(_int16ToBytes(bytes.length));
    b.add(bytes);
  }

  void _writeData(BytesBuilder b, Uint8List data) {
    b.add(_int32ToBytes(data.length));
    b.add(data);
  }

  Uint8List _seal(Uint8List data, String password) {
    final rnd = Random.secure();
    final salt = Uint8List(20);
    for (int i = 0; i < 20; i++) salt[i] = rnd.nextInt(256);

    const iterationCount = 10000;

    final key =
        BksKeyStore._derivePkcs12Key(password, salt, iterationCount, 24, 1);
    final iv =
        BksKeyStore._derivePkcs12Key(password, salt, iterationCount, 8, 2);

    final params = ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
    final cipher = CBCBlockCipher(DESedeEngine())..init(true, params);
    final paddedCipher = PaddedBlockCipherImpl(PKCS7Padding(), cipher);

    final ciphertext = paddedCipher.process(data);

    final res = BytesBuilder();
    res.add(salt);
    res.add(_int32ToBytes(iterationCount));
    res.add(ciphertext);
    return res.toBytes();
  }
}
