import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/export.dart';

import 'keystore_base.dart';
import 'keystore_binary_utils.dart';

final PlatformCrypto _pkiCrypto = createPlatformCrypto();

const int _jksMagic = 0xFEEDFEED;
const int _jceksMagic = 0xCECECECE;

const int _tagPrivateKey = 1;
const int _tagTrustedCert = 2;
const int _tagSecretKey = 3;

/// `sun.security.provider.KeyProtector` (JKS private keys).
const String _jksKeyProtectorOid = '1.3.6.1.4.1.42.2.17.1.1';

/// `com.sun.crypto.provider.KeyProtector`, PBEWithMD5AndTripleDES (JCEKS).
const String _jceksKeyProtectorOid = '1.3.6.1.4.1.42.2.19.1';

/// A Java KeyStore in the JKS (`0xFEEDFEED`) or JCEKS (`0xCECECECE`) format,
/// as written by `sun.security.provider.JavaKeyStore` and
/// `com.sun.crypto.provider.JceKeyStore`.
///
/// Layout (big-endian):
///
///     magic · version (1 or 2) · count · entries · SHA-1 digest
///
/// - private key (tag 1): alias · date · protected key · chain
/// - trusted certificate (tag 2): alias · date · certificate
/// - certificate: type (version 2 only) · length · DER
///
/// The digest is `SHA-1(UTF-16BE(password) · "Mighty Aphrodite" · body)`.
/// Private keys are kept as loaded (protected) until
/// [JksPrivateKeyEntry.decrypt] is called, and written back untouched when
/// they were never decrypted.
class JksKeyStore extends AbstractKeystore {
  JksKeyStore._(String storeType, Map<String, KeystoreEntry> entries)
      : super(storeType, entries);

  /// An empty store to fill and [save] (`storeType` 'jks' or 'jceks').
  factory JksKeyStore.empty({String storeType = 'jks'}) {
    if (storeType != 'jks' && storeType != 'jceks') {
      throw ArgumentError.value(storeType, 'storeType', "must be 'jks' or 'jceks'");
    }
    return JksKeyStore._(storeType, <String, KeystoreEntry>{});
  }

  /// Loads a JKS or JCEKS keystore from bytes.
  ///
  /// With a non-empty [storePassword] the integrity digest is checked, as
  /// `KeyStore.load` does; with an empty one it is skipped.
  static JksKeyStore load(Uint8List bytes, {String storePassword = ''}) {
    try {
      return _load(bytes, storePassword);
    } on RangeError {
      throw BadKeystoreFormatException('Truncated JKS keystore');
    }
  }

  static JksKeyStore _load(Uint8List bytes, String storePassword) {
    if (bytes.length < 12) {
      throw BadKeystoreFormatException('JKS keystore too small');
    }
    final data = ByteData.sublistView(bytes);
    final magic = data.getUint32(0);
    if (magic != _jksMagic && magic != _jceksMagic) {
      throw Exception('Invalid JKS magic number');
    }
    final storeType = magic == _jceksMagic ? 'jceks' : 'jks';

    final version = data.getUint32(4);
    if (version != 1 && version != 2) {
      throw Exception('Unsupported JKS version: $version');
    }
    final count = data.getUint32(8);
    int offset = 12;

    String readUtf() {
      final length = data.getUint16(offset);
      offset += 2;
      final text = keystoreModifiedUtf8Decode(
          Uint8List.sublistView(bytes, offset, offset + length));
      offset += length;
      return text;
    }

    Uint8List readBlob() {
      final length = data.getUint32(offset);
      offset += 4;
      final blob = Uint8List.fromList(bytes.sublist(offset, offset + length));
      offset += length;
      return blob;
    }

    // Version 1 stores have no certificate type: it is always X.509.
    (String, Uint8List) readCertificate() {
      final type = version == 2 ? readUtf() : 'X.509';
      return (type, readBlob());
    }

    final entries = <String, KeystoreEntry>{};
    for (int i = 0; i < count; i++) {
      final tag = data.getUint32(offset);
      offset += 4;
      final alias = readUtf();
      final timestamp = keystoreReadInt64(data, offset);
      offset += 8;

      if (tag == _tagPrivateKey) {
        final protectedKey = readBlob();
        final chainLength = data.getUint32(offset);
        offset += 4;
        final chain = <(String, Uint8List)>[
          for (int j = 0; j < chainLength; j++) readCertificate(),
        ];
        entries[alias] = JksPrivateKeyEntry(
          alias: alias,
          timestamp: timestamp,
          storeType: storeType,
          certChain: chain,
          encryptedData: protectedKey,
        );
      } else if (tag == _tagTrustedCert) {
        final (certType, certData) = readCertificate();
        entries[alias] = TrustedCertEntry(
          alias: alias,
          timestamp: timestamp,
          storeType: storeType,
          certType: certType,
          certData: certData,
        );
      } else if (tag == _tagSecretKey && storeType == 'jceks') {
        // A Java-serialized SealedObject: its length is not stored, so the
        // rest of the file cannot be located without a Java deserializer.
        throw KeystoreException(
            'JCEKS secret key entry "$alias" is not supported');
      } else {
        throw Exception('Unknown JKS tag: $tag');
      }
    }

    if (storePassword.isNotEmpty) {
      // KeyStore.load reads the 20 digest bytes right after the entries; a
      // missing digest is a corrupt store, not a reason to skip the check.
      if (bytes.length - offset < 20) {
        throw Exception(
            'Keystore password incorrect or data corrupted: digest missing');
      }
      final computed = _storeDigest(
          storePassword, Uint8List.sublistView(bytes, 0, offset));
      if (!fixedTimeEqual(
          computed, Uint8List.sublistView(bytes, offset, offset + 20))) {
        throw Exception('Keystore password incorrect or data corrupted');
      }
    }

    return JksKeyStore._(storeType, entries);
  }

  /// Saves the keystore in the JKS format.
  ///
  /// [storePassword] keys the integrity digest. Decrypted private keys are
  /// protected again with [keyPassword] (default: [storePassword]); keys that
  /// were never decrypted are written back as loaded.
  Uint8List save(String storePassword, {String? keyPassword}) =>
      _encode(_jksMagic, storePassword, keyPassword);

  /// Saves the keystore in the JCEKS format (PBEWithMD5AndTripleDES keys).
  Uint8List saveJceks(String storePassword, {String? keyPassword}) =>
      _encode(_jceksMagic, storePassword, keyPassword);

  Uint8List _encode(int magic, String storePassword, String? keyPassword) {
    final body = BytesBuilder();
    body.add(_int32ToBytes(magic));
    body.add(_int32ToBytes(2));
    body.add(_int32ToBytes(entries.length));

    for (final entry in entries.values) {
      if (entry is PrivateKeyEntry) {
        body.add(_int32ToBytes(_tagPrivateKey));
        _writeJavaUtf(body, entry.alias);
        body.add(_int64ToBytes(entry.timestamp));

        final protectedKey = entry.encryptedDataBytes ??
            _protect(entry, magic, keyPassword ?? storePassword);
        body.add(_int32ToBytes(protectedKey.length));
        body.add(protectedKey);

        body.add(_int32ToBytes(entry.certChain.length));
        for (final (certType, certData) in entry.certChain) {
          _writeJavaUtf(body, certType);
          body.add(_int32ToBytes(certData.length));
          body.add(certData);
        }
      } else if (entry is TrustedCertEntry) {
        body.add(_int32ToBytes(_tagTrustedCert));
        _writeJavaUtf(body, entry.alias);
        body.add(_int64ToBytes(entry.timestamp));
        _writeJavaUtf(body, entry.certType);
        body.add(_int32ToBytes(entry.certData.length));
        body.add(entry.certData);
      } else {
        throw KeystoreException(
            'Unsupported entry type: ${entry.runtimeType}');
      }
    }

    final bodyBytes = body.toBytes();
    return (BytesBuilder()
          ..add(bodyBytes)
          ..add(_storeDigest(storePassword, bodyBytes)))
        .toBytes();
  }

  static Uint8List _protect(PrivateKeyEntry entry, int magic, String password) {
    final pkcs8 = entry.pkcs8PrivateKey ?? entry.rawPrivateKey;
    if (pkcs8 == null) {
      throw KeystoreException(
          'Cannot save private key entry ${entry.alias}: no private key loaded');
    }
    return magic == _jksMagic
        ? _jksProtectPrivateKey(pkcs8, password)
        : _jceksProtectPrivateKey(pkcs8, password);
  }
}

/// `SHA-1(UTF-16BE(password) · "Mighty Aphrodite" · data)`, from
/// `JavaKeyStore.getPreKeyedHash`.
Uint8List _storeDigest(String password, Uint8List data) {
  final input = BytesBuilder()
    ..add(utf16BeEncode(password))
    ..add(ascii.encode('Mighty Aphrodite'))
    ..add(data);
  return _pkiCrypto.sha1Sync(input.toBytes());
}

/// JCEKS Protection (PBEWithMD5AndTripleDES)
Uint8List _jceksProtectPrivateKey(Uint8List plainPkcs8, String password) {
  // 8-byte salt. Salts with equal halves get special treatment in the JDK
  // key derivation; drawing again keeps this writer out of that corner.
  Uint8List salt;
  do {
    salt = _pkiCrypto.randomBytes(8);
  } while (fixedTimeEqual(salt.sublist(0, 4), salt.sublist(4)));

  const int iterationCount = 200000; // JDK's JceKeyStore default

  final passwordBytes = Uint8List.fromList(password.codeUnits); // ASCII
  final digest1 =
      _jceksDerivePart(passwordBytes, salt.sublist(0, 4), iterationCount);
  final digest2 =
      _jceksDerivePart(passwordBytes, salt.sublist(4), iterationCount);

  final key = Uint8List(24);
  key.setAll(0, digest1);
  key.setAll(16, digest2.sublist(0, 8));

  final iv = digest2.sublist(8, 16);

  // 3DES-CBC-PKCS7
  final params = ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
  final cipher = CBCBlockCipher(DESedeEngine())..init(true, params);
  final paddedCipher = PaddedBlockCipherImpl(PKCS7Padding(), cipher);

  final encryptedData = paddedCipher.process(plainPkcs8);

  // EncryptedPrivateKeyInfo ::= SEQUENCE {
  //   SEQUENCE { OID 1.3.6.1.4.1.42.2.19.1,
  //              SEQUENCE { salt OCTET STRING, iterationCount INTEGER } },
  //   encryptedData OCTET STRING }
  final paramsDer = _DerWriter()
      .writeSequence(
          (w) => w.writeOctetString(salt).writeInteger(iterationCount))
      .toBytes();

  final algIdDer = _DerWriter()
      .writeSequence((w) => w
          .writeOidContent(Uint8List.fromList(
              [0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x13, 0x01]))
          .writeBytes(paramsDer))
      .toBytes();

  return _DerWriter()
      .writeSequence(
          (w) => w.writeBytes(algIdDer).writeOctetString(encryptedData))
      .toBytes();
}

// Minimal DER Writer
class _DerWriter {
  final BytesBuilder _b = BytesBuilder();

  Uint8List toBytes() => _b.toBytes();

  _DerWriter writeBytes(Uint8List b) {
    _b.add(b);
    return this;
  }

  _DerWriter writeSequence(void Function(_DerWriter) content) {
    final inner = _DerWriter();
    content(inner);
    final data = inner.toBytes();
    _b.addByte(0x30); // SEQUENCE
    _writeLength(data.length);
    _b.add(data);
    return this;
  }

  _DerWriter writeOctetString(Uint8List data) {
    _b.addByte(0x04); // OCTET STRING
    _writeLength(data.length);
    _b.add(data);
    return this;
  }

  _DerWriter writeNull() {
    _b
      ..addByte(0x05)
      ..addByte(0x00);
    return this;
  }

  _DerWriter writeInteger(int val) {
    _b.addByte(0x02); // INTEGER
    // Basic integer encoding (assuming positive for simplicity in this context)
    // If val < 128: 1 byte
    if (val < 128) {
      _b.addByte(1);
      _b.addByte(val);
    } else {
      // Encode big endian
      var bytes = <int>[];
      var v = val;
      while (v > 0) {
        bytes.insert(0, v & 0xFF);
        v >>= 8;
      }
      if (bytes.isEmpty) bytes.add(0); // Case 0

      if ((bytes[0] & 0x80) != 0) {
        bytes.insert(0, 0x00); // Pad zero to avoid negative interpretation
      }
      _b.addByte(bytes.length);
      _b.add(Uint8List.fromList(bytes));
    }
    return this;
  }

  _DerWriter writeOidContent(Uint8List contentBytes) {
    _b.addByte(0x06); // OID
    _writeLength(contentBytes.length);
    _b.add(contentBytes);
    return this;
  }

  void _writeLength(int len) {
    if (len < 128) {
      _b.addByte(len);
    } else {
      // Long form
      final bytes = <int>[];
      while (len > 0) {
        bytes.insert(0, len & 0xFF);
        len >>= 8;
      }
      if (bytes.isEmpty) bytes.add(0);

      _b.addByte(0x80 | bytes.length);
      _b.add(Uint8List.fromList(bytes));
    }
  }
}

/// Helpers for JKS Writing
Uint8List _int32ToBytes(int value) {
  final b = ByteData(4);
  b.setUint32(0, value);
  return b.buffer.asUint8List();
}

Uint8List _int64ToBytes(int value) {
  return keystoreInt64ToBytesBigEndian(value);
}

void _writeJavaUtf(BytesBuilder b, String s) {
  final encoded = keystoreModifiedUtf8Encode(s);
  if (encoded.length > 65535) {
    throw KeystoreException('String too long for JKS format');
  }
  final len = ByteData(2);
  len.setUint16(0, encoded.length);
  b.add(len.buffer.asUint8List());
  b.add(encoded);
}

/// `sun.security.provider.KeyProtector.protect`: a 20-byte salt, the key
/// XORed with an SHA-1 keystream and the plain SHA-1 of password and key,
/// wrapped in an EncryptedPrivateKeyInfo under the KeyProtector OID.
Uint8List _jksProtectPrivateKey(Uint8List plainKey, String password) {
  final salt = _pkiCrypto.randomBytes(20);
  final passwordBE = utf16BeEncode(password);

  final encrypted = _jksXor(plainKey, passwordBE, salt);
  final integrity = _pkiCrypto.sha1Sync(
      (BytesBuilder()
            ..add(passwordBE)
            ..add(plainKey))
          .toBytes());

  final protectedKey = (BytesBuilder()
        ..add(salt)
        ..add(encrypted)
        ..add(integrity))
      .toBytes();

  final algIdDer = _DerWriter()
      .writeSequence((w) => w
          .writeOidContent(Uint8List.fromList(
              [0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01]))
          .writeNull())
      .toBytes();

  return _DerWriter()
      .writeSequence(
          (w) => w.writeBytes(algIdDer).writeOctetString(protectedKey))
      .toBytes();
}

/// XOR with the KeyProtector keystream: `d0 = salt`,
/// `d(i) = SHA-1(UTF-16BE(password) · d(i-1))`.
Uint8List _jksXor(Uint8List input, Uint8List passwordBE, Uint8List salt) {
  Uint8List digest = salt;
  final out = Uint8List(input.length);
  int offset = 0;
  while (offset < input.length) {
    digest = _pkiCrypto.sha1Sync(
        (BytesBuilder()
              ..add(passwordBE)
              ..add(digest))
            .toBytes());
    final len = min(digest.length, input.length - offset);
    for (int i = 0; i < len; i++) {
      out[offset + i] = input[offset + i] ^ digest[i];
    }
    offset += len;
  }
  return out;
}

class JksPrivateKeyEntry extends PrivateKeyEntry {
  JksPrivateKeyEntry({
    required super.alias,
    required super.timestamp,
    required super.storeType,
    required super.certChain,
    required Uint8List super.encryptedData,
  });

  @override
  void decrypt(String password) {
    if (isDecrypted()) return;

    try {
      final protectedKey = encryptedDataBytes!;
      final Uint8List plaintext;
      if (protectedKey.isNotEmpty && protectedKey[0] == 0x30) {
        // EncryptedPrivateKeyInfo, in JKS and in JCEKS: the OID says which.
        final top = _DerReader(protectedKey).readSequence();
        final oid = top.readSequence().readOid();
        if (oid == _jksKeyProtectorOid) {
          plaintext = _jksRecover(top.readOctetString(), password,
              digestEncrypted: false);
        } else if (oid == _jceksKeyProtectorOid) {
          plaintext = _jceksDecrypt(protectedKey, password);
        } else {
          throw DecryptionFailureException(
              'Unsupported key protection algorithm: $oid');
        }
      } else {
        // Written by pdf_plus before 4.0.2: no EncryptedPrivateKeyInfo and
        // the integrity digest XORed together with the key.
        plaintext = _jksRecover(protectedKey, password, digestEncrypted: true);
      }

      pkcs8PrivateKey = plaintext;
      rawPrivateKey = _privateKeyOctets(plaintext) ?? plaintext;
      encryptedDataBytes = null;
    } catch (e) {
      if (e is KeystoreException) rethrow;
      throw DecryptionFailureException('Decryption failed: $e');
    }
  }

  /// `KeyProtector.recover`: `salt[20] · encrypted · digest[20]`.
  static Uint8List _jksRecover(Uint8List blob, String password,
      {required bool digestEncrypted}) {
    if (blob.length < 40) {
      throw DecryptionFailureException('Invalid JKS key data length');
    }
    final passwordBE = utf16BeEncode(password);
    final salt = blob.sublist(0, 20);
    final Uint8List plainKey;
    final Uint8List storedDigest;
    if (digestEncrypted) {
      final all = _jksXor(blob.sublist(20), passwordBE, salt);
      plainKey = all.sublist(0, all.length - 20);
      storedDigest = all.sublist(all.length - 20);
    } else {
      plainKey =
          _jksXor(blob.sublist(20, blob.length - 20), passwordBE, salt);
      storedDigest = blob.sublist(blob.length - 20);
    }
    final computed = _pkiCrypto.sha1Sync(
        (BytesBuilder()
              ..add(passwordBE)
              ..add(plainKey))
            .toBytes());
    if (!fixedTimeEqual(computed, storedDigest)) {
      throw DecryptionFailureException(
          'Password incorrect or integrity check failed');
    }
    return plainKey;
  }

  /// The privateKey OCTET STRING of a PKCS#8 PrivateKeyInfo, if it parses.
  static Uint8List? _privateKeyOctets(Uint8List pkcs8) {
    try {
      final reader = _DerReader(pkcs8).readSequence();
      if (reader.readInt() != 0) return null;
      reader.readSequence(); // AlgorithmIdentifier
      return reader.readOctetString();
    } catch (_) {
      return null;
    }
  }
}

/// Helper: UTF-16BE encoding
Uint8List utf16BeEncode(String s) {
  final units = s.codeUnits;
  final bytes = Uint8List(units.length * 2);
  final bd = ByteData.view(bytes.buffer);
  for (int i = 0; i < units.length; i++) {
    bd.setUint16(i * 2, units[i], Endian.big);
  }
  return bytes;
}

/// JCEKS Decryption (PBEWithMD5AndTripleDES)
Uint8List _jceksDecrypt(Uint8List encryptedPrivateKeyInfo, String password) {
  try {
    final reader = _DerReader(encryptedPrivateKeyInfo);
    // EncryptedPrivateKeyInfo ::= SEQUENCE {
    //   encryptionAlgorithm  AlgorithmIdentifier,
    //   encryptedData        OCTET STRING
    // }
    final top = reader.readSequence();
    final algReader = top.readSequence();
    algReader.readOid();

    // Parameters: SEQUENCE { salt OCTET STRING, iterationCount INTEGER }
    final paramReader = algReader.readSequence();
    final salt = paramReader.readOctetString();
    final iterations = paramReader.readInt();

    final encryptedData = top.readOctetString();

    // Split salt
    final half1 = salt.sublist(0, 4);
    final half2 = salt.sublist(4);

    // If the halves are equal, invert the second half (JCEKS quirk).
    if (fixedTimeEqual(half1, half2)) {
      for (int i = 0; i < 4; i++) half2[i] ^= 0xFF;
    }

    // Password is ASCII bytes
    final passwordBytes = Uint8List.fromList(password.codeUnits); // ASCII

    // Derive
    final digest1 = _jceksDerivePart(passwordBytes, half1, iterations);
    final digest2 = _jceksDerivePart(passwordBytes, half2, iterations);

    final key = Uint8List(24);
    key.setAll(0, digest1);
    key.setAll(16, digest2.sublist(0, 8));

    final iv = digest2.sublist(8, 16);

    // Decrypt
    final params = ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
    final cipher = CBCBlockCipher(DESedeEngine())..init(false, params);
    final paddedCipher = PaddedBlockCipherImpl(PKCS7Padding(), cipher);

    return paddedCipher.process(encryptedData);
  } catch (e) {
    throw DecryptionFailureException('JCEKS decryption failed: $e');
  }
}

Uint8List _jceksDerivePart(
    Uint8List password, Uint8List saltPart, int iterations) {
  // Initial: MD5(saltPart || password)
  Uint8List input = Uint8List(saltPart.length + password.length);
  input.setAll(0, saltPart);
  input.setAll(saltPart.length, password);

  Uint8List current = _pkiCrypto.md5Sync(input);

  // Rounds: MD5(current || password)
  for (int i = 1; i < iterations; i++) {
    Uint8List nextInput = Uint8List(current.length + password.length);
    nextInput.setAll(0, current);
    nextInput.setAll(current.length, password);
    current = _pkiCrypto.md5Sync(nextInput);
  }
  return current;
}

// --- DER Reader Helper (Minimal) ---

class _DerReader {
  final Uint8List _data;
  int _off = 0;

  _DerReader(this._data);

  int _readByte() {
    if (_off >= _data.length) throw Exception('DER: unexpected EOF');
    return _data[_off++];
  }

  Uint8List _readBytes(int n) {
    if (_off + n > _data.length)
      throw Exception('DER: unexpected EOF (need $n bytes)');
    final v = _data.sublist(_off, _off + n);
    _off += n;
    return v;
  }

  int _readLength() {
    final b = _readByte();
    if ((b & 0x80) == 0) {
      return b & 0x7F;
    }
    final num = b & 0x7F;
    if (num == 0 || num > 4)
      throw Exception('DER: invalid length octets: $num');
    int len = 0;
    for (int i = 0; i < num; i++) {
      len = (len << 8) | _readByte();
    }
    return len;
  }

  _DerReader readSequence() {
    final tag = _readByte();
    if (tag != 0x30)
      throw Exception(
          'DER: expected SEQUENCE (0x30), got 0x${tag.toRadixString(16)}');
    final len = _readLength();
    final v = _readBytes(len);
    return _DerReader(v);
  }

  Uint8List readOctetString() {
    final tag = _readByte();
    if (tag != 0x04)
      throw Exception(
          'DER: expected OCTET STRING (0x04), got 0x${tag.toRadixString(16)}');
    final len = _readLength();
    return _readBytes(len);
  }

  int readInt() {
    final tag = _readByte();
    if (tag != 0x02)
      throw Exception(
          'DER: expected INTEGER (0x02), got 0x${tag.toRadixString(16)}');
    final len = _readLength();
    final v = _readBytes(len);

    int n = 0;
    for (final b in v) {
      n = (n << 8) | (b & 0xFF);
    }
    return n;
  }

  String readOid() {
    final tag = _readByte();
    if (tag != 0x06)
      throw Exception(
          'DER: expected OID (0x06), got 0x${tag.toRadixString(16)}');
    final len = _readLength();
    final v = _readBytes(len);
    return _decodeOid(v);
  }

  String _decodeOid(Uint8List bytes) {
    if (bytes.isEmpty) throw Exception('DER: empty OID');
    final first = bytes[0];
    final x = first ~/ 40;
    final y = first % 40;

    final parts = <int>[x, y];
    int value = 0;

    for (int i = 1; i < bytes.length; i++) {
      final b = bytes[i];
      value = (value << 7) | (b & 0x7F);
      if ((b & 0x80) == 0) {
        parts.add(value);
        value = 0;
      }
    }
    return parts.join('.');
  }
}

// Helper function for constant-time comparison (anti-timing attack).
bool fixedTimeEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  int result = 0;
  for (int i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}
