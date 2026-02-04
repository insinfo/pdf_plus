import 'dart:typed_data';

/// Exception thrown when a keystore parsing operation fails.
class KeystoreException implements Exception {
  final String message;
  KeystoreException(this.message);

  @override
  String toString() => 'KeystoreException: $message';
}

/// Exception thrown when keystore format is invalid.
class BadKeystoreFormatException extends KeystoreException {
  BadKeystoreFormatException(super.message);
}

/// Exception thrown when keystore version is unsupported.
class UnsupportedKeystoreVersionException extends KeystoreException {
  UnsupportedKeystoreVersionException(super.message);
}

/// Exception thrown when keystore signature verification fails.
class KeystoreSignatureException extends KeystoreException {
  KeystoreSignatureException(super.message);
}

/// Exception thrown when duplicate alias is found.
class DuplicateAliasException extends KeystoreException {
  DuplicateAliasException(super.message);
}

/// Exception thrown when decryption fails.
class DecryptionFailureException extends KeystoreException {
  DecryptionFailureException(super.message);
}

/// Represents an entry in a keystore.
abstract class KeystoreEntry {
  /// The alias of this entry.
  String alias;

  /// The timestamp when this entry was created (milliseconds since epoch).
  int timestamp;

  /// The type of the store this entry belongs to.
  String storeType;

  KeystoreEntry({
    required this.alias,
    required this.timestamp,
    required this.storeType,
  });

  /// Returns true if this entry has been decrypted.
  bool isDecrypted();

  /// Decrypts this entry using the given password.
  void decrypt(String password);
}

/// Represents a trusted certificate entry.
class TrustedCertEntry extends KeystoreEntry {
  /// The type of certificate (usually "X.509").
  final String certType;

  /// The DER-encoded certificate data.
  final Uint8List certData;

  TrustedCertEntry({
    required super.alias,
    required super.timestamp,
    required super.storeType,
    required this.certType,
    required this.certData,
  });

  @override
  bool isDecrypted() => true;

  @override
  void decrypt(String password) {
    // Certificates are not encrypted
  }
}

/// Represents a private key entry.
class PrivateKeyEntry extends KeystoreEntry {
  /// The certificate chain associated with the private key.
  /// Each element is a tuple of (certType, certData).
  final List<(String, Uint8List)> certChain;

  /// The encrypted private key data (PKCS#8 EncryptedPrivateKeyInfo).
  Uint8List? encryptedDataBytes;

  /// The decrypted private key (raw format).
  Uint8List? rawPrivateKey;

  /// The decrypted private key in PKCS#8 format.
  Uint8List? pkcs8PrivateKey;

  /// The algorithm OID of the private key.
  List<int>? keyAlgorithmOid;

  PrivateKeyEntry({
    required super.alias,
    required super.timestamp,
    required super.storeType,
    required this.certChain,
    Uint8List? encryptedData,
    Uint8List? privateKey,
    Uint8List? privateKeyPkcs8,
    List<int>? algorithmOid,
  })  : encryptedDataBytes = encryptedData,
        rawPrivateKey = privateKey,
        pkcs8PrivateKey = privateKeyPkcs8,
        keyAlgorithmOid = algorithmOid;

  /// Gets the raw private key bytes. Throws if not decrypted.
  Uint8List get privateKey {
    if (!isDecrypted()) {
      throw StateError('Entry not decrypted. Call decrypt() first.');
    }
    return rawPrivateKey!;
  }

  /// Gets the PKCS#8 encoded private key. Throws if not decrypted.
  Uint8List get privateKeyPkcs8 {
    if (!isDecrypted()) {
      throw StateError('Entry not decrypted. Call decrypt() first.');
    }
    return pkcs8PrivateKey!;
  }

  /// Gets the algorithm OID. Throws if not decrypted.
  List<int> get algorithmOid {
    if (!isDecrypted()) {
      throw StateError('Entry not decrypted. Call decrypt() first.');
    }
    return keyAlgorithmOid!;
  }

  @override
  bool isDecrypted() => encryptedDataBytes == null;

  @override
  void decrypt(String password) {
    if (isDecrypted()) return;

    // TODO: Implement JKS/JCEKS private key decryption
    // This requires:
    // 1. Parse the EncryptedPrivateKeyInfo ASN.1 structure
    // 2. Determine the encryption algorithm (JKS proprietary or JCEKS PBE)
    // 3. Decrypt using the appropriate algorithm
    // 4. Parse the resulting PKCS#8 PrivateKeyInfo
    throw UnimplementedError('Private key decryption not yet implemented');
  }
}

/// Abstract base class for keystores.
abstract class AbstractKeystore {
  /// The type of keystore (e.g., "jks", "jceks", "bks").
  final String storeType;

  /// Map of aliases to entries.
  final Map<String, KeystoreEntry> entries;

  AbstractKeystore(this.storeType, this.entries);

  /// Returns all trusted certificate entries.
  Map<String, TrustedCertEntry> get certs {
    return Map.fromEntries(entries.entries
        .where((e) => e.value is TrustedCertEntry)
        .map((e) => MapEntry(e.key, e.value as TrustedCertEntry)));
  }

  /// Returns all private key entries.
  Map<String, PrivateKeyEntry> get privateKeys {
    return Map.fromEntries(entries.entries
        .where((e) => e.value is PrivateKeyEntry)
        .map((e) => MapEntry(e.key, e.value as PrivateKeyEntry)));
  }

  /// Gets all certificates from the keystore as DER-encoded bytes.
  List<Uint8List> getAllCertificates() {
    final result = <Uint8List>[];

    // Add certificates from trusted cert entries
    for (final entry in certs.values) {
      result.add(entry.certData);
    }

    // Add certificates from private key entry chains
    for (final entry in privateKeys.values) {
      for (final (_, certData) in entry.certChain) {
        result.add(certData);
      }
    }

    return result;
  }
}
