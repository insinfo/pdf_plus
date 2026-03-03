import 'dart:convert';
import 'dart:html' as html;
import 'dart:js_util' as js_util;
import 'dart:typed_data';

String base64EncodeBytesImpl(Uint8List bytes) {
  if (bytes.isEmpty) return '';
  final binary = String.fromCharCodes(bytes);
  return html.window.btoa(binary);
}

Uint8List base64DecodeToBytesImpl(String value) {
  final normalized = _stripWhitespace(value);
  if (normalized.isEmpty) return Uint8List(0);

  final nativeBytes = _decodeBase64WithNativeUint8Array(normalized);
  if (nativeBytes != null) {
    return nativeBytes;
  }

  final binary = html.window.atob(normalized);
  final out = Uint8List(binary.length);
  for (var i = 0; i < binary.length; i++) {
    out[i] = binary.codeUnitAt(i);
  }
  return out;
}

String base64EncodeUtf8Impl(String value) {
  final bytes = _encodeUtf8WithTextEncoder(value);
  return base64EncodeBytesImpl(bytes);
}

String base64DecodeUtf8Impl(String value) {
  final bytes = base64DecodeToBytesImpl(value);
  return _decodeUtf8WithTextDecoder(bytes);
}

String _stripWhitespace(String input) {
  if (!input.contains(RegExp(r'\s'))) {
    return input;
  }
  return input.replaceAll(RegExp(r'\s+'), '');
}

Uint8List _encodeUtf8WithTextEncoder(String value) {
  try {
    final global = js_util.globalThis;
    final ctor = js_util.getProperty<Object?>(global, 'TextEncoder');
    if (ctor == null) {
      return Uint8List.fromList(utf8.encode(value));
    }
    final encoder = js_util.callConstructor<Object>(ctor, const <Object>[]);
    final result = js_util.callMethod<Object>(
      encoder,
      'encode',
      <Object>[value],
    );
    return _toUint8List(result);
  } catch (_) {
    return Uint8List.fromList(utf8.encode(value));
  }
}

String _decodeUtf8WithTextDecoder(Uint8List bytes) {
  try {
    final global = js_util.globalThis;
    final ctor = js_util.getProperty<Object?>(global, 'TextDecoder');
    if (ctor == null) {
      return utf8.decode(bytes);
    }
    final decoder = js_util.callConstructor<Object>(ctor, const <Object>[]);
    final result = js_util.callMethod<Object>(
      decoder,
      'decode',
      <Object>[bytes],
    );
    if (result is String) {
      return result;
    }
    return utf8.decode(bytes);
  } catch (_) {
    return utf8.decode(bytes);
  }
}

Uint8List? _decodeBase64WithNativeUint8Array(String normalized) {
  try {
    final global = js_util.globalThis;
    final uint8ArrayCtor = js_util.getProperty<Object?>(global, 'Uint8Array');
    if (uint8ArrayCtor == null) return null;

    if (js_util.hasProperty(uint8ArrayCtor, 'fromBase64')) {
      final result = js_util.callMethod<Object>(
        uint8ArrayCtor,
        'fromBase64',
        <Object>[normalized],
      );
      return _toUint8List(result);
    }

    final prototype = js_util.getProperty<Object?>(uint8ArrayCtor, 'prototype');
    if (prototype != null && js_util.hasProperty(prototype, 'setFromBase64')) {
      final targetLength = _decodedLengthFromBase64(normalized);
      final target = js_util.callConstructor<Object>(
        uint8ArrayCtor,
        <Object>[targetLength],
      );
      js_util.callMethod<Object>(
        target,
        'setFromBase64',
        <Object>[normalized],
      );
      return _toUint8List(target);
    }
  } catch (_) {}

  return null;
}

int _decodedLengthFromBase64(String value) {
  final length = value.length;
  if (length == 0) return 0;

  var padding = 0;
  if (value.codeUnitAt(length - 1) == 61) padding++;
  if (length > 1 && value.codeUnitAt(length - 2) == 61) padding++;
  return ((length * 3) >> 2) - padding;
}

Uint8List _toUint8List(Object result) {
  if (result is Uint8List) {
    return result;
  }
  if (result is ByteBuffer) {
    return Uint8List.view(result);
  }
  if (result is List<int>) {
    return Uint8List.fromList(result);
  }

  try {
    if (js_util.hasProperty(result, 'buffer') &&
        js_util.hasProperty(result, 'byteOffset') &&
        js_util.hasProperty(result, 'byteLength')) {
      final buffer = js_util.getProperty<ByteBuffer>(result, 'buffer');
      final byteOffset = js_util.getProperty<num>(result, 'byteOffset').toInt();
      final byteLength = js_util.getProperty<num>(result, 'byteLength').toInt();
      return Uint8List.view(buffer, byteOffset, byteLength);
    }
  } catch (_) {}

  throw const FormatException('Falha ao converter resultado do TextEncoder');
}
