import 'dart:js_util' as js_util;
import 'dart:typed_data';

int _toHexSupport = 0;
int _setFromHexSupport = 0;

String? tryNativeHexEncode(List<int> bytes, int start, int end) {
  if (start < 0 || end < start || end > bytes.length) return null;
  if (bytes is! Uint8List) return null;

  final view = (start == 0 && end == bytes.length)
      ? bytes
      : Uint8List.sublistView(bytes, start, end);
  if (!_supportsToHex(view)) return null;

  try {
    return js_util.callMethod<String>(view, 'toHex', const <Object>[]);
  } catch (_) {
    return null;
  }
}

Uint8List? tryNativeHexDecode(String input) {
  if (!input.length.isEven) return null;

  final out = Uint8List(input.length ~/ 2);
  if (!_supportsSetFromHex(out)) return null;

  try {
    js_util.callMethod<Object>(out, 'setFromHex', <Object>[input]);
    return out;
  } catch (_) {
    return null;
  }
}

bool _supportsToHex(Uint8List value) {
  if (_toHexSupport == 1) return true;
  if (_toHexSupport == -1) return false;
  try {
    _toHexSupport = js_util.hasProperty(value, 'toHex') ? 1 : -1;
  } catch (_) {
    _toHexSupport = -1;
  }
  return _toHexSupport == 1;
}

bool _supportsSetFromHex(Uint8List value) {
  if (_setFromHexSupport == 1) return true;
  if (_setFromHexSupport == -1) return false;
  try {
    _setFromHexSupport = js_util.hasProperty(value, 'setFromHex') ? 1 : -1;
  } catch (_) {
    _setFromHexSupport = -1;
  }
  return _setFromHexSupport == 1;
}
