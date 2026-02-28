@TestOn('browser')

import 'dart:js_util' as js_util;
import 'dart:typed_data';

import 'package:pdf_plus/src/utils/convert/hex/decoder.dart';
import 'package:pdf_plus/src/utils/convert/hex/encoder.dart';
import 'package:test/test.dart';

void main() {
  test('hex codec uses Uint8Array toHex/setFromHex when available', () {
    final global = js_util.globalThis;
    final uint8ArrayCtor = js_util.getProperty<Object>(global, 'Uint8Array');
    final prototype = js_util.getProperty<Object>(uint8ArrayCtor, 'prototype');

    final hadToHex = js_util.hasProperty(prototype, 'toHex');
    final hadSetFromHex = js_util.hasProperty(prototype, 'setFromHex');
    final previousToHex =
        hadToHex ? js_util.getProperty<Object?>(prototype, 'toHex') : null;
    final previousSetFromHex = hadSetFromHex
        ? js_util.getProperty<Object?>(prototype, 'setFromHex')
        : null;

    js_util.setProperty(global, '__toHexCalls', 0);
    js_util.setProperty(global, '__setFromHexCalls', 0);

    final toHexFn = _newJsFunction(const <String>[], '''
      globalThis.__toHexCalls = (globalThis.__toHexCalls || 0) + 1;
      return Array.from(this)
        .map(function (b) { return b.toString(16).padStart(2, '0'); })
        .join('');
    ''');
    final setFromHexFn = _newJsFunction(const <String>['hex'], '''
      globalThis.__setFromHexCalls = (globalThis.__setFromHexCalls || 0) + 1;
      for (var i = 0; i < hex.length; i += 2) {
        this[i >> 1] = parseInt(hex.slice(i, i + 2), 16);
      }
      return { read: hex.length, written: hex.length / 2 };
    ''');

    js_util.setProperty(prototype, 'toHex', toHexFn);
    js_util.setProperty(prototype, 'setFromHex', setFromHexFn);

    try {
      final encoded = hexEncoder.convert(Uint8List.fromList(<int>[
        0x00,
        0x01,
        0xab,
        0xff,
      ]));
      final decoded = hexDecoder.convert('0001abff');

      expect(encoded, '0001abff');
      expect(decoded, <int>[0x00, 0x01, 0xab, 0xff]);
      expect(
        js_util.getProperty<num>(global, '__toHexCalls'),
        greaterThan(0),
      );
      expect(
        js_util.getProperty<num>(global, '__setFromHexCalls'),
        greaterThan(0),
      );
    } finally {
      if (hadToHex) {
        js_util.setProperty(prototype, 'toHex', previousToHex);
      } else {
        _deleteJsProperty(prototype, 'toHex');
      }
      if (hadSetFromHex) {
        js_util.setProperty(prototype, 'setFromHex', previousSetFromHex);
      } else {
        _deleteJsProperty(prototype, 'setFromHex');
      }
      _deleteJsProperty(global, '__toHexCalls');
      _deleteJsProperty(global, '__setFromHexCalls');
    }
  });
}

Object _newJsFunction(List<String> args, String body) {
  final functionCtor =
      js_util.getProperty<Object>(js_util.globalThis, 'Function');
  return js_util.callConstructor<Object>(
    functionCtor,
    <Object?>[
      ...args,
      body,
    ],
  );
}

void _deleteJsProperty(Object target, String propertyName) {
  final reflect = js_util.getProperty<Object>(js_util.globalThis, 'Reflect');
  js_util.callMethod<Object>(
    reflect,
    'deleteProperty',
    <Object?>[target, propertyName],
  );
}
