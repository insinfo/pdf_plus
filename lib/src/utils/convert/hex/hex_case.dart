import 'hex.dart';

String hexLower(List<int> bytes) => hex.encode(bytes);

String hexUpper(List<int> bytes) => hex.encode(bytes).toUpperCase();

String intHexLower(int value) => value.toRadixString(16);

String intHexUpper(int value) => value.toRadixString(16).toUpperCase();

String bigIntHexLower(BigInt value) => value.toRadixString(16);

String bigIntHexUpper(BigInt value) => value.toRadixString(16).toUpperCase();
