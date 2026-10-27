import 'dart:typed_data';

/// Signed big-endian int64 at [offset].
int keystoreReadInt64(ByteData data, int offset) => data.getInt64(offset);

/// [value] as 8 big-endian bytes.
Uint8List keystoreInt64ToBytesBigEndian(int value) =>
    (ByteData(8)..setInt64(0, value)).buffer.asUint8List();
