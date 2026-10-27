// 64-bit big-endian integers for keystore dates.
//
// The VM reads and writes them natively with ByteData; JavaScript has no
// 64-bit integers (`getInt64` throws, `>> 32` truncates), so the browser
// build splits them into two 32-bit halves.
export 'keystore_int64_vm.dart'
    if (dart.library.html) 'keystore_int64_web.dart';
