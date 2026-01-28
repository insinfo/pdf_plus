/// Implementation of the Bidi algorithm, as described in http://www.unicode.org/reports/tr9/tr9-17.html.
///
/// Converts *logical* strings to their equivalent *visual* representation. Persian, Hebrew and Arabic languages (and any other RTL language) are supported.

import 'dart:core';
import 'dart:math';
import 'dart:collection';

part 'core/bidi.dart';
part 'core/character_type.dart';
part 'core/direction_override.dart';
part 'core/shape_joining_type.dart';
part 'core/decomposition_type.dart';
part 'core/letter_form.dart';
part 'core/canonical_class.dart';
part 'core/character_category.dart';
part 'core/paragraph.dart';
part 'core/stack.dart';
part 'core/character_mirror.dart';
part 'core/bidi_characters.dart';
part 'core/shaping_resolver.dart';
part 'core/unicode_character_resolver.dart';
