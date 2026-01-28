import 'package:meta/meta.dart' show experimental;
import '../petitparser/core.dart' show Failure;

import 'core/xml/nodes/node.dart';
import 'core/xml/utils/cache.dart';
import 'core/xpath/evaluation/context.dart';
import 'core/xpath/evaluation/expression.dart';
import 'core/xpath/evaluation/functions.dart';
import 'core/xpath/exceptions/parser_exception.dart';
import 'core/xpath/parser.dart';
import 'core/xpath/types/sequence.dart';

export 'core/xpath/evaluation/functions.dart' show XPathFunction;
export 'core/xpath/exceptions/evaluation_exception.dart';
export 'core/xpath/exceptions/parser_exception.dart';
export 'core/xpath/generator.dart' show XPathGenerator;
export 'core/xpath/types/sequence.dart';

extension XPathExtension on XmlNode {
  /// Returns an iterable over the nodes matching the provided XPath
  /// [expression].
  @experimental
  Iterable<XmlNode> xpath(
    String expression, {
    Map<String, XPathSequence> variables = const {},
    Map<String, Object> functions = const {},
  }) =>
      xpathEvaluate(
        expression,
        variables: variables,
        functions: functions,
      ).whereType<XmlNode>();

  /// Returns the value resulting from evaluating the given XPath [expression].
  ///
  /// The returned value is of type [XPathSequence], which is an iterable of
  /// [Object]s.
  @experimental
  XPathSequence xpathEvaluate(
    String expression, {
    Map<String, XPathSequence> variables = const {},
    Map<String, Object> functions = const {},
  }) {
    final allFunctions = {...standardFunctions, ...functions};
    return _cache[expression](
      XPathContext(this, variables: variables, functions: allFunctions),
    );
  }
}

final _parser = const XPathParser().build();
final _cache = XmlCache<String, XPathExpression>((expression) {
  final result = _parser.parse(expression);
  if (result is Failure) {
    throw XPathParserException(
      result.message,
      buffer: expression,
      position: result.position,
    );
  }
  return result.value;
}, 25);
