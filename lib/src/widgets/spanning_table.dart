import 'dart:math' as math;

import 'package:meta/meta.dart';
import 'package:pdf_plus/src/utils/vector_math/vector_math_64.dart';

import '../../pdf.dart';
import '../../widgets.dart';

@immutable
class SpanningTableCell {
  const SpanningTableCell({
    required this.child,
    this.columnSpan = 1,
    this.rowSpan = 1,
    this.padding = EdgeInsets.zero,
    this.alignment,
    this.decoration,
    this.verticalAlignment,
  })  : assert(columnSpan > 0),
        assert(rowSpan > 0);

  final Widget child;
  final int columnSpan;
  final int rowSpan;
  final EdgeInsetsGeometry padding;
  final AlignmentGeometry? alignment;
  final BoxDecoration? decoration;
  final TableCellVerticalAlignment? verticalAlignment;
}

@immutable
class SpanningTableRow {
  const SpanningTableRow({
    required this.children,
    this.repeat = false,
    this.decoration,
    this.verticalAlignment,
  });

  final List<SpanningTableCell> children;
  final bool repeat;
  final BoxDecoration? decoration;
  final TableCellVerticalAlignment? verticalAlignment;
}

class SpanningTableContext extends WidgetContext {
  int firstRow = 0;
  int lastRow = 0;
  int? deferredRow;
  bool retryDeferredRow = false;

  @override
  void apply(SpanningTableContext other) {
    firstRow = other.firstRow;
    lastRow = other.lastRow;
    deferredRow = other.deferredRow;
    retryDeferredRow = other.retryDeferredRow;
  }

  @override
  WidgetContext clone() => SpanningTableContext()..apply(this);

  @override
  String toString() => '$runtimeType firstRow: $firstRow lastRow: $lastRow '
      'deferredRow: $deferredRow retryDeferredRow: $retryDeferredRow';
}

/// Exception thrown when [SpanningTable] cannot produce a safe layout.
class SpanningTableException implements Exception {
  SpanningTableException(this.message);

  final String message;

  @override
  String toString() => message;
}

/// Controls how [SpanningTable] handles a row group that is taller than the
/// available page height.
enum SpanningTableOverflowMode {
  /// Throw a [SpanningTableException] when a row group cannot fit on a page.
  strict,

  /// Clip the row group to the available page height and continue rendering.
  clip,
}

typedef SpanningTableCellBuilder = Widget? Function(
    int index, dynamic data, int rowNum);

typedef SpanningTableCellTextStyleBuilder = TextStyle? Function(
    int index, dynamic data, int rowNum);

class _TablePlacement {
  _TablePlacement({
    required this.cell,
    required this.row,
    required this.column,
    required this.rowSpan,
    required this.columnSpan,
  });

  final SpanningTableCell cell;
  final int row;
  final int column;
  final int rowSpan;
  final int columnSpan;
  PdfRect? rect;
}

class _ResolvedLayout {
  _ResolvedLayout({
    required this.widths,
    required this.heights,
    required this.placements,
    required this.occupancy,
  });

  final List<double> widths;
  final List<double> heights;
  final List<_TablePlacement> placements;
  final List<List<int?>> occupancy;
}

class _VisibleLayout {
  _VisibleLayout({
    required this.rows,
    required this.rowBottoms,
    required this.totalHeight,
    required this.nextRow,
  });

  final List<int> rows;
  final Map<int, double> rowBottoms;
  final double totalHeight;
  final int nextRow;
}

/// A table widget that can span pages while preserving rowspan and colspan.
///
/// A group of rows connected by [SpanningTableCell.rowSpan] is always rendered
/// on the same page. If that group is taller than the available page height,
/// [SpanningTableOverflowMode.strict] throws a [SpanningTableException] and
/// [SpanningTableOverflowMode.clip] clips the overflowing content and advances
/// to the next row group.
class SpanningTable extends Widget with SpanningWidget {
  SpanningTable({
    this.children = const <SpanningTableRow>[],
    this.border,
    this.defaultVerticalAlignment = TableCellVerticalAlignment.top,
    this.defaultCellAlignment = Alignment.topLeft,
    this.defaultColumnWidth = const IntrinsicColumnWidth(),
    this.columnWidths,
    this.tableWidth = TableWidth.max,
    this.overflow = SpanningTableOverflowMode.strict,
    this.textDirection,
  }) : super();

  factory SpanningTable.fromTextArray({
    Context? context,
    required List<List<dynamic>> data,
    EdgeInsetsGeometry cellPadding = const EdgeInsets.all(5),
    double cellHeight = 0,
    AlignmentGeometry cellAlignment = Alignment.topLeft,
    Map<int, AlignmentGeometry>? cellAlignments,
    TextStyle? cellStyle,
    TextStyle? oddCellStyle,
    OnCellFormat? cellFormat,
    OnCellDecoration? cellDecoration,
    int headerCount = 1,
    List<dynamic>? headers,
    EdgeInsetsGeometry? headerPadding,
    double? headerHeight,
    AlignmentGeometry headerAlignment = Alignment.center,
    Map<int, AlignmentGeometry>? headerAlignments,
    TextStyle? headerStyle,
    OnCellFormat? headerFormat,
    TableBorder? border = const TableBorder(
      left: BorderSide(),
      right: BorderSide(),
      top: BorderSide(),
      bottom: BorderSide(),
      horizontalInside: BorderSide(),
      verticalInside: BorderSide(),
    ),
    Map<int, TableColumnWidth>? columnWidths,
    TableColumnWidth defaultColumnWidth = const IntrinsicColumnWidth(),
    TableWidth tableWidth = TableWidth.max,
    BoxDecoration? headerDecoration,
    BoxDecoration? headerCellDecoration,
    BoxDecoration? rowDecoration,
    BoxDecoration? oddRowDecoration,
    TextDirection? headerDirection,
    TextDirection? tableDirection,
    SpanningTableCellBuilder? cellBuilder,
    SpanningTableCellTextStyleBuilder? textStyleBuilder,
    TableCellVerticalAlignment defaultVerticalAlignment =
        TableCellVerticalAlignment.full,
    SpanningTableOverflowMode overflow = SpanningTableOverflowMode.strict,
    TextDirection? textDirection,
    bool repeatHeaderRows = true,
  }) {
    assert(headerCount >= 0);

    if (context != null) {
      final theme = Theme.of(context);
      headerStyle ??= theme.tableHeader;
      cellStyle ??= theme.tableCell;
    }

    headerPadding ??= cellPadding;
    headerHeight ??= cellHeight;
    oddRowDecoration ??= rowDecoration;
    oddCellStyle ??= cellStyle;
    cellAlignments ??= const <int, AlignmentGeometry>{};
    headerAlignments ??= cellAlignments;

    final rows = <SpanningTableRow>[];
    final effectiveDirection = textDirection ??
        context?.dependsOn<InheritedDirectionality>()?.textDirection ??
        TextDirection.ltr;

    SpanningTableCell buildCell({
      required dynamic cell,
      required int index,
      required int rowNum,
      required bool header,
      required bool odd,
    }) {
      if (cell is SpanningTableCell) {
        return cell;
      }

      final align = header
          ? headerAlignments![index] ?? headerAlignment
          : cellAlignments![index] ?? cellAlignment;
      final resolvedAlign = align.resolve(effectiveDirection);
      final textAlign = _textAlign(resolvedAlign);
      final padding = header ? headerPadding! : cellPadding;
      final minHeight = header ? headerHeight! : cellHeight;
      final decoration = header
          ? headerCellDecoration
          : cellDecoration?.call(index, cell, rowNum);
      final child = cell is Widget
          ? cell
          : cellBuilder?.call(index, cell, rowNum) ??
              Text(
                header
                    ? headerFormat == null
                        ? cell.toString()
                        : headerFormat(index, cell)
                    : cellFormat == null
                        ? cell.toString()
                        : cellFormat(index, cell),
                style: header
                    ? headerStyle
                    : textStyleBuilder?.call(index, cell, rowNum) ??
                        (odd ? oddCellStyle : cellStyle),
                textAlign: textAlign,
                textDirection: header ? headerDirection : tableDirection,
              );

      return SpanningTableCell(
        alignment: align,
        padding: padding,
        decoration: decoration,
        child: minHeight > 0
            ? ConstrainedBox(
                constraints: BoxConstraints(minHeight: minHeight),
                child: child,
              )
            : child,
      );
    }

    var rowNum = 0;
    if (headers != null) {
      rows.add(
        SpanningTableRow(
          repeat: repeatHeaderRows,
          decoration: headerDecoration,
          children: <SpanningTableCell>[
            for (var index = 0; index < headers.length; index++)
              buildCell(
                cell: headers[index],
                index: index,
                rowNum: rowNum,
                header: true,
                odd: false,
              ),
          ],
        ),
      );
      rowNum++;
    }

    for (final row in data) {
      final isHeader = rowNum < headerCount;
      final isOdd = (rowNum - headerCount) % 2 != 0;
      rows.add(
        SpanningTableRow(
          repeat: repeatHeaderRows && isHeader,
          decoration: isHeader
              ? headerDecoration
              : isOdd
                  ? oddRowDecoration
                  : rowDecoration,
          children: <SpanningTableCell>[
            for (var index = 0; index < row.length; index++)
              buildCell(
                cell: row[index],
                index: index,
                rowNum: rowNum,
                header: isHeader,
                odd: isOdd,
              ),
          ],
        ),
      );
      rowNum++;
    }

    return SpanningTable(
      border: border,
      tableWidth: tableWidth,
      children: rows,
      columnWidths: columnWidths,
      defaultColumnWidth: defaultColumnWidth,
      defaultVerticalAlignment: defaultVerticalAlignment,
      overflow: overflow,
      textDirection: textDirection,
    );
  }

  final List<SpanningTableRow> children;
  final TableBorder? border;
  final TableCellVerticalAlignment defaultVerticalAlignment;
  final AlignmentGeometry defaultCellAlignment;
  final TableColumnWidth defaultColumnWidth;
  final Map<int, TableColumnWidth>? columnWidths;
  final TableWidth tableWidth;
  final SpanningTableOverflowMode overflow;
  final TextDirection? textDirection;

  final SpanningTableContext _context = SpanningTableContext();
  _ResolvedLayout? _layout;
  _VisibleLayout? _visible;
  _ResolvedLayout? _cachedLayout;
  double? _cachedMaxWidth;
  bool? _cachedHasBoundedWidth;
  TextDirection? _cachedTextDirection;

  @override
  bool get canSpan => true;

  @override
  bool get hasMoreWidgets => _context.lastRow < children.length;

  @override
  WidgetContext saveContext() => _context;

  @override
  void restoreContext(SpanningTableContext context) {
    _context.apply(context);
    _context.firstRow = _context.lastRow;
    _context.retryDeferredRow = _context.deferredRow != null;
  }

  @override
  void layout(Context context, BoxConstraints constraints,
      {bool parentUsesSize = false}) {
    _validateStructure();

    if (children.isEmpty) {
      _context.lastRow = _context.firstRow;
      _layout = null;
      _visible = null;
      box = PdfRect.fromPoints(PdfPoint.zero, constraints.smallest);
      return;
    }

    final resolved = _resolveCachedLayout(context, constraints);
    _validateResolvedLayout(resolved);
    _layout = resolved;
    final visible = _resolveVisibleRows(resolved, constraints);
    _visible = visible;
    _context.lastRow = visible.nextRow;

    _positionVisibleChildren(context, resolved, visible);

    final width = resolved.widths.fold(0.0, (sum, width) => sum + width);
    box = constraints.constrainRect(width: width, height: visible.totalHeight);
  }

  @override
  void paint(Context context) {
    super.paint(context);

    final resolved = _layout;
    final visible = _visible;
    if (resolved == null || visible == null || visible.rows.isEmpty) {
      return;
    }

    final mat = Matrix4.identity();
    mat.translateByDouble(box!.left, box!.bottom, 0, 1);
    context.canvas
      ..saveContext()
      ..setTransform(mat)
      ..drawRect(0, 0, box!.width, visible.totalHeight)
      ..clipPath();

    _paintRows(context, resolved, visible, PaintPhase.background);
    _paintCells(context, resolved, visible);
    _paintRows(context, resolved, visible, PaintPhase.foreground);
    if (border != null) {
      _paintBorder(context, resolved, visible);
    }

    context.canvas.restoreContext();
  }

  static TextAlign _textAlign(Alignment align) {
    if (align.x == 0) {
      return TextAlign.center;
    } else if (align.x < 0) {
      return TextAlign.left;
    } else {
      return TextAlign.right;
    }
  }

  TextDirection _textDirection(Context context) =>
      textDirection ?? Directionality.of(context);

  _ResolvedLayout _resolveCachedLayout(
    Context context,
    BoxConstraints constraints,
  ) {
    final direction = _textDirection(context);
    if (_cachedLayout != null &&
        _cachedMaxWidth == constraints.maxWidth &&
        _cachedHasBoundedWidth == constraints.hasBoundedWidth &&
        _cachedTextDirection == direction) {
      return _cachedLayout!;
    }

    final resolved = _resolveLayout(context, constraints);
    _cachedLayout = resolved;
    _cachedMaxWidth = constraints.maxWidth;
    _cachedHasBoundedWidth = constraints.hasBoundedWidth;
    _cachedTextDirection = direction;
    return resolved;
  }

  _ResolvedLayout _resolveLayout(Context context, BoxConstraints constraints) {
    final placements = <_TablePlacement>[];
    final occupancy = <List<int?>>[];
    var columnCount = 0;

    for (var row = 0; row < children.length; row++) {
      while (occupancy.length <= row) {
        occupancy.add(<int?>[]);
      }
      var column = 0;
      for (final cell in children[row].children) {
        while (_slotAt(occupancy, row, column) != null) {
          column++;
        }
        final rowSpan = _effectiveRowSpan(row, cell);
        final placement = _TablePlacement(
          cell: cell,
          row: row,
          column: column,
          rowSpan: rowSpan,
          columnSpan: cell.columnSpan,
        );
        final index = placements.length;
        placements.add(placement);
        for (var r = row; r < row + rowSpan; r++) {
          while (occupancy.length <= r) {
            occupancy.add(<int?>[]);
          }
          while (occupancy[r].length < column + cell.columnSpan) {
            occupancy[r].add(null);
          }
          for (var c = column; c < column + cell.columnSpan; c++) {
            occupancy[r][c] = index;
          }
        }
        column += cell.columnSpan;
        columnCount = math.max(columnCount, column);
      }
    }

    for (final row in occupancy) {
      while (row.length < columnCount) {
        row.add(null);
      }
    }

    final widths = _resolveColumnWidths(
      context,
      constraints,
      placements,
      columnCount,
    );
    final heights = _resolveRowHeights(context, placements, widths);

    return _ResolvedLayout(
      widths: widths,
      heights: heights,
      placements: placements,
      occupancy: occupancy,
    );
  }

  List<double> _resolveColumnWidths(
    Context context,
    BoxConstraints constraints,
    List<_TablePlacement> placements,
    int columnCount,
  ) {
    final widths = List<double>.filled(columnCount, 0);
    final flex = List<double>.filled(columnCount, 0);

    for (var column = 0; column < columnCount; column++) {
      final columnWidth = columnWidths?[column] ?? defaultColumnWidth;
      final placement = placements.cast<_TablePlacement?>().firstWhere(
            (placement) =>
                placement!.column == column && placement.columnSpan == 1,
            orElse: () => null,
          );
      final child = placement?.cell.child ?? SizedBox.shrink();
      final layout = columnWidth.layout(child, context, constraints);
      widths[column] = math.max(widths[column], layout.width);
      flex[column] = math.max(flex[column], layout.flex);
    }

    for (final placement in placements) {
      if (placement.columnSpan == 1) {
        continue;
      }
      placement.cell.child.layout(context, const BoxConstraints());
      final padding = placement.cell.padding.resolve(_textDirection(context));
      final width = placement.cell.child.box!.width + padding.horizontal;
      final current = _sum(widths, placement.column, placement.columnSpan);
      if (width > current) {
        final extra = (width - current) / placement.columnSpan;
        for (var column = placement.column;
            column < placement.column + placement.columnSpan;
            column++) {
          widths[column] += extra;
        }
      }
    }

    final intrinsicWidth = widths.fold(0.0, (sum, width) => sum + width);
    if (constraints.hasBoundedWidth && columnCount > 0) {
      final totalFlex = flex.fold(0.0, (sum, value) => sum + value);
      var fixedSpace = 0.0;
      for (var column = 0; column < widths.length; column++) {
        if (flex[column] == 0) {
          final scaledWidth = intrinsicWidth == 0
              ? constraints.maxWidth / widths.length
              : widths[column] / intrinsicWidth * constraints.maxWidth;
          if ((tableWidth == TableWidth.max && totalFlex == 0) ||
              scaledWidth < widths[column]) {
            widths[column] = scaledWidth;
          }
          fixedSpace += widths[column];
        }
      }

      if (totalFlex > 0) {
        final spacePerFlex = (constraints.maxWidth - fixedSpace) / totalFlex;
        for (var column = 0; column < widths.length; column++) {
          if (flex[column] > 0) {
            widths[column] = math.max(0.0, spacePerFlex * flex[column]);
          }
        }
      }
    }

    return widths;
  }

  List<double> _resolveRowHeights(
    Context context,
    List<_TablePlacement> placements,
    List<double> widths,
  ) {
    final heights = List<double>.filled(children.length, 0);
    final pending = <_TablePlacement>[];

    for (final placement in placements) {
      final height = _layoutPlacement(context, placement, widths);
      if (placement.rowSpan == 1) {
        heights[placement.row] = math.max(heights[placement.row], height);
      } else {
        pending.add(placement);
      }
    }

    for (final placement in pending) {
      final height = placement.rect!.height;
      final current = _sum(heights, placement.row, placement.rowSpan);
      if (height > current) {
        final extra = (height - current) / placement.rowSpan;
        for (var row = placement.row;
            row < placement.row + placement.rowSpan;
            row++) {
          heights[row] += extra;
        }
      }
    }

    return heights;
  }

  double _layoutPlacement(
    Context context,
    _TablePlacement placement,
    List<double> widths,
  ) {
    final padding = placement.cell.padding.resolve(_textDirection(context));
    final width = _sum(widths, placement.column, placement.columnSpan);
    final childWidth = math.max(0.0, width - padding.horizontal);
    placement.cell.child.layout(
      context,
      BoxConstraints(maxWidth: childWidth),
      parentUsesSize: false,
    );
    final height = placement.cell.child.box!.height + padding.vertical;
    placement.rect = PdfRect(0, 0, width, height);
    return height;
  }

  _VisibleLayout _resolveVisibleRows(
    _ResolvedLayout layout,
    BoxConstraints constraints,
  ) {
    final rows = <int>[];
    var totalHeight = 0.0;
    final maxHeight =
        constraints.hasBoundedHeight ? constraints.maxHeight : double.infinity;

    for (var row = 0; row < children.length; row++) {
      if (children[row].repeat) {
        rows.add(row);
        totalHeight += layout.heights[row];
      }
    }

    var row = _context.firstRow;
    while (row < children.length && children[row].repeat) {
      row++;
    }

    if (constraints.hasBoundedHeight) {
      if (row >= children.length) {
        if (overflow == SpanningTableOverflowMode.strict) {
          throw SpanningTableException(
            'SpanningTable cannot paginate because no non-repeat rows remain. '
            'Repeated rows are headers and must be followed by at least one body row.',
          );
        }

        return _VisibleLayout(
          rows: rows,
          rowBottoms: _resolveRowBottoms(layout, rows, totalHeight),
          totalHeight: math.min(totalHeight, maxHeight),
          nextRow: children.length,
        );
      }

      final end = _rowGroupEnd(layout.placements, row);
      final groupHeight = _sum(layout.heights, row, end - row);
      final requiredHeight = totalHeight + groupHeight;
      if (requiredHeight > maxHeight) {
        final message = 'SpanningTable row group $row..${end - 1} is taller '
            'than the available page height. Required height: '
            '${requiredHeight.toStringAsFixed(2)}, available height: '
            '${maxHeight.toStringAsFixed(2)}, repeated rows height: '
            '${totalHeight.toStringAsFixed(2)}. Split the cell content, '
            'reduce padding/font size, increase the page height, or render '
            'that content outside this table.';

        if (_context.deferredRow == row && _context.retryDeferredRow) {
          if (overflow == SpanningTableOverflowMode.clip) {
            _context.deferredRow = null;
            _context.retryDeferredRow = false;
            for (var r = row; r < end; r++) {
              rows.add(r);
            }
            final clippedHeight = math.min(requiredHeight, maxHeight);
            return _VisibleLayout(
              rows: rows,
              rowBottoms: _resolveRowBottoms(layout, rows, clippedHeight),
              totalHeight: clippedHeight,
              nextRow: end,
            );
          }

          throw SpanningTableException(message);
        }

        _context.deferredRow = row;
        _context.retryDeferredRow = false;
        return _VisibleLayout(
          rows: const <int>[],
          rowBottoms: const <int, double>{},
          totalHeight: 0,
          nextRow: _context.firstRow,
        );
      }
    }

    _context.deferredRow = null;
    _context.retryDeferredRow = false;

    var hasBodyRow = false;
    while (row < children.length) {
      if (children[row].repeat) {
        row++;
        continue;
      }

      final end = _rowGroupEnd(layout.placements, row);
      final groupHeight = _sum(layout.heights, row, end - row);
      if (hasBodyRow && totalHeight + groupHeight > maxHeight) {
        break;
      }
      for (var r = row; r < end; r++) {
        rows.add(r);
      }
      totalHeight += groupHeight;
      hasBodyRow = true;
      row = end;
      if (totalHeight >= maxHeight) {
        break;
      }
    }

    return _VisibleLayout(
      rows: rows,
      rowBottoms: _resolveRowBottoms(layout, rows, totalHeight),
      totalHeight: totalHeight,
      nextRow: row,
    );
  }

  Map<int, double> _resolveRowBottoms(
    _ResolvedLayout layout,
    List<int> rows,
    double totalHeight,
  ) {
    final rowBottoms = <int, double>{};
    var top = totalHeight;
    for (final row in rows) {
      top -= layout.heights[row];
      rowBottoms[row] = top;
    }
    return rowBottoms;
  }

  int _effectiveRowSpan(int row, SpanningTableCell cell) {
    if (overflow == SpanningTableOverflowMode.strict) {
      return cell.rowSpan;
    }

    if (children[row].repeat) {
      return 1;
    }

    var rowSpan = math.min(cell.rowSpan, children.length - row);
    for (var r = row + 1; r < row + rowSpan; r++) {
      if (children[r].repeat) {
        rowSpan = r - row;
        break;
      }
    }
    return math.max(1, rowSpan);
  }

  int _rowGroupEnd(List<_TablePlacement> placements, int start) {
    var end = start + 1;
    var changed = true;
    while (changed) {
      changed = false;
      for (final placement in placements) {
        final placementEnd = placement.row + placement.rowSpan;
        final startsInGroup = placement.row >= start && placement.row < end;
        final crossesGroup = placement.row < end && placementEnd > end;
        if ((startsInGroup || crossesGroup) && placementEnd > end) {
          end = placementEnd;
          changed = true;
        }
      }
    }
    return math.min(end, children.length);
  }

  void _validateStructure() {
    var hasRepeatRows = false;
    var hasBodyRows = false;

    for (var row = 0; row < children.length; row++) {
      final tableRow = children[row];
      if (tableRow.repeat) {
        hasRepeatRows = true;
      } else {
        hasBodyRows = true;
      }

      for (final cell in tableRow.children) {
        if (overflow == SpanningTableOverflowMode.strict &&
            cell.rowSpan > children.length - row) {
          throw SpanningTableException(
            'SpanningTable cell at row $row has rowSpan ${cell.rowSpan}, '
            'but only ${children.length - row} row(s) are available.',
          );
        }

        if (overflow == SpanningTableOverflowMode.strict &&
            tableRow.repeat &&
            cell.rowSpan > 1) {
          throw SpanningTableException(
            'SpanningTable repeat row $row cannot contain rowSpan '
            '${cell.rowSpan}. Repeated rows are rendered on each page and '
            'must not span into other rows.',
          );
        }
      }
    }

    if (overflow == SpanningTableOverflowMode.strict &&
        hasRepeatRows &&
        !hasBodyRows) {
      throw SpanningTableException(
        'SpanningTable cannot contain only repeat rows. Repeated rows are '
        'headers and must be followed by at least one body row.',
      );
    }
  }

  void _validateResolvedLayout(_ResolvedLayout layout) {
    for (final placement in layout.placements) {
      if (placement.rowSpan == 1) {
        continue;
      }

      for (var row = placement.row + 1;
          row < placement.row + placement.rowSpan;
          row++) {
        if (overflow == SpanningTableOverflowMode.strict &&
            children[row].repeat) {
          throw SpanningTableException(
            'SpanningTable cell at row ${placement.row}, column '
            '${placement.column} spans into repeat row $row. Row spans '
            'must not cross repeated header rows.',
          );
        }
      }
    }
  }

  void _positionVisibleChildren(
    Context context,
    _ResolvedLayout layout,
    _VisibleLayout visible,
  ) {
    final visibleRows = visible.rows.toSet();
    for (final placement in layout.placements) {
      if (!_placementVisible(placement, visibleRows)) {
        continue;
      }
      final padding = placement.cell.padding.resolve(_textDirection(context));
      final left = _sum(layout.widths, 0, placement.column);
      final bottom = visible.rowBottoms[placement.row + placement.rowSpan - 1]!;
      final width = _sum(layout.widths, placement.column, placement.columnSpan);
      final height = _sum(layout.heights, placement.row, placement.rowSpan);
      placement.rect = PdfRect(left, bottom, width, height);

      final content = PdfRect(
        left + padding.left,
        bottom + padding.bottom,
        math.max(0.0, width - padding.horizontal),
        math.max(0.0, height - padding.vertical),
      );
      final verticalAlignment = placement.cell.verticalAlignment ??
          children[placement.row].verticalAlignment ??
          defaultVerticalAlignment;
      if (verticalAlignment == TableCellVerticalAlignment.full) {
        placement.cell.child.layout(
          context,
          BoxConstraints.tightFor(width: content.width, height: content.height),
          parentUsesSize: false,
        );
      }
      final baseAlignment = (placement.cell.alignment ?? defaultCellAlignment)
          .resolve(_textDirection(context));
      final alignment = Alignment(
        baseAlignment.x,
        _verticalAlignmentY(verticalAlignment),
      );
      placement.cell.child.box = alignment.inscribe(
        placement.cell.child.box!.size,
        content,
      );
    }
  }

  void _paintRows(
    Context context,
    _ResolvedLayout layout,
    _VisibleLayout visible,
    PaintPhase phase,
  ) {
    for (final row in visible.rows) {
      final decoration = children[row].decoration;
      if (decoration == null) {
        continue;
      }
      decoration.paint(
        context,
        PdfRect(0, visible.rowBottoms[row]!, box!.width, layout.heights[row]),
        phase,
      );
    }
  }

  void _paintCells(
    Context context,
    _ResolvedLayout layout,
    _VisibleLayout visible,
  ) {
    final visibleRows = visible.rows.toSet();
    for (final placement in layout.placements) {
      if (!_placementVisible(placement, visibleRows)) {
        continue;
      }
      final rect = placement.rect!;
      placement.cell.decoration?.paint(context, rect, PaintPhase.background);
      context.canvas
        ..saveContext()
        ..drawRect(rect.left, rect.bottom, rect.width, rect.height)
        ..clipPath();
      placement.cell.child.paint(context);
      context.canvas.restoreContext();
      placement.cell.decoration?.paint(context, rect, PaintPhase.foreground);
    }
  }

  void _paintBorder(
    Context context,
    _ResolvedLayout layout,
    _VisibleLayout visible,
  ) {
    final visibleRows = visible.rows;
    final columnOffsets = <double>[0];
    for (final width in layout.widths) {
      columnOffsets.add(columnOffsets.last + width);
    }

    for (var column = 0; column <= layout.widths.length; column++) {
      final side = column == 0
          ? border!.left
          : column == layout.widths.length
              ? border!.right
              : border!.verticalInside;
      if (!side.style.paint) {
        continue;
      }
      final x = columnOffsets[column];
      var segmentStart = -1;
      for (var index = 0; index < visibleRows.length; index++) {
        final row = visibleRows[index];
        final leftId =
            column == 0 ? null : _slotAt(layout.occupancy, row, column - 1);
        final rightId = column == layout.widths.length
            ? null
            : _slotAt(layout.occupancy, row, column);
        final draw = leftId != rightId;
        if (draw && segmentStart < 0) {
          segmentStart = index;
        } else if (!draw && segmentStart >= 0) {
          _drawVerticalBorder(
              context, side, x, visibleRows, visible, segmentStart, index - 1);
          segmentStart = -1;
        }
      }
      if (segmentStart >= 0) {
        _drawVerticalBorder(context, side, x, visibleRows, visible,
            segmentStart, visibleRows.length - 1);
      }
    }

    for (var index = 0; index <= visibleRows.length; index++) {
      final topBoundary = index == 0;
      final bottomBoundary = index == visibleRows.length;
      final side = topBoundary
          ? border!.top
          : bottomBoundary
              ? border!.bottom
              : border!.horizontalInside;
      if (!side.style.paint) {
        continue;
      }
      final y = topBoundary
          ? visible.totalHeight
          : visible.rowBottoms[visibleRows[index - 1]]!;
      var segmentStart = -1;
      for (var column = 0; column < layout.widths.length; column++) {
        final upRow = topBoundary ? null : visibleRows[index - 1];
        final downRow = bottomBoundary ? null : visibleRows[index];
        final upId =
            upRow == null ? null : _slotAt(layout.occupancy, upRow, column);
        final downId =
            downRow == null ? null : _slotAt(layout.occupancy, downRow, column);
        final draw = upId != downId;
        if (draw && segmentStart < 0) {
          segmentStart = column;
        } else if (!draw && segmentStart >= 0) {
          _drawHorizontalBorder(context, side, y, columnOffsets[segmentStart],
              columnOffsets[column]);
          segmentStart = -1;
        }
      }
      if (segmentStart >= 0) {
        _drawHorizontalBorder(
            context, side, y, columnOffsets[segmentStart], columnOffsets.last);
      }
    }
  }

  void _drawVerticalBorder(
    Context context,
    BorderSide side,
    double x,
    List<int> rows,
    _VisibleLayout visible,
    int startIndex,
    int endIndex,
  ) {
    final bottom = visible.rowBottoms[rows[endIndex]]!;
    final top = visible.rowBottoms[rows[startIndex]]! +
        (_layout?.heights[rows[startIndex]] ?? 0);
    _drawLine(context, side, x, bottom, x, top);
  }

  void _drawHorizontalBorder(
    Context context,
    BorderSide side,
    double y,
    double left,
    double right,
  ) {
    _drawLine(context, side, left, y, right, y);
  }

  void _drawLine(
    Context context,
    BorderSide side,
    double x1,
    double y1,
    double x2,
    double y2,
  ) {
    side.style.setStyle(context);
    context.canvas
      ..setStrokeColor(side.color)
      ..setLineWidth(side.width)
      ..moveTo(x1, y1)
      ..lineTo(x2, y2)
      ..strokePath();
    side.style.unsetStyle(context);
  }

  bool _placementVisible(_TablePlacement placement, Set<int> visibleRows) {
    for (var row = placement.row;
        row < placement.row + placement.rowSpan;
        row++) {
      if (!visibleRows.contains(row)) {
        return false;
      }
    }
    return true;
  }

  int? _slotAt(List<List<int?>> occupancy, int row, int column) {
    if (row < 0 || row >= occupancy.length) {
      return null;
    }
    if (column < 0 || column >= occupancy[row].length) {
      return null;
    }
    return occupancy[row][column];
  }

  double _verticalAlignmentY(TableCellVerticalAlignment alignment) {
    switch (alignment) {
      case TableCellVerticalAlignment.bottom:
        return -1;
      case TableCellVerticalAlignment.middle:
        return 0;
      case TableCellVerticalAlignment.top:
      case TableCellVerticalAlignment.full:
        return 1;
    }
  }

  double _sum(List<double> values, int start, int count) {
    var total = 0.0;
    for (var index = start;
        index < start + count && index < values.length;
        index++) {
      total += values[index];
    }
    return total;
  }
}
