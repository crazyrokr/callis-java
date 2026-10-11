package org.reachability.analyzer.engine;

import java.util.List;

/** Fixed-width console tables: header row + data rows, two spaces between columns. */
public final class TablePrinter {

    private TablePrinter() {
    }

    public static void print(DiagnosticSink sink, String[] header, List<String[]> rows) {
        int[] widths = columnWidths(header, rows);
        String format = format(widths);
        sink.out(String.format(format, (Object[]) header));
        for (String[] row : rows) {
            sink.out(String.format(format, (Object[]) row));
        }
    }

    private static int[] columnWidths(String[] header, List<String[]> rows) {
        int[] widths = new int[header.length];
        for (int i = 0; i < header.length; i++) {
            widths[i] = header[i].length();
        }
        for (String[] row : rows) {
            for (int i = 0; i < widths.length; i++) {
                widths[i] = Math.max(widths[i], row[i].length());
            }
        }
        return widths;
    }

    /** No trailing newline: the sink's {@code out(line)} appends it (println semantics). */
    private static String format(int[] widths) {
        StringBuilder format = new StringBuilder();
        for (int width : widths) {
            format.append("%-").append(width).append("s  ");
        }
        return format.toString();
    }
}
