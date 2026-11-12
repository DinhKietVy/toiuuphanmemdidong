package com.example.mobitive.benchmark;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/** App-private benchmark CSV, exportable through Android's document picker. */
public final class BenchmarkStore {

    public static final String FILE_NAME = "mobitive_m3_scan_benchmarks.csv";

    private BenchmarkStore() { }

    private static File localFile(Context context) {
        return new File(context.getFilesDir(), FILE_NAME);
    }

    public static boolean hasData(Context context) {
        File file = localFile(context);
        return file.exists() && file.length() > 0;
    }

    public static synchronized void append(Context context, ScanBenchmark benchmark) throws IOException {
        appendTo(localFile(context), benchmark);
    }

    /**
     * Appends one row to {@code file}. If the file was written by an older app
     * version with different columns, it is moved to "*.prev.csv" first so a
     * single CSV never mixes two header formats.
     */
    public static synchronized void appendTo(File file, ScanBenchmark benchmark) throws IOException {
        if (file.exists() && file.length() > 0 && !ScanBenchmark.csvHeader().equals(firstLine(file))) {
            File previous = new File(file.getParentFile(),
                    file.getName().replace(".csv", "") + ".prev.csv");
            if (previous.exists() && !previous.delete()) {
                throw new IOException("Không xoá được CSV cũ: " + previous.getName());
            }
            if (!file.renameTo(previous)) {
                throw new IOException("Không đổi tên được CSV cũ: " + file.getName());
            }
        }
        boolean needHeader = !file.exists() || file.length() == 0;
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(file, true), StandardCharsets.UTF_8))) {
            if (needHeader) {
                writer.write(ScanBenchmark.csvHeader());
                writer.newLine();
            }
            writer.write(benchmark.csvRow());
            writer.newLine();
        }
    }

    private static String firstLine(File file) throws IOException {
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(
                new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line = reader.readLine();
            return line == null ? "" : line;
        }
    }

    public static void export(Context context, ContentResolver resolver, Uri destination)
            throws IOException {
        File source = localFile(context);
        if (!source.exists()) {
            throw new IOException("Chưa có dữ liệu benchmark. Hãy quét một APK trước.");
        }
        try (FileInputStream input = new FileInputStream(source);
             OutputStream output = resolver.openOutputStream(destination, "wt")) {
            if (output == null) {
                throw new IOException("Không mở được file CSV đích.");
            }
            byte[] buffer = new byte[8192];
            int n;
            while ((n = input.read(buffer)) != -1) {
                output.write(buffer, 0, n);
            }
            output.flush();
        }
    }
}
