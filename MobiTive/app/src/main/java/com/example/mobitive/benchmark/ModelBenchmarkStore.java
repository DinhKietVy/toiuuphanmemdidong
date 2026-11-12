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

/** Separate M2 inference CSV; never mixes results with M0/M1 scan timings. */
public final class ModelBenchmarkStore {
    public static final String FILE_NAME = "mobitive_ai_benchmarks.csv";

    private ModelBenchmarkStore() { }

    private static File file(Context context) {
        return new File(context.getFilesDir(), FILE_NAME);
    }

    public static boolean hasData(Context context) {
        File file = file(context);
        return file.exists() && file.length() > 0;
    }

    public static synchronized void append(Context context, ModelBenchmark.Result result)
            throws IOException {
        File file = file(context);
        boolean first = !file.exists() || file.length() == 0;
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(file, true), StandardCharsets.UTF_8))) {
            if (first) {
                writer.write(ModelBenchmark.HEADER);
                writer.newLine();
            }
            for (String row : result.csvRows) {
                writer.write(row);
                writer.newLine();
            }
        }
    }

    public static void export(Context context, ContentResolver resolver, Uri destination)
            throws IOException {
        File source = file(context);
        if (!source.exists()) throw new IOException("Chưa có AI benchmark. Hãy chạy AI Benchmark trước.");
        try (FileInputStream input = new FileInputStream(source);
             OutputStream output = resolver.openOutputStream(destination, "wt")) {
            if (output == null) throw new IOException("Không ghi được CSV");
            byte[] buffer = new byte[8192];
            int n;
            while ((n = input.read(buffer)) != -1) output.write(buffer, 0, n);
            output.flush();
        }
    }
}
