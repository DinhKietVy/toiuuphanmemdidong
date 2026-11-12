package com.example.mobitive.benchmark;

import android.os.Build;
import android.os.Debug;
import android.os.SystemClock;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Measures wall-clock and worker-thread CPU time per scan stage.
 * PSS readings are snapshots, not peak memory measurements.
 */
public final class ScanBenchmark {

    private static final String[] STAGES = {
            "copy_apk", "hash_apk", "cache_read", "cache_write", "init_analyzer", "manifest", "dex",
            "feature_lookup", "vectorize", "init_model", "inference", "total"
    };

    private final long startedEpochMs = System.currentTimeMillis();
    private final long startedWallNs = SystemClock.elapsedRealtimeNanos();
    private final long startedCpuNs = Debug.threadCpuTimeNanos();
    private final String apkName;

    private final Map<String, Double> wallMs = new LinkedHashMap<>();
    private final Map<String, Double> threadCpuMs = new LinkedHashMap<>();

    private String cacheMode = "NONE";
    private String apkSha256 = "";
    private long pssAfterAnalysisKb = -1;
    private String m4ModelId = "gru128_fp32";
    private int m4Threads = 4;
    private long apkBytes;
    private String vectorSha256 = "";
    private String vectorBits = "";
    private long pssStartKb = -1;
    private long pssEndKb = -1;
    private String status = "IN_PROGRESS";
    private String error = "";

    public ScanBenchmark(String apkName) {
        this.apkName = apkName == null ? "unknown.apk" : apkName;
    }

    public Token startStage() {
        return new Token(SystemClock.elapsedRealtimeNanos(), Debug.threadCpuTimeNanos());
    }

    public void endStage(String name, Token token) {
        if (token == null) {
            return;
        }
        long wall = SystemClock.elapsedRealtimeNanos() - token.wallNs;
        long cpu = Debug.threadCpuTimeNanos() - token.cpuNs;
        wallMs.put(name, wall / 1_000_000.0);
        threadCpuMs.put(name, cpu / 1_000_000.0);
    }

    /** Hash little-endian float32 raw bytes to compare Python/Android vectors. */
    public void setVectorHash(float[] vector) {
        if (vector == null) return;
        ByteBuffer bytes = ByteBuffer.allocate(vector.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        StringBuilder bits = new StringBuilder(vector.length);
        for (float feature : vector) {
            bytes.putFloat(feature);
            bits.append(feature == 0.0f ? '0' : feature == 1.0f ? '1' : '?');
        }
        vectorBits = bits.toString();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes.array());
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                hex.append(String.format(Locale.US, "%02x", value & 0xff));
            }
            vectorSha256 = hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Missing SHA-256", e);
        }
    }

    public void samplePssBefore() {
        pssStartKb = Debug.getPss();
    }

    public void samplePssAfter() {
        pssEndKb = Debug.getPss();
    }

    public void setCacheInfo(String mode, String sha) {
        cacheMode = mode == null ? "NONE" : mode;
        apkSha256 = sha == null ? "" : sha;
    }

    public void samplePssAfterAnalysis() {
        pssAfterAnalysisKb = Debug.getPss();
    }

    public void setModelInfo(String modelId, int threads) {
        if (modelId == null || !modelId.matches("[a-zA-Z0-9_]+")) {
            throw new IllegalArgumentException("Invalid model id");
        }
        m4ModelId = modelId;
        m4Threads = threads;
    }

    public double m4TotalWallMs() { return getWallMs("total"); }

    public void setApkBytes(long apkBytes) {
        this.apkBytes = apkBytes;
    }

    public void finish(String status, String error) {
        if (wallMs.containsKey("total")) {
            return;
        }
        this.status = status;
        this.error = error == null ? "" : error;
        wallMs.put("total", (SystemClock.elapsedRealtimeNanos() - startedWallNs) / 1_000_000.0);
        threadCpuMs.put("total", (Debug.threadCpuTimeNanos() - startedCpuNs) / 1_000_000.0);
    }

    public String readableSummary() {
        return String.format(Locale.US,
                "\n\nM3 SCAN BENCHMARK (wall-clock)\n" +
                "Cache mode: %s (HIT = same APK+dictionary; FORCED = full scan)\n" +
                "Total: %.1f ms; Copy+SHA-256 (1 pass): %.1f ms\n" +
                "Cache read: %.1f ms; Cache write: %.1f ms\n" +
                "Manifest: %.1f ms; DEX: %.1f ms; Inference: %.3f ms\n" +
                "PSS start/after analysis/end: %d / %d / %d KB\n" +
                "(PSS snapshots are NOT peak RAM)",
                cacheMode, getWallMs("total"), getWallMs("copy_apk"),
                getWallMs("cache_read"),
                getWallMs("cache_write"), getWallMs("manifest"),
                getWallMs("dex"), getWallMs("inference"),
                pssStartKb, pssAfterAnalysisKb, pssEndKb);
    }

    private double getWallMs(String stage) {
        Double value = wallMs.get(stage);
        return value == null ? 0.0 : value;
    }

    private String formatDuration(Map<String, Double> durations, String stage) {
        Double value = durations.get(stage);
        return value == null ? "" : String.format(Locale.US, "%.3f", value);
    }

    public static String csvHeader() {
        StringBuilder builder = new StringBuilder(
                "epoch_ms,device,android_sdk,model_id,threads,apk_name,status,error,apk_bytes,vector_sha256,vector_bits,pss_start_kb,pss_end_kb");
        for (String stage : STAGES) {
            builder.append(',').append(stage).append("_wall_ms");
            builder.append(',').append(stage).append("_thread_cpu_ms");
        }
        builder.append(",cache_mode,apk_sha256,pss_after_analysis_kb");
        return builder.toString();
    }

    public String csvRow() {
        StringBuilder builder = new StringBuilder();
        builder.append(startedEpochMs).append(',');
        builder.append(quote(Build.MANUFACTURER + " " + Build.MODEL)).append(',');
        builder.append(Build.VERSION.SDK_INT).append(',');
        builder.append(quote(m4ModelId)).append(',');
        builder.append(m4Threads).append(',');
        builder.append(quote(apkName)).append(',');
        builder.append(quote(status)).append(',');
        builder.append(quote(error)).append(',');
        builder.append(apkBytes).append(',');
        builder.append(quote(vectorSha256)).append(',');
        builder.append(quote(vectorBits)).append(',');
        builder.append(pssStartKb).append(',').append(pssEndKb);
        for (String stage : STAGES) {
            builder.append(',').append(formatDuration(wallMs, stage));
            builder.append(',').append(formatDuration(threadCpuMs, stage));
        }
        builder.append(',').append(quote(cacheMode));
        builder.append(',').append(quote(apkSha256));
        builder.append(',').append(pssAfterAnalysisKb);
        return builder.toString();
    }

    private static String quote(String input) {
        String safe = input == null ? "" : input;
        // Prevent formula execution when a CSV is opened in spreadsheet software.
        if (!safe.isEmpty() && "=+-@".indexOf(safe.charAt(0)) >= 0) {
            safe = "'" + safe;
        }
        return '"' + safe.replace("\"", "\"\"") + '"';
    }

    public static final class Token {
        private final long wallNs;
        private final long cpuNs;

        private Token(long wallNs, long cpuNs) {
            this.wallNs = wallNs;
            this.cpuNs = cpuNs;
        }
    }
}
