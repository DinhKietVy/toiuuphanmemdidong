package com.example.mobitive;

import android.app.ActivityManager;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.example.mobitive.benchmark.BenchmarkStore;
import com.example.mobitive.benchmark.ModelBenchmark;
import com.example.mobitive.benchmark.ScanBenchmark;
import com.example.mobitive.ml.ModelCatalog;
import com.example.mobitive.scan.ScanPipeline;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * M7 automated on-device benchmark (mục 3): scans every APK in
 * {@code /sdcard/Android/data/com.example.mobitive/files/bench/} with the exact
 * production pipeline and writes CSVs to {@code .../files/results/}.
 *
 * Driven by MobiTive/tools/run_device_benchmark.py. Arguments (-e key value):
 *   repeats      FORCED (full) scans per APK, interleaved across APKs   [5]
 *   warmup       unrecorded-for-stats warm-up scans of the first APK    [1]
 *   hitRepeats   cache scans per APK after the FORCED phase (MISS/HIT)  [3]
 *   models       comma list of model ids, or "all"                      [gru128_fp32]
 *   cooldownMs   pause between scans, limits thermal drift              [1000]
 *   modelBench   also run the TFLite 5-model x 1/2/4-thread benchmark   [true]
 *   runId        label written into file names                          [epoch ms]
 *
 * Methodology: APK order is interleaved per repetition (A B C, A B C, ...)
 * so slow drift (thermal, background work) spreads across all APKs instead
 * of biasing the last ones. Warm-up rows are kept with iteration < 0.
 */
@RunWith(AndroidJUnit4.class)
public class DeviceScanBenchmark {

    private static final String TAG = "MobiTiveHarness";

    @Test
    public void scanAllBenchmarkApks() throws Exception {
        Bundle args = InstrumentationRegistry.getArguments();
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();

        int repeats = intArg(args, "repeats", 5);
        int warmup = intArg(args, "warmup", 1);
        int hitRepeats = intArg(args, "hitRepeats", 3);
        long cooldownMs = intArg(args, "cooldownMs", 1000);
        boolean modelBench = !"false".equalsIgnoreCase(args.getString("modelBench", "true"));
        String runId = args.getString("runId", String.valueOf(System.currentTimeMillis()));

        File benchDir = context.getExternalFilesDir("bench");
        File resultsDir = context.getExternalFilesDir("results");
        assertTrue("Không có external files dir", benchDir != null && resultsDir != null);

        File[] found = benchDir.listFiles((dir, name) -> name.toLowerCase(Locale.US).endsWith(".apk"));
        if (found == null || found.length == 0) {
            fail("Không có APK nào trong " + benchDir.getAbsolutePath()
                    + " — hãy chạy tools/run_device_benchmark.py để đẩy APK lên máy.");
        }
        List<File> apks = new ArrayList<>(Arrays.asList(found));
        apks.sort(Comparator.comparingLong(File::length));

        List<ModelCatalog.Choice> models = selectModels(context, args.getString("models", "gru128_fp32"));
        String device = slug(Build.MANUFACTURER + "_" + Build.MODEL);
        File scanCsv = new File(resultsDir, "scan_" + device + "_" + runId + ".csv");
        writeDeviceInfo(context, new File(resultsDir, "device_" + device + "_" + runId + ".json"));

        log(String.format(Locale.US, "device=%s apks=%d models=%d repeats=%d warmup=%d hitRepeats=%d",
                device, apks.size(), models.size(), repeats, warmup, hitRepeats));

        float[] lastVector = null;
        int failures = 0;

        try (ScanPipeline pipeline = new ScanPipeline(context)) {
            for (ModelCatalog.Choice model : models) {
                // 1) Warm-up (cold start of class loading, JIT, model init). Kept, iteration < 0.
                for (int w = 0; w < warmup; w++) {
                    failures += run(pipeline, apks.get(0), model, true, -1 - w, scanCsv, cooldownMs);
                }
                // 2) FORCED full scans, interleaved.
                for (int r = 0; r < repeats; r++) {
                    for (File apk : apks) {
                        ScanPipeline.Outcome o = scan(pipeline, apk, model, true, r);
                        failures += record(o, scanCsv, apk, model, r, cooldownMs);
                        if (o.ok()) lastVector = o.analysis.getFeatureVector();
                    }
                }
                // 3) Cache path: first non-forced scan may be MISS (LRU evicted), then HIT.
                for (File apk : apks) {
                    for (int h = 0; h < hitRepeats; h++) {
                        failures += run(pipeline, apk, model, false, h, scanCsv, cooldownMs);
                    }
                }
            }
        }

        if (modelBench && lastVector != null) {
            log("Running TFLite model benchmark (5 models x 1/2/4 threads)...");
            ModelBenchmark.Result result = ModelBenchmark.run(context, lastVector);
            File modelCsv = new File(resultsDir, "model_" + device + "_" + runId + ".csv");
            try (Writer w = new FileWriter(modelCsv)) {
                w.write(ModelBenchmark.HEADER + "\n");
                for (String row : result.csvRows) w.write(row + "\n");
            }
            log(result.summary);
        }

        log("DONE failures=" + failures + " csv=" + scanCsv.getAbsolutePath());
        assertTrue("Có " + failures + " lần quét lỗi, xem cột error trong " + scanCsv.getName(),
                failures == 0);
    }

    private static int run(ScanPipeline pipeline, File apk, ModelCatalog.Choice model,
                           boolean forced, int iteration, File csv, long cooldownMs) throws IOException {
        return record(scan(pipeline, apk, model, forced, iteration), csv, apk, model, iteration, cooldownMs);
    }

    private static ScanPipeline.Outcome scan(ScanPipeline pipeline, File apk,
                                             ModelCatalog.Choice model, boolean forced, int iteration) {
        ScanPipeline.Outcome o = pipeline.scan(Uri.fromFile(apk), apk.getName(), model, forced);
        o.benchmark.setRunInfo("harness", iteration);
        return o;
    }

    private static int record(ScanPipeline.Outcome o, File csv, File apk, ModelCatalog.Choice model,
                              int iteration, long cooldownMs) throws IOException {
        BenchmarkStore.appendTo(csv, o.benchmark);
        log(String.format(Locale.US, "%s it=%d model=%s mode=%s total=%.1fms %s",
                apk.getName(), iteration, model.id, o.cacheMode, o.benchmark.m4TotalWallMs(),
                o.ok() ? o.prediction.getLabel() : "ERROR " + o.error));
        if (cooldownMs > 0) SystemClock.sleep(cooldownMs);
        return o.ok() ? 0 : 1;
    }

    private static List<ModelCatalog.Choice> selectModels(Context context, String spec) throws IOException {
        List<ModelCatalog.Choice> installed = ModelCatalog.installed(context);
        if ("all".equalsIgnoreCase(spec)) return installed;
        List<ModelCatalog.Choice> out = new ArrayList<>();
        for (String id : spec.split(",")) {
            boolean matched = false;
            for (ModelCatalog.Choice c : installed) {
                if (c.id.equals(id.trim())) {
                    out.add(c);
                    matched = true;
                }
            }
            if (!matched) fail("Model không tồn tại: " + id + " (có: " + idsOf(installed) + ")");
        }
        return out;
    }

    private static String idsOf(List<ModelCatalog.Choice> choices) {
        StringBuilder sb = new StringBuilder();
        for (ModelCatalog.Choice c : choices) sb.append(sb.length() == 0 ? "" : ",").append(c.id);
        return sb.toString();
    }

    /** Hardware description for the report's device table (like the papers' Table I). */
    private static void writeDeviceInfo(Context context, File out) throws IOException {
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo mem = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(mem);
        int cores = Runtime.getRuntime().availableProcessors();
        StringBuilder freqs = new StringBuilder();
        for (int i = 0; i < cores; i++) {
            String khz = readFirstLine("/sys/devices/system/cpu/cpu" + i + "/cpufreq/cpuinfo_max_freq");
            freqs.append(i == 0 ? "" : ",").append(khz == null ? "null" : khz);
        }
        String soc = Build.VERSION.SDK_INT >= 31
                ? Build.SOC_MANUFACTURER + " " + Build.SOC_MODEL : Build.HARDWARE;
        String json = String.format(Locale.US,
                "{\n  \"manufacturer\": \"%s\",\n  \"model\": \"%s\",\n  \"device\": \"%s\",\n"
                        + "  \"soc\": \"%s\",\n  \"abi\": \"%s\",\n  \"android_sdk\": %d,\n"
                        + "  \"cpu_cores\": %d,\n  \"cpu_max_freq_khz\": [%s],\n"
                        + "  \"total_ram_mb\": %d,\n  \"is_emulator_hint\": %b,\n  \"app_version\": \"%s\"\n}\n",
                esc(Build.MANUFACTURER), esc(Build.MODEL), esc(Build.DEVICE), esc(soc),
                esc(Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : ""),
                Build.VERSION.SDK_INT, cores, freqs, mem.totalMem / (1024 * 1024),
                Build.FINGERPRINT.contains("generic") || Build.HARDWARE.contains("ranchu")
                        || Build.MANUFACTURER.contains("Genymobile"),
                ScanBenchmark.APP_VERSION);
        try (Writer w = new FileWriter(out)) {
            w.write(json);
        }
        log(json);
    }

    private static String readFirstLine(String path) {
        try (BufferedReader r = new BufferedReader(new FileReader(path))) {
            return r.readLine();
        } catch (IOException | SecurityException e) {
            return null;
        }
    }

    private static int intArg(Bundle args, String key, int fallback) {
        String v = args.getString(key);
        try {
            return v == null ? fallback : Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Tham số " + key + " phải là số: " + v);
        }
    }

    private static String slug(String s) {
        return s.replaceAll("[^A-Za-z0-9]+", "_");
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void log(String message) {
        Log.i(TAG, message);
        Bundle status = new Bundle();
        status.putString("stream", message + "\n");
        // Code 2 is unused by AndroidJUnitRunner (0/1/negative), so test reporters ignore it.
        InstrumentationRegistry.getInstrumentation().sendStatus(2, status);
    }
}
