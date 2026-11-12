package com.example.mobitive.scan;

import android.app.ActivityManager;
import android.content.Context;
import android.net.Uri;
import android.os.PowerManager;
import android.util.Log;

import com.example.mobitive.analyzer.ApkAnalyzer;
import com.example.mobitive.benchmark.ScanBenchmark;
import com.example.mobitive.cache.AnalysisCache;
import com.example.mobitive.ml.ModelCatalog;
import com.example.mobitive.ml.MalwareClassifier;
import com.example.mobitive.utils.FileUtils;

import java.io.File;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * The complete scan flow (copy+hash → cache → manifest/DEX → vector → TFLite),
 * shared by the UI (MainActivity) and the automated device benchmark
 * (androidTest/DeviceScanBenchmark), so both measure exactly the same code.
 *
 * Not thread-safe: call {@link #scan} and {@link #close} from one worker thread.
 */
public final class ScanPipeline implements AutoCloseable {

    private static final String TAG = "MobiTive";

    /** Everything a caller needs after one scan. {@code error == null} means success. */
    public static final class Outcome {
        public final ScanBenchmark benchmark;
        public final ApkAnalyzer.AnalysisResult analysis;
        public final MalwareClassifier.Prediction prediction;
        public final String cacheMode;
        public final String error;

        Outcome(ScanBenchmark benchmark, ApkAnalyzer.AnalysisResult analysis,
                MalwareClassifier.Prediction prediction, String cacheMode, String error) {
            this.benchmark = benchmark;
            this.analysis = analysis;
            this.prediction = prediction;
            this.cacheMode = cacheMode;
            this.error = error;
        }

        public boolean ok() { return error == null; }
    }

    private final Context context;
    private AnalysisCache analysisCache;
    private ApkAnalyzer apkAnalyzer;
    /** One interpreter per model id, created on first use and reused across scans. */
    private final Map<String, MalwareClassifier> classifiers = new HashMap<>();

    public ScanPipeline(Context context) {
        this.context = context.getApplicationContext();
    }

    public Outcome scan(Uri apkUri, String fileName, ModelCatalog.Choice choice,
                        boolean forceFullScan) {
        ScanBenchmark benchmark = new ScanBenchmark(fileName);
        benchmark.setModelInfo(choice.id, choice.threads);
        benchmark.setDeviceState(thermalStatus(), totalRamMb());

        File temporaryApk = null;
        ApkAnalyzer.AnalysisResult analysis = null;
        MalwareClassifier.Prediction prediction = null;
        String error = null;
        String apkSha = "";
        String cacheMode = forceFullScan ? "FORCED" : "MISS";
        benchmark.samplePssBefore();

        try {
            // M6: copy and SHA-256 in a single pass. "copy_apk" includes hashing;
            // "hash_apk" is intentionally left empty in the CSV.
            ScanBenchmark.Token copyTiming = benchmark.startStage();
            temporaryApk = File.createTempFile("mobitive_scan_", ".apk", context.getCacheDir());
            FileUtils.CopyResult copied;
            try (InputStream input = context.getContentResolver().openInputStream(apkUri)) {
                copied = FileUtils.copyWithSha256(input, temporaryApk);
            }
            benchmark.endStage("copy_apk", copyTiming);
            benchmark.setApkBytes(copied.bytes);
            apkSha = copied.sha256;

            if (analysisCache == null) {
                analysisCache = new AnalysisCache(context);
            }

            if (!forceFullScan) {
                ScanBenchmark.Token readTiming = benchmark.startStage();
                analysis = analysisCache.load(apkSha);
                benchmark.endStage("cache_read", readTiming);
                if (analysis != null) cacheMode = "HIT";
            }
            benchmark.setCacheInfo(cacheMode, apkSha);

            if (analysis == null) {
                if (apkAnalyzer == null) {
                    ScanBenchmark.Token initAnalyzerTiming = benchmark.startStage();
                    apkAnalyzer = new ApkAnalyzer(context);
                    benchmark.endStage("init_analyzer", initAnalyzerTiming);
                }
                analysis = apkAnalyzer.analyze(temporaryApk, benchmark);
            }
            benchmark.samplePssAfterAnalysis();
            benchmark.setVectorHash(analysis.getFeatureVector());

            MalwareClassifier classifier = classifiers.get(choice.id);
            if (classifier == null) {
                ScanBenchmark.Token initTiming = benchmark.startStage();
                classifier = new MalwareClassifier(context, choice);
                benchmark.endStage("init_model", initTiming);
                classifiers.put(choice.id, classifier);
            }
            ScanBenchmark.Token inferenceTiming = benchmark.startStage();
            prediction = classifier.predict(analysis.getFeatureVector());
            benchmark.endStage("inference", inferenceTiming);

            // Only cache successfully classified analyses; failures here
            // never invalidate an otherwise correct scan result.
            if (!"HIT".equals(cacheMode)) {
                ScanBenchmark.Token writeTiming = benchmark.startStage();
                try {
                    analysisCache.save(apkSha, analysis);
                } catch (Exception cacheError) {
                    Log.w(TAG, "M3 cache write skipped", cacheError);
                } finally {
                    benchmark.endStage("cache_write", writeTiming);
                }
            }
        } catch (Exception e) {
            error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Log.e(TAG, "APK scan failed", e);
        } finally {
            if (temporaryApk != null && temporaryApk.exists() && !temporaryApk.delete()) {
                Log.w(TAG, "Could not delete temporary APK");
            }
            benchmark.setCacheInfo(cacheMode, apkSha);
            benchmark.samplePssAfter();
            benchmark.finish(error == null ? "OK" : "ERROR", error);
        }
        return new Outcome(benchmark, analysis, prediction, cacheMode, error);
    }

    private int thermalStatus() {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        return pm == null ? -1 : pm.getCurrentThermalStatus();
    }

    private long totalRamMb() {
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (am == null) return -1;
        ActivityManager.MemoryInfo info = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(info);
        return info.totalMem / (1024 * 1024);
    }

    @Override
    public void close() {
        for (MalwareClassifier classifier : classifiers.values()) {
            classifier.close();
        }
        classifiers.clear();
    }
}
