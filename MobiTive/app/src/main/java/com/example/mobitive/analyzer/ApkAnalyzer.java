
package com.example.mobitive.analyzer;

import android.content.Context;

import com.example.mobitive.ml.FeatureDictionary;
import com.example.mobitive.ml.FeatureVectorizer;
import com.example.mobitive.benchmark.ScanBenchmark;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class ApkAnalyzer {

    private final Context context;

    private final ManifestExtractor manifestExtractor;
    private final DexExtractor dexExtractor;

    private final FeatureDictionary dictionary;
    private final FeatureVectorizer vectorizer;

    public ApkAnalyzer(Context context) throws IOException {

        this.context = context.getApplicationContext();

        manifestExtractor = new ManifestExtractor();
        dexExtractor = new DexExtractor();

        // Đọc Feature Dictionary từ assets.
        dictionary = FeatureDictionary.load(this.context);

        // Khởi tạo bộ vector hóa.
        vectorizer = new FeatureVectorizer(dictionary);

        if (dictionary.getFeatureCount() <= 0) {
            throw new IllegalStateException("Feature Dictionary rỗng.");
        }
    }

    /**
     * Phân tích một APK và tạo vector đặc trưng.
     */
    public AnalysisResult analyze(File apkFile) throws Exception {
        return analyze(apkFile, null);
    }

    public AnalysisResult analyze(File apkFile, ScanBenchmark benchmark) throws Exception {

        if (apkFile == null || !apkFile.exists()) {
            throw new IOException("APK không tồn tại.");
        }

        // --------------------------------
        // 1. Trích xuất Manifest
        // --------------------------------

        ScanBenchmark.Token manifestTiming = benchmark == null ? null : benchmark.startStage();
        ManifestExtractor.ManifestFeatures manifest =
                manifestExtractor.extract(apkFile);
        if (benchmark != null) benchmark.endStage("manifest", manifestTiming);

        Set<String> manifestFeatures = manifest.toFeatureSet();

        // --------------------------------
        // 2. Trích xuất DEX
        // --------------------------------

        ScanBenchmark.Token dexTiming = benchmark == null ? null : benchmark.startStage();
        DexExtractor.DexFeatures dex =
                dexExtractor.extract(apkFile);
        if (benchmark != null) benchmark.endStage("dex", dexTiming);

        Set<String> apiFeatures = dex.getApiCalls();

        // --------------------------------
        // 3. Kiểm tra feature không được hỗ trợ
        // --------------------------------

        ScanBenchmark.Token lookupTiming = benchmark == null ? null : benchmark.startStage();
        Set<String> unknownApiFeatures = new HashSet<>();

        for (String feature : apiFeatures) {
            if (dictionary.getApiIndex(feature) < 0) {
                unknownApiFeatures.add(feature);
            }
        }

        Set<String> unknownManifestFeatures = new HashSet<>();

        for (String feature : manifestFeatures) {
            if (dictionary.getManifestIndex(feature) < 0) {
                unknownManifestFeatures.add(feature);
            }
        }

        // --------------------------------
        // 4. Vector hóa
        // --------------------------------

        if (benchmark != null) benchmark.endStage("feature_lookup", lookupTiming);
        ScanBenchmark.Token vectorTiming = benchmark == null ? null : benchmark.startStage();
        float[] vector = vectorizer.vectorize(
                apiFeatures,
                manifestFeatures
        );
        if (benchmark != null) benchmark.endStage("vectorize", vectorTiming);

        // --------------------------------
        // 5. Kiểm tra kết quả
        // --------------------------------

        if (vector.length != dictionary.getFeatureCount()) {
            throw new IllegalStateException(
                    "Vector phải có " + dictionary.getFeatureCount()
                            + " chiều, hiện tại: " + vector.length
            );
        }

        int activeFeatures =
                vectorizer.countActiveFeatures(vector);

        return new AnalysisResult(
                vector,
                apiFeatures.size(),
                manifestFeatures.size(),
                activeFeatures,
                unknownApiFeatures.size(),
                unknownManifestFeatures.size(),
                dex.getDexFileCount(),
                dex.getClassDefCount(),
                dex.getMethodRefCount(),
                dex.getFrameworkMethodRefCount(),
                dex.getBundledLibraryRefCount(),
                manifest,
                dex
        );
    }

    /**
     * Kết quả phân tích APK.
     */
    public static class AnalysisResult {

        private final float[] featureVector;

        private final int extractedApiCount;
        private final int extractedManifestCount;
        private final int activeFeatureCount;

        private final int unknownApiCount;
        private final int unknownManifestCount;

        // DEX method-table statistics (M5).
        private final int dexFileCount;
        private final int classDefCount;
        private final int methodRefCount;
        private final int frameworkMethodRefCount;
        private final int bundledLibraryRefCount;

        private final ManifestExtractor.ManifestFeatures manifest;
        private final DexExtractor.DexFeatures dex;

        public AnalysisResult(
                float[] featureVector,
                int extractedApiCount,
                int extractedManifestCount,
                int activeFeatureCount,
                int unknownApiCount,
                int unknownManifestCount,
                int dexFileCount,
                int classDefCount,
                int methodRefCount,
                int frameworkMethodRefCount,
                int bundledLibraryRefCount,
                ManifestExtractor.ManifestFeatures manifest,
                DexExtractor.DexFeatures dex) {

            this.featureVector = featureVector;

            this.extractedApiCount = extractedApiCount;
            this.extractedManifestCount = extractedManifestCount;
            this.activeFeatureCount = activeFeatureCount;

            this.unknownApiCount = unknownApiCount;
            this.unknownManifestCount = unknownManifestCount;

            this.dexFileCount = dexFileCount;
            this.classDefCount = classDefCount;
            this.methodRefCount = methodRefCount;
            this.frameworkMethodRefCount = frameworkMethodRefCount;
            this.bundledLibraryRefCount = bundledLibraryRefCount;

            this.manifest = manifest;
            this.dex = dex;
        }

        public float[] getFeatureVector() { return featureVector; }
        public int getExtractedApiCount() { return extractedApiCount; }
        public int getExtractedManifestCount() { return extractedManifestCount; }
        public int getActiveFeatureCount() { return activeFeatureCount; }
        public int getUnknownApiCount() { return unknownApiCount; }
        public int getUnknownManifestCount() { return unknownManifestCount; }
        public int getDexFileCount() { return dexFileCount; }
        public int getClassDefCount() { return classDefCount; }
        public int getMethodRefCount() { return methodRefCount; }
        public int getFrameworkMethodRefCount() { return frameworkMethodRefCount; }
        public int getBundledLibraryRefCount() { return bundledLibraryRefCount; }
        public ManifestExtractor.ManifestFeatures getManifest() { return manifest; }
        public DexExtractor.DexFeatures getDex() { return dex; }
    }
}
