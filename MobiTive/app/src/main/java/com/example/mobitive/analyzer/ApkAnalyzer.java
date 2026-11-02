
package com.example.mobitive.analyzer;

import android.content.Context;

import com.example.mobitive.ml.FeatureDictionary;
import com.example.mobitive.ml.FeatureVectorizer;

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

        if (dictionary.getFeatureCount() != 2915) {
            throw new IllegalStateException(
                    "Feature Dictionary phải có 2915 features, hiện tại: "
                            + dictionary.getFeatureCount()
            );
        }
    }

    /**
     * Phân tích một APK và tạo vector đặc trưng.
     */
    public AnalysisResult analyze(File apkFile) throws Exception {

        if (apkFile == null || !apkFile.exists()) {
            throw new IOException("APK không tồn tại.");
        }

        // --------------------------------
        // 1. Trích xuất Manifest
        // --------------------------------

        ManifestExtractor.ManifestFeatures manifest =
                manifestExtractor.extract(apkFile);

        Set<String> manifestFeatures = manifest.toFeatureSet();

        // --------------------------------
        // 2. Trích xuất DEX
        // --------------------------------

        DexExtractor.DexFeatures dex =
                dexExtractor.extract(apkFile, context.getCacheDir());

        Set<String> apiFeatures = dex.getApiCalls();

        // --------------------------------
        // 3. Kiểm tra feature không được hỗ trợ
        // --------------------------------

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

        float[] vector = vectorizer.vectorize(
                apiFeatures,
                manifestFeatures
        );

        // --------------------------------
        // 5. Kiểm tra kết quả
        // --------------------------------

        if (vector.length != 2915) {
            throw new IllegalStateException(
                    "Vector phải có 2915 chiều, hiện tại: "
                            + vector.length
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
                dex.getParsedClassCount(),
                dex.getParsedMethodCount(),
                dex.getInvokeInstructionCount(),
                dex.getMatchedMethodCount(),
                dex.getFrameworkInvokeCount(),
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

        private final int parsedClassCount;
        private final int parsedMethodCount;

        private final int invokeInstructionCount;
        private final int matchedMethodCount;
        private final int frameworkInvokeCount;

        private final ManifestExtractor.ManifestFeatures manifest;
        private final DexExtractor.DexFeatures dex;

        public AnalysisResult(
                float[] featureVector,
                int extractedApiCount,
                int extractedManifestCount,
                int activeFeatureCount,
                int unknownApiCount,
                int unknownManifestCount,
                int parsedClassCount,
                int parsedMethodCount,
                int invokeInstructionCount,
                int matchedMethodCount,
                int frameworkInvokeCount,
                ManifestExtractor.ManifestFeatures manifest,
                DexExtractor.DexFeatures dex) {

            this.featureVector = featureVector;

            this.extractedApiCount = extractedApiCount;
            this.extractedManifestCount = extractedManifestCount;
            this.activeFeatureCount = activeFeatureCount;

            this.unknownApiCount = unknownApiCount;
            this.unknownManifestCount = unknownManifestCount;

            this.parsedClassCount = parsedClassCount;
            this.parsedMethodCount = parsedMethodCount;

            this.invokeInstructionCount = invokeInstructionCount;
            this.matchedMethodCount = matchedMethodCount;
            this.frameworkInvokeCount = frameworkInvokeCount;

            this.manifest = manifest;
            this.dex = dex;
        }

        public float[] getFeatureVector() {
            return featureVector;
        }

        public int getExtractedApiCount() {
            return extractedApiCount;
        }

        public int getExtractedManifestCount() {
            return extractedManifestCount;
        }

        public int getActiveFeatureCount() {
            return activeFeatureCount;
        }

        public int getUnknownApiCount() {
            return unknownApiCount;
        }

        public int getUnknownManifestCount() {
            return unknownManifestCount;
        }

        public int getParsedClassCount() {
            return parsedClassCount;
        }

        public int getParsedMethodCount() {
            return parsedMethodCount;
        }

        public int getInvokeInstructionCount() {
            return invokeInstructionCount;
        }

        public int getMatchedMethodCount() {
            return matchedMethodCount;
        }

        public int getFrameworkInvokeCount() {
            return frameworkInvokeCount;
        }

        public ManifestExtractor.ManifestFeatures getManifest() {
            return manifest;
        }

        public DexExtractor.DexFeatures getDex() {
            return dex;
        }
    }
}
