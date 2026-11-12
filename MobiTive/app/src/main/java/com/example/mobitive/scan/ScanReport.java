package com.example.mobitive.scan;

import com.example.mobitive.analyzer.ApkAnalyzer;
import com.example.mobitive.ml.MalwareClassifier;

import java.util.Locale;

/** Human-readable scan report shown on the main screen (pure formatting, no Android UI). */
public final class ScanReport {

    private ScanReport() { }

    public static String format(ScanPipeline.Outcome outcome) {
        ApkAnalyzer.AnalysisResult a = outcome.analysis;
        MalwareClassifier.Prediction p = outcome.prediction;
        StringBuilder r = new StringBuilder();
        r.append("SCAN COMPLETED\n\n");
        r.append("RESULT: ").append(p.getLabel()).append("\n\n");
        r.append(String.format(Locale.US, "Malware probability: %.2f%%\n", p.malwareProbability * 100f));
        r.append(String.format(Locale.US, "Benign probability: %.2f%%\n\n", p.benignProbability * 100f));

        r.append("EXTRACTION STATISTICS\n\n");
        r.append("DEX files: ").append(a.getDexFileCount()).append('\n');
        r.append("DEX class defs: ").append(a.getClassDefCount()).append('\n');
        r.append("Method refs (method_ids): ").append(a.getMethodRefCount()).append('\n');
        r.append("Framework method refs: ").append(a.getFrameworkMethodRefCount()).append('\n');
        r.append("Dropped (bundled support/arch libs): ").append(a.getBundledLibraryRefCount()).append("\n\n");

        r.append("FEATURE STATISTICS\n\n");
        r.append("Extracted API: ").append(a.getExtractedApiCount()).append('\n');
        r.append("Extracted Manifest: ").append(a.getExtractedManifestCount()).append('\n');
        r.append("Active features: ").append(a.getActiveFeatureCount())
                .append(" / ").append(a.getFeatureVector().length).append('\n');
        r.append("Unknown API features: ").append(a.getUnknownApiCount()).append('\n');
        r.append("Unknown Manifest features: ").append(a.getUnknownManifestCount()).append('\n');

        return r + outcome.benchmark.readableSummary();
    }
}
