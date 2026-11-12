package com.example.mobitive.m4;

import android.content.Context;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Whitelisted local TFLite models; no remote loading or unverified model paths. */
public final class M4ModelCatalog {
    public static final class Choice {
        public final String id;
        public final String title;
        public final String fileName;
        public final int threads;
        public Choice(String id, String title, String fileName, int threads) {
            this.id = id;
            this.title = title;
            this.fileName = fileName;
            this.threads = threads;
        }
        public boolean isBaseline() { return "gru128_fp32".equals(id); }
        @Override public String toString() { return title; }
    }

    private static final Choice[] ALL = {
            new Choice("gru128_fp32", "GRU-128 FP32 · Baseline", "mobitive_gru.tflite", 4),
            new Choice("gru128_fp16", "GRU-128 FP16 · Smaller", "mobitive_gru_fp16.tflite", 1),
            new Choice("gru128_dynamic", "GRU-128 Dynamic · Quantized", "mobitive_gru_dynamic_range.tflite", 1),
            new Choice("gru64_fp32", "GRU-64 FP32 · Compact", "mobitive_gru64_float32.tflite", 1),
            new Choice("mlp64_fp32", "MLP-64 FP32 · Lightweight", "mobitive_mlp64_float32.tflite", 1)
    };

    private M4ModelCatalog() {}

    public static List<Choice> installed(Context context) throws IOException {
        String[] names = context.getAssets().list("models");
        List<String> installed = names == null ? Collections.emptyList() : Arrays.asList(names);
        List<Choice> choices = new ArrayList<>();
        for (Choice choice : ALL) {
            if (installed.contains(choice.fileName)) choices.add(choice);
        }
        if (choices.isEmpty() || !choices.get(0).isBaseline()) {
            throw new IOException("Thiếu model GRU-128 baseline trong assets/models.");
        }
        return Collections.unmodifiableList(choices);
    }
}
