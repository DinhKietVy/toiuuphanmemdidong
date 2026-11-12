package com.example.mobitive.benchmark;

import android.content.Context;
import android.os.Build;
import android.os.Debug;
import android.os.SystemClock;

import com.example.mobitive.ml.ModelAssets;

import org.tensorflow.lite.DataType;
import org.tensorflow.lite.Interpreter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Repeatable on-device inference-only microbenchmark.
 *
 * Models must have FLOAT32 input and [1,2] FLOAT32 output; unsupported
 * model shapes/types are recorded as ERROR (not silently coerced).
 * Benchmarks only INFERENCE, not file copy, DEX or model preparation.
 * Does NOT measure accuracy: label agreement is not ground-truth accuracy.
 */
public final class ModelBenchmark {
    public static final String[] MODEL_FILES = {
            "mobitive_gru.tflite",
            "mobitive_gru_fp16.tflite",
            "mobitive_gru_dynamic_range.tflite",
            "mobitive_gru64_float32.tflite",
            "mobitive_mlp64_float32.tflite"
    };
    public static final int[] THREAD_COUNTS = {1, 2, 4};
    public static final int WARMUP = 5;
    public static final int ITERATIONS = 30;
    public static final String HEADER =
            "epoch_ms,device,android_sdk,model_id,threads,model_bytes,warmup,iterations," +
            "init_wall_ms,inference_p50_ms,inference_p95_ms,inference_mean_ms," +
            "inference_thread_cpu_mean_ms,benign_probability,malware_probability," +
            "same_label_as_baseline,probability_delta_from_baseline,status,error";

    private ModelBenchmark() { }

    public static final class Result {
        public final String summary;
        public final List<String> csvRows;
        public Result(String summary, List<String> csvRows) {
            this.summary = summary;
            this.csvRows = csvRows;
        }
    }

    private static final class Predictions {
        float benign;
        float malware;
        Predictions(float benign, float malware) {
            this.benign = benign;
            this.malware = malware;
        }
        boolean isMalware() { return malware > benign; }
    }

    /** Run synchronously on the dedicated background executor, never UI thread. */
    public static Result run(Context context, float[] vector) {
        if (vector == null || vector.length == 0) {
            throw new IllegalArgumentException("Cần quét APK thành công trước.");
        }
        for (float x : vector) {
            if (!Float.isFinite(x)) {
                throw new IllegalArgumentException("Feature vector có NaN hoặc Infinity");
            }
        }
        Context app = context.getApplicationContext();
        List<String> rows = new ArrayList<>();
        StringBuilder summary = new StringBuilder("AI BENCHMARK (inference-only)\n");
        summary.append("5 warmups + 30 measured iterations / scenario\n");
        summary.append("Model initialization excluded from p50/p95.\n\n");
        Predictions baseline = null;
        long epochMs = System.currentTimeMillis();

        // Run the baseline with 4 threads first. This matches the original
        // MalwareClassifier configuration, but does not imply optimality.
        for (String file : MODEL_FILES) {
            boolean exists;
            try {
                String[] installed = app.getAssets().list("models");
                exists = installed != null && Arrays.asList(installed).contains(file);
            } catch (IOException ex) {
                exists = false;
            }
            if (!exists) {
                summary.append(file).append(": not installed (SKIP)\n");
                continue;
            }
            final int[] threadOrder = file.equals(MODEL_FILES[0])
                    ? new int[]{4, 1, 2} : THREAD_COUNTS;
            for (int threads : threadOrder) {
                String modelId = file.replace(".tflite", "");
                Interpreter interpreter = null;
                try {
                    long startInit = SystemClock.elapsedRealtimeNanos();
                    ModelAssets.Model model = ModelAssets.map(app, "models/" + file);
                    Interpreter.Options options = new Interpreter.Options();
                    options.setNumThreads(threads);
                    try {
                        interpreter = new Interpreter(model.buffer, options);
                    } catch (Exception e) {
                        throw new IllegalStateException("Cannot load model: " + e.getMessage(), e);
                    }
                    double initMs = elapsedMs(startInit);
                    if (interpreter.getInputTensor(0).dataType() != DataType.FLOAT32 ||
                            interpreter.getOutputTensor(0).dataType() != DataType.FLOAT32) {
                        throw new IllegalArgumentException("Only float32 input/output supported");
                    }
                    int[] inShape = interpreter.getInputTensor(0).shape();
                    int n = vector.length;
                    if (!Arrays.equals(inShape, new int[]{1, 1, n}) &&
                            !Arrays.equals(inShape, new int[]{1, n})) {
                        throw new IllegalArgumentException("Model input " + Arrays.toString(inShape)
                                + " does not match " + n + " features");
                    }
                    if (!Arrays.equals(interpreter.getOutputTensor(0).shape(), new int[]{1,2})) {
                        throw new IllegalArgumentException("Unsupported output shape");
                    }
                    Object input;
                    if (inShape.length == 3) {
                        input = new float[][][]{{vector.clone()}};
                    } else {
                        input = new float[][]{vector.clone()};
                    }
                    float[][] output = new float[1][2];
                    for (int i = 0; i < WARMUP; i++) interpreter.run(input, output);
                    List<Double> samples = new ArrayList<>(ITERATIONS);
                    double cpuTotalMs = 0;
                    for (int i = 0; i < ITERATIONS; i++) {
                        long startCpuNs = Debug.threadCpuTimeNanos();
                        long startNs = SystemClock.elapsedRealtimeNanos();
                        interpreter.run(input, output);
                        samples.add(elapsedMs(startNs));
                        cpuTotalMs += (Debug.threadCpuTimeNanos() - startCpuNs) / 1_000_000.0;
                    }
                    Predictions prediction = new Predictions(output[0][0], output[0][1]);
                    if (baseline == null && file.equals(MODEL_FILES[0]) && threads == 4) {
                        baseline = prediction;
                    }
                    Double probDelta = baseline == null ? null :
                            (double) Math.abs(prediction.malware - baseline.malware);
                    Boolean sameLabel = baseline == null ? null :
                            prediction.isMalware() == baseline.isMalware();
                    Collections.sort(samples);
                    double p50 = percentile(samples, .50);
                    double p95 = percentile(samples, .95);
                    double sum = 0;
                    for (double sample : samples) sum += sample;
                    double mean = sum / samples.size();
                    String row = prefix(epochMs, modelId, threads, model.bytes) +
                            WARMUP + "," + ITERATIONS + "," + fmt(initMs) + "," +
                            fmt(p50) + "," + fmt(p95) + "," + fmt(mean) + "," +
                            fmt(cpuTotalMs / ITERATIONS) + "," + fmt(prediction.benign) + "," +
                            fmt(prediction.malware) + "," + (sameLabel == null ? "" : sameLabel) + "," +
                            (probDelta == null ? "" : fmt(probDelta)) + ",OK,";
                    rows.add(row);
                    summary.append(String.format(Locale.US,
                            "%s (%d threads): p50 %.3f ms, p95 %.3f ms, init %.2f ms, malware %.4f\n",
                            modelId, threads, p50, p95, initMs, prediction.malware));
                } catch (Exception e) {
                    String error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                    rows.add(prefix(epochMs, modelId, threads, -1) + WARMUP + "," + ITERATIONS +
                            ",,,,,,,,,,ERROR," + csvQuote(error));
                    summary.append(modelId).append(" (").append(threads)
                            .append(" threads): ERROR ").append(error).append('\n');
                } finally {
                    if (interpreter != null) interpreter.close();
                }
            }
        }
        return new Result(summary.toString(), rows);
    }

    private static double percentile(List<Double> sorted, double quantile) {
        int index = Math.max(0, (int) Math.ceil(quantile * sorted.size()) - 1);
        return sorted.get(index);
    }

    private static String prefix(long epoch, String model, int threads, long bytes) {
        return epoch + "," + csvQuote(Build.MANUFACTURER + " " + Build.MODEL) + "," +
                Build.VERSION.SDK_INT + "," + csvQuote(model) + "," + threads + "," +
                (bytes < 0 ? "" : bytes) + ",";
    }

    private static String fmt(double value) {
        return String.format(Locale.US, "%.6f", value);
    }

    private static String csvQuote(String s) {
        if (s == null) s = "";
        if (!s.isEmpty() && "=+-@".indexOf(s.charAt(0)) >= 0) s = "'" + s;
        return '"' + s.replace("\"", "\"\"") + '"';
    }

    private static double elapsedMs(long startNs) {
        return (SystemClock.elapsedRealtimeNanos() - startNs) / 1_000_000.0;
    }
}
