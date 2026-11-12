package com.example.mobitive;

import android.app.Application;
import android.content.ContentResolver;
import android.net.Uri;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.example.mobitive.benchmark.BenchmarkStore;
import com.example.mobitive.benchmark.ModelBenchmark;
import com.example.mobitive.benchmark.ModelBenchmarkStore;
import com.example.mobitive.history.ScanHistory;
import com.example.mobitive.ml.ModelCatalog;
import com.example.mobitive.scan.ScanPipeline;
import com.example.mobitive.scan.ScanReport;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Owns all background work and screen state, so a configuration change
 * (rotation, dark mode, split screen) neither cancels a scan nor loses its result.
 * Every task runs on ONE worker thread: the TFLite interpreters inside
 * {@link ScanPipeline} are never used concurrently and are closed on that thread.
 */
public class MainViewModel extends AndroidViewModel {

    private static final String TAG = "MobiTive";

    /** Immutable snapshot rendered by MainActivity. */
    public static final class UiState {
        public final boolean busy;
        public final String fileName;
        public final String status;
        public final String result;
        public final boolean hasVector;
        public final boolean scanCsvAvailable;
        public final boolean aiCsvAvailable;

        UiState(boolean busy, String fileName, String status, String result, boolean hasVector,
                boolean scanCsvAvailable, boolean aiCsvAvailable) {
            this.busy = busy;
            this.fileName = fileName;
            this.status = status;
            this.result = result;
            this.hasVector = hasVector;
            this.scanCsvAvailable = scanCsvAvailable;
            this.aiCsvAvailable = aiCsvAvailable;
        }
    }

    /** A message shown once (Toast); {@link #consume()} returns null after the first read. */
    public static final class Message {
        private final String text;
        private boolean consumed;

        Message(String text) { this.text = text; }

        public String consume() {
            if (consumed) return null;
            consumed = true;
            return text;
        }
    }

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final MutableLiveData<UiState> state = new MutableLiveData<>();
    private final MutableLiveData<Message> messages = new MutableLiveData<>();
    private ScanPipeline pipeline;             // worker thread only
    private volatile float[] lastFeatureVector;

    public MainViewModel(@NonNull Application app) {
        super(app);
        state.setValue(new UiState(false, "Chưa chọn APK", "Sẵn sàng · Xử lý trên thiết bị",
                "Chọn một APK để bắt đầu phân tích.", false,
                BenchmarkStore.hasData(app), ModelBenchmarkStore.hasData(app)));
    }

    public LiveData<UiState> getState() { return state; }

    public LiveData<Message> getMessages() { return messages; }

    // ------------------------------------------------------------------ actions

    public void scan(Uri apkUri, String fileName, ModelCatalog.Choice choice, boolean forceFullScan) {
        if (isBusy()) return;
        update(true, fileName, "Đang quét với " + choice.title + "...",
                forceFullScan ? "Đang phân tích lại đầy đủ APK..." : "Đang kiểm tra SHA-256 và cache...");
        worker.execute(() -> {
            if (pipeline == null) pipeline = new ScanPipeline(getApplication());
            ScanPipeline.Outcome o = pipeline.scan(apkUri, fileName, choice, forceFullScan);

            if (o.ok()) {
                try {
                    ScanHistory.append(getApplication(), fileName, choice.id, o.prediction.getLabel(),
                            o.cacheMode, o.prediction.malwareProbability, o.benchmark.m4TotalWallMs());
                } catch (Exception e) {
                    Log.w(TAG, "Scan history write skipped", e);
                }
            }
            boolean saved = true;
            try {
                BenchmarkStore.append(getApplication(), o.benchmark);
            } catch (Exception e) {
                saved = false;
                Log.e(TAG, "Cannot save benchmark CSV", e);
            }
            // One machine-readable line per scan (used to verify release/R8 builds via logcat).
            Log.i(TAG, String.format(Locale.US, "SCAN_RESULT file=%s model=%s mode=%s label=%s total_ms=%.1f error=%s",
                    fileName, choice.id, o.cacheMode, o.ok() ? o.prediction.getLabel() : "-",
                    o.benchmark.m4TotalWallMs(), o.error));

            if (o.ok()) {
                lastFeatureVector = o.analysis.getFeatureVector().clone();
                postState(false, fileName, "Hoàn tất · " + o.cacheMode + " · " + choice.title,
                        "MODEL: " + choice.title + "\n" + ScanReport.format(o));
            } else {
                lastFeatureVector = null;
                postState(false, fileName, "Lỗi khi quét APK · " + o.error, "Phân tích thất bại: " + o.error);
                messages.postValue(new Message("Phân tích thất bại: " + o.error));
            }
            if (!saved) messages.postValue(new Message("Không lưu được benchmark CSV"));
        });
    }

    /** CPU 1/2/4-thread inference benchmark on the last extracted vector (no re-parsing). */
    public void runAiBenchmark() {
        final float[] vector = lastFeatureVector;
        if (vector == null) {
            messages.setValue(new Message("Hãy quét một APK thành công trước"));
            return;
        }
        if (isBusy()) return;
        UiState s = state.getValue();
        update(true, s.fileName, "Đang đo suy luận AI (inference-only)...",
                "Đang chạy AI microbenchmark: CPU 1/2/4 threads...");
        worker.execute(() -> {
            try {
                ModelBenchmark.Result result = ModelBenchmark.run(getApplication(), vector);
                ModelBenchmarkStore.append(getApplication(), result);
                postState(false, s.fileName, "AI Benchmark hoàn tất", result.summary
                        + "\nLưu ý: benchmark suy luận, không phải tổng thời gian quét APK.");
            } catch (Exception e) {
                Log.e(TAG, "AI benchmark failed", e);
                String error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                postState(false, s.fileName, "Lỗi AI Benchmark", "Benchmark AI thất bại: " + error);
                messages.postValue(new Message("Benchmark AI thất bại: " + error));
            }
        });
    }

    public void exportScanCsv(Uri destination) {
        export(destination, false);
    }

    public void exportAiCsv(Uri destination) {
        export(destination, true);
    }

    private void export(Uri destination, boolean ai) {
        ContentResolver resolver = getApplication().getContentResolver();
        worker.execute(() -> {
            try {
                if (ai) {
                    ModelBenchmarkStore.export(getApplication(), resolver, destination);
                } else {
                    BenchmarkStore.export(getApplication(), resolver, destination);
                }
                messages.postValue(new Message(ai ? "Đã xuất AI benchmark CSV" : "Đã xuất benchmark CSV"));
            } catch (Exception e) {
                Log.e(TAG, "Export CSV failed", e);
                messages.postValue(new Message("Xuất CSV thất bại: " + e.getMessage()));
            }
        });
    }

    public void disableScanning(String reason) {
        UiState s = state.getValue();
        state.setValue(new UiState(true, s.fileName, reason, s.result, false,
                s.scanCsvAvailable, s.aiCsvAvailable));
    }

    // ------------------------------------------------------------------ helpers

    private boolean isBusy() {
        UiState s = state.getValue();
        return s != null && s.busy;
    }

    /** Main thread. */
    private void update(boolean busy, String fileName, String status, String result) {
        state.setValue(build(busy, fileName, status, result));
    }

    /** Worker thread. */
    private void postState(boolean busy, String fileName, String status, String result) {
        state.postValue(build(busy, fileName, status, result));
    }

    private UiState build(boolean busy, String fileName, String status, String result) {
        return new UiState(busy, fileName, status, result, lastFeatureVector != null,
                BenchmarkStore.hasData(getApplication()), ModelBenchmarkStore.hasData(getApplication()));
    }

    @Override
    protected void onCleared() {
        // Close interpreters on the worker AFTER any running task, never concurrently with run().
        worker.execute(() -> {
            if (pipeline != null) {
                pipeline.close();
                pipeline = null;
            }
        });
        worker.shutdown();
    }
}
