
package com.example.mobitive;

import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.Spinner;
import android.widget.ArrayAdapter;
import android.widget.AdapterView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.example.mobitive.analyzer.ApkAnalyzer;
import com.example.mobitive.ml.MalwareClassifier;
import com.example.mobitive.benchmark.ScanBenchmark;
import com.example.mobitive.benchmark.BenchmarkStore;
import com.example.mobitive.benchmark.ModelBenchmark;
import com.example.mobitive.benchmark.ModelBenchmarkStore;
import com.example.mobitive.m4.M4ModelCatalog;
import com.example.mobitive.m4.M4ScanHistory;
import com.example.mobitive.m4.M4HistoryActivity;
import com.example.mobitive.scan.ScanPipeline;

import java.io.File;
import java.util.Locale;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private Button btnSelectApk;
    private Button btnExportCsv;
    private Button btnAiBenchmark;
    private Button btnExportAiCsv;
    private float[] lastFeatureVector;
    private CheckBox cbForceFullScan;
    private Spinner m4ModelSpinner;
    private TextView m4Status;
    private List<M4ModelCatalog.Choice> m4Models;
    private TextView tvFileName;
    private TextView tvResult;
    private ProgressBar progressBar;

    private ExecutorService executorService;

    private ScanPipeline scanPipeline;

    private ActivityResultLauncher<Intent> apkPickerLauncher;
    private ActivityResultLauncher<String> csvExportLauncher;
    private ActivityResultLauncher<String> aiCsvExportLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initializeViews();
        setupM4Ui();

        executorService = Executors.newSingleThreadExecutor();

        registerApkPicker();
        registerCsvExporter();
        registerAiCsvExporter();

        btnSelectApk.setOnClickListener(v -> openApkPicker());
        btnExportCsv.setOnClickListener(v ->
                csvExportLauncher.launch(BenchmarkStore.FILE_NAME));
        btnAiBenchmark.setOnClickListener(v -> runAiBenchmark());
        btnExportAiCsv.setOnClickListener(v ->
                aiCsvExportLauncher.launch(ModelBenchmarkStore.FILE_NAME));
    }

    private void initializeViews() {

        btnSelectApk = findViewById(R.id.btnSelectApk);
        btnExportCsv = findViewById(R.id.btnExportCsv);
        btnExportCsv.setEnabled(BenchmarkStore.hasData(this));
        btnAiBenchmark = findViewById(R.id.btnAiBenchmark);
        btnAiBenchmark.setEnabled(false);
        btnExportAiCsv = findViewById(R.id.btnExportAiCsv);
        btnExportAiCsv.setEnabled(ModelBenchmarkStore.hasData(this));
        cbForceFullScan = findViewById(R.id.cbForceFullScan);
        tvFileName = findViewById(R.id.tvFileName);
        tvResult = findViewById(R.id.tvResult);
        progressBar = findViewById(R.id.progressBar);

        progressBar.setVisibility(View.GONE);

        tvFileName.setText("Chưa chọn APK");
        tvResult.setText("Chọn một APK để bắt đầu phân tích.");
    }

    private void registerApkPicker() {

        apkPickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {

                    if (result.getResultCode() != RESULT_OK
                            || result.getData() == null) {
                        return;
                    }

                    Uri apkUri = result.getData().getData();

                    if (apkUri == null) {
                        showError("Không thể đọc APK.");
                        return;
                    }

                    scanApk(apkUri);
                }
        );
    }

    private void registerCsvExporter() {
        csvExportLauncher = registerForActivityResult(
                new ActivityResultContracts.CreateDocument("text/csv"), uri -> {
                    if (uri == null) return;
                    executorService.execute(() -> {
                        try {
                            BenchmarkStore.export(getApplicationContext(),
                                    getContentResolver(), uri);
                            runOnUiThread(() -> {
                                if (!isFinishing() && !isDestroyed()) {
                                    Toast.makeText(this, "Đã xuất benchmark CSV", Toast.LENGTH_SHORT).show();
                                }
                            });
                        } catch (Exception e) {
                            Log.e("MobiTive", "Export CSV failed", e);
                            runOnUiThread(() -> {
                                if (!isFinishing() && !isDestroyed()) {
                                    showError("Xuất CSV thất bại: " + e.getMessage());
                                }
                            });
                        }
                    });
                });
    }

    /** Save M2 inference-only results via Storage Access Framework. */
    private void registerAiCsvExporter() {
        aiCsvExportLauncher = registerForActivityResult(
                new ActivityResultContracts.CreateDocument("text/csv"), uri -> {
                    if (uri == null) return;
                    executorService.execute(() -> {
                        try {
                            ModelBenchmarkStore.export(getApplicationContext(),
                                    getContentResolver(), uri);
                            runOnUiThread(() -> {
                                if (!isFinishing() && !isDestroyed()) {
                                    Toast.makeText(this, "Đã xuất AI benchmark CSV", Toast.LENGTH_SHORT).show();
                                }
                            });
                        } catch (Exception e) {
                            Log.e("MobiTive", "AI benchmark export failed", e);
                            runOnUiThread(() -> {
                                if (!isFinishing() && !isDestroyed()) {
                                    showError("Xuất AI benchmark thất bại: " + e.getMessage());
                                }
                            });
                        }
                    });
                });
    }

    /**
     * Benchmarks TFLite (CPU, 1/2/4 threads) from the LAST successfully
     * extracted feature vector; no extra APK/DEX parsing in this experiment.
     */
    private void runAiBenchmark() {
        if (lastFeatureVector == null) {
            Toast.makeText(this, "Hãy quét một APK thành công trước", Toast.LENGTH_SHORT).show();
            return;
        }
        final float[] vector = lastFeatureVector.clone();
        btnSelectApk.setEnabled(false);
        btnAiBenchmark.setEnabled(false);
        btnExportAiCsv.setEnabled(false);
        m4ModelSpinner.setEnabled(false);
        m4Status.setText("Đang đo suy luận AI (inference-only)...");
        progressBar.setVisibility(View.VISIBLE);
        tvResult.setText("Đang chạy AI microbenchmark: CPU 1/2/4 threads...");

        executorService.execute(() -> {
            String error = null;
            ModelBenchmark.Result result = null;
            try {
                result = ModelBenchmark.run(getApplicationContext(), vector);
                ModelBenchmarkStore.append(getApplicationContext(), result);
            } catch (Exception e) {
                Log.e("MobiTive", "AI benchmark failed", e);
                error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            }
            final String shownError = error;
            final ModelBenchmark.Result shownResult = result;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                progressBar.setVisibility(View.GONE);
                btnSelectApk.setEnabled(true);
                btnAiBenchmark.setEnabled(true);
                btnExportAiCsv.setEnabled(ModelBenchmarkStore.hasData(this));
                m4ModelSpinner.setEnabled(true);
                m4Status.setText(shownError == null ? "AI Benchmark hoàn tất" : "Lỗi AI Benchmark");
                if (shownError != null) {
                    showError("Benchmark AI thất bại: " + shownError);
                } else {
                    tvResult.setText(shownResult.summary +
                            "\nLưu ý: benchmark suy luận, không phải tổng thời gian quét APK." +
                            "\nSo sánh trên điện thoại thật để kết luận.");
                }
            });
        });
    }

    /** M4: model choice affects actual APK classification; M2 model benchmark is unchanged. */
    private void setupM4Ui() {
        m4ModelSpinner = findViewById(R.id.m4ModelSpinner);
        m4Status = findViewById(R.id.m4Status);
        findViewById(R.id.m4HistoryButton).setOnClickListener(v ->
                startActivity(new Intent(this, M4HistoryActivity.class)));
        try {
            m4Models = M4ModelCatalog.installed(getApplicationContext());
        } catch (Exception ex) {
            m4Models = new ArrayList<>();
            btnSelectApk.setEnabled(false);
            m4Status.setText("Thiếu model trong assets/models: " + ex.getMessage());
            return;
        }
        List<String> titles = new ArrayList<>();
        for (M4ModelCatalog.Choice item : m4Models) titles.add(item.title);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, titles);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        m4ModelSpinner.setAdapter(adapter);
        String previous = getPreferences(MODE_PRIVATE).getString("m4_model_id", "gru128_fp32");
        for (int i = 0; i < m4Models.size(); i++) {
            if (m4Models.get(i).id.equals(previous)) {
                m4ModelSpinner.setSelection(i);
                break;
            }
        }
        m4ModelSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view,
                                                 int position, long id) {
                if (position >= 0 && position < m4Models.size()) {
                    getPreferences(MODE_PRIVATE).edit()
                            .putString("m4_model_id", m4Models.get(position).id).apply();
                }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
    }

    private M4ModelCatalog.Choice selectedM4Model() {
        int position = m4ModelSpinner.getSelectedItemPosition();
        if (m4Models == null || position < 0 || position >= m4Models.size()) {
            throw new IllegalStateException("Chưa có model AI phù hợp.");
        }
        return m4Models.get(position);
    }

    private void openApkPicker() {

        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);

        intent.addCategory(Intent.CATEGORY_OPENABLE);

        intent.setType("application/vnd.android.package-archive");

        apkPickerLauncher.launch(intent);
    }

    /** M3: cache is content addressed; forceFullScan is captured on UI thread. */
    private void scanApk(Uri apkUri) {
        final M4ModelCatalog.Choice m4Choice = selectedM4Model();
        final boolean forceFullScan = cbForceFullScan.isChecked();
        btnSelectApk.setEnabled(false);
        btnAiBenchmark.setEnabled(false);
        cbForceFullScan.setEnabled(false);
        m4ModelSpinner.setEnabled(false);
        m4Status.setText("Đang quét với " + m4Choice.title + "...");
        progressBar.setVisibility(View.VISIBLE);
        tvResult.setText(forceFullScan ? "Đang phân tích lại đầy đủ APK..." :
                "Đang kiểm tra SHA-256 và cache...");

        final String fileName = getFileName(apkUri);
        tvFileName.setText(fileName);

        executorService.execute(() -> {
            if (scanPipeline == null) {
                scanPipeline = new ScanPipeline(getApplicationContext());
            }
            ScanPipeline.Outcome outcome =
                    scanPipeline.scan(apkUri, fileName, m4Choice, forceFullScan);
            ScanBenchmark benchmark = outcome.benchmark;
            ApkAnalyzer.AnalysisResult analysis = outcome.analysis;
            MalwareClassifier.Prediction prediction = outcome.prediction;
            String error = outcome.error;
            String cacheMode = outcome.cacheMode;
            boolean saved = false;
            if (error == null && prediction != null && analysis != null) {
                try {
                    M4ScanHistory.append(getApplicationContext(), fileName,
                            m4Choice.id, prediction.getLabel(), cacheMode,
                            prediction.malwareProbability, benchmark.m4TotalWallMs());
                } catch (Exception historyError) {
                    Log.w("MobiTive", "M4 history write skipped", historyError);
                }
            }
            try {
                BenchmarkStore.append(getApplicationContext(), benchmark);
                saved = true;
            } catch (Exception e) {
                Log.e("MobiTive", "Cannot save benchmark CSV", e);
            }

            final ApkAnalyzer.AnalysisResult shownAnalysis = analysis;
            final MalwareClassifier.Prediction shownPrediction = prediction;
            final String shownError = error;
            final boolean csvSaved = saved;
            final String m4ShownMode = cacheMode;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                progressBar.setVisibility(View.GONE);
                btnSelectApk.setEnabled(true);
                cbForceFullScan.setEnabled(true);
                m4ModelSpinner.setEnabled(true);
                m4Status.setText(shownError == null ?
                        "Hoàn tất · " + m4ShownMode + " · " + m4Choice.title :
                        "Lỗi khi quét APK · " + shownError);
                btnExportCsv.setEnabled(BenchmarkStore.hasData(this));
                if (shownError != null) {
                    lastFeatureVector = null;
                    btnAiBenchmark.setEnabled(false);
                    showError("Phân tích thất bại: " + shownError);
                } else {
                    lastFeatureVector = shownAnalysis.getFeatureVector().clone();
                    btnAiBenchmark.setEnabled(true);
                    displayResult(shownAnalysis, shownPrediction, benchmark);
                    tvResult.setText("MODEL: " + m4Choice.title + "\n" + tvResult.getText());
                }
                if (!csvSaved) {
                    Toast.makeText(this, "Không lưu được benchmark CSV", Toast.LENGTH_LONG).show();
                }
            });
        });
    }

    /**
     * Lấy tên file từ Uri.
     */
    private String getFileName(Uri uri) {

        String fileName = "Unknown.apk";

        try (Cursor cursor = getContentResolver().query(
                uri,
                null,
                null,
                null,
                null
        )) {

            if (cursor != null && cursor.moveToFirst()) {

                int nameIndex = cursor.getColumnIndex(
                        OpenableColumns.DISPLAY_NAME
                );

                if (nameIndex >= 0) {
                    fileName = cursor.getString(nameIndex);
                }
            }

        } catch (Exception ignored) {
        }

        return fileName;
    }

    /**
     * Hiển thị kết quả phân tích.
     */
    private void displayResult(
            ApkAnalyzer.AnalysisResult analysis,
            MalwareClassifier.Prediction prediction,
            ScanBenchmark benchmark) {

        StringBuilder result = new StringBuilder();

        result.append("SCAN COMPLETED\n\n");

        result.append("RESULT: ")
                .append(prediction.getLabel())
                .append("\n\n");

        result.append(String.format(
                Locale.US,
                "Malware probability: %.2f%%\n",
                prediction.malwareProbability * 100f
        ));

        result.append(String.format(
                Locale.US,
                "Benign probability: %.2f%%\n\n",
                prediction.benignProbability * 100f
        ));

        result.append("EXTRACTION STATISTICS\n\n");

        result.append("DEX files: ")
                .append(analysis.getDexFileCount())
                .append("\n");

        result.append("DEX class defs: ")
                .append(analysis.getClassDefCount())
                .append("\n");

        result.append("Method refs (method_ids): ")
                .append(analysis.getMethodRefCount())
                .append("\n");

        result.append("Framework method refs: ")
                .append(analysis.getFrameworkMethodRefCount())
                .append("\n");

        result.append("Dropped (bundled support/arch libs): ")
                .append(analysis.getBundledLibraryRefCount())
                .append("\n\n");

        result.append("FEATURE STATISTICS\n\n");

        result.append("Extracted API: ")
                .append(analysis.getExtractedApiCount())
                .append("\n");

        result.append("Extracted Manifest: ")
                .append(analysis.getExtractedManifestCount())
                .append("\n");

        result.append("Active features: ")
                .append(analysis.getActiveFeatureCount())
                .append(" / 2915\n");

        result.append("Unknown API features: ")
                .append(analysis.getUnknownApiCount())
                .append("\n");

        result.append("Unknown Manifest features: ")
                .append(analysis.getUnknownManifestCount())
                .append("\n");

        tvResult.setText(result.toString() + benchmark.readableSummary());
    }

    private void showError(String message) {

        tvResult.setText(message);

        Toast.makeText(
                this,
                message,
                Toast.LENGTH_LONG
        ).show();
    }

    @Override
    protected void onDestroy() {

        super.onDestroy();

        if (executorService != null) {
            // Close the interpreter on the same serial worker AFTER any active scan.
            // Avoid closing it concurrently with interpreter.run().
            executorService.execute(() -> {
                if (scanPipeline != null) {
                    scanPipeline.close();
                    scanPipeline = null;
                }
            });
            executorService.shutdown();
        }
    }
}
