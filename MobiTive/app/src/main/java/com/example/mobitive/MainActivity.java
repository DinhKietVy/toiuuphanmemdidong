
package com.example.mobitive;

import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.example.mobitive.analyzer.ApkAnalyzer;
import com.example.mobitive.ml.MalwareClassifier;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private Button btnSelectApk;
    private TextView tvFileName;
    private TextView tvResult;
    private ProgressBar progressBar;

    private ExecutorService executorService;

    private ApkAnalyzer apkAnalyzer;
    private MalwareClassifier malwareClassifier;

    private ActivityResultLauncher<Intent> apkPickerLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initializeViews();

        executorService = Executors.newSingleThreadExecutor();

        registerApkPicker();

        btnSelectApk.setOnClickListener(v -> openApkPicker());
    }

    private void initializeViews() {

        btnSelectApk = findViewById(R.id.btnSelectApk);
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

    private void openApkPicker() {

        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);

        intent.addCategory(Intent.CATEGORY_OPENABLE);

        intent.setType("application/vnd.android.package-archive");

        apkPickerLauncher.launch(intent);
    }

    private void scanApk(Uri apkUri) {

        btnSelectApk.setEnabled(false);
        progressBar.setVisibility(View.VISIBLE);

        tvResult.setText("Đang chuẩn bị phân tích APK...");

        String fileName = getFileName(apkUri);

        tvFileName.setText(fileName);

        executorService.execute(() -> {

            File temporaryApk = null;

            try {

                // 1. Copy APK vào cache.
                temporaryApk = copyApkToCache(apkUri);

                // 2. Khởi tạo bộ phân tích.
                if (apkAnalyzer == null) {
                    apkAnalyzer = new ApkAnalyzer(
                            getApplicationContext()
                    );
                }

                // 3. Trích xuất và vector hóa.
                ApkAnalyzer.AnalysisResult analysis =
                        apkAnalyzer.analyze(temporaryApk);

                float[] featureVector =
                        analysis.getFeatureVector();

                // 4. Khởi tạo mô hình TFLite.
                if (malwareClassifier == null) {
                    malwareClassifier = new MalwareClassifier(
                            getApplicationContext()
                    );
                }

                // 5. Dự đoán.
                MalwareClassifier.Prediction prediction =
                        malwareClassifier.predict(featureVector);

                // 6. Hiển thị kết quả.
                runOnUiThread(() -> displayResult(
                        analysis,
                        prediction
                ));

            } catch (Exception e) {

                String errorMessage = e.getMessage();

                if (errorMessage == null) {
                    errorMessage = e.getClass().getSimpleName();
                }

                String finalErrorMessage = errorMessage;

                runOnUiThread(() -> showError(
                        "Phân tích thất bại: " + finalErrorMessage
                ));

            } finally {

                if (temporaryApk != null && temporaryApk.exists()) {
                    temporaryApk.delete();
                }

                runOnUiThread(() -> {
                    progressBar.setVisibility(View.GONE);
                    btnSelectApk.setEnabled(true);
                });
            }
        });
    }

    /**
     * Sao chép APK từ Uri vào cache.
     */
    private File copyApkToCache(Uri uri) throws Exception {

        File outputFile = File.createTempFile(
                "mobitive_scan_",
                ".apk",
                getCacheDir()
        );

        try (
                InputStream inputStream =
                        getContentResolver().openInputStream(uri);

                FileOutputStream outputStream =
                        new FileOutputStream(outputFile)
        ) {

            if (inputStream == null) {
                throw new Exception("Không thể mở APK.");
            }

            byte[] buffer = new byte[8192];

            int length;

            while ((length = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, length);
            }

            outputStream.flush();
        }

        return outputFile;
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
            MalwareClassifier.Prediction prediction) {

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

        result.append("DEX classes: ")
                .append(analysis.getParsedClassCount())
                .append("\n");

        result.append("DEX methods: ")
                .append(analysis.getParsedMethodCount())
                .append("\n");

        result.append("Invoke instructions: ")
                .append(analysis.getInvokeInstructionCount())
                .append("\n");

        result.append("Matched methods: ")
                .append(analysis.getMatchedMethodCount())
                .append("\n");

        result.append("Framework invokes: ")
                .append(analysis.getFrameworkInvokeCount())
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

        tvResult.setText(result.toString());
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
            executorService.shutdown();
        }

        if (malwareClassifier != null) {
            malwareClassifier.close();
            malwareClassifier = null;
        }
    }
}
