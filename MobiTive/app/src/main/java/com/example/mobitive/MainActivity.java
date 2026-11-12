package com.example.mobitive;

import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;

import com.example.mobitive.benchmark.BenchmarkStore;
import com.example.mobitive.benchmark.ModelBenchmarkStore;
import com.example.mobitive.history.ScanHistoryActivity;
import com.example.mobitive.ml.ModelCatalog;

import java.util.ArrayList;
import java.util.List;

/**
 * UI only: renders {@link MainViewModel.UiState} and forwards user actions.
 * All scanning, benchmarking and CSV export run in the ViewModel, so they
 * survive configuration changes.
 */
public class MainActivity extends AppCompatActivity {

    private static final String PREF_MODEL_ID = "m4_model_id"; // key kept for existing installs

    private MainViewModel viewModel;
    private List<ModelCatalog.Choice> models = new ArrayList<>();

    private Button btnSelectApk;
    private Button btnExportCsv;
    private Button btnAiBenchmark;
    private Button btnExportAiCsv;
    private CheckBox cbForceFullScan;
    private Spinner modelSpinner;
    private TextView tvStatus;
    private TextView tvFileName;
    private TextView tvResult;
    private ProgressBar progressBar;

    private ActivityResultLauncher<String[]> apkPicker;
    private ActivityResultLauncher<String> scanCsvExporter;
    private ActivityResultLauncher<String> aiCsvExporter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        viewModel = new ViewModelProvider(this).get(MainViewModel.class);

        btnSelectApk = findViewById(R.id.btnSelectApk);
        btnExportCsv = findViewById(R.id.btnExportCsv);
        btnAiBenchmark = findViewById(R.id.btnAiBenchmark);
        btnExportAiCsv = findViewById(R.id.btnExportAiCsv);
        cbForceFullScan = findViewById(R.id.cbForceFullScan);
        modelSpinner = findViewById(R.id.m4ModelSpinner);
        tvStatus = findViewById(R.id.m4Status);
        tvFileName = findViewById(R.id.tvFileName);
        tvResult = findViewById(R.id.tvResult);
        progressBar = findViewById(R.id.progressBar);

        apkPicker = registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
            if (uri != null) startScan(uri);
        });
        scanCsvExporter = registerForActivityResult(
                new ActivityResultContracts.CreateDocument("text/csv"), uri -> {
                    if (uri != null) viewModel.exportScanCsv(uri);
                });
        aiCsvExporter = registerForActivityResult(
                new ActivityResultContracts.CreateDocument("text/csv"), uri -> {
                    if (uri != null) viewModel.exportAiCsv(uri);
                });

        setupModelSpinner();
        btnSelectApk.setOnClickListener(v ->
                apkPicker.launch(new String[]{"application/vnd.android.package-archive"}));
        btnAiBenchmark.setOnClickListener(v -> viewModel.runAiBenchmark());
        btnExportCsv.setOnClickListener(v -> scanCsvExporter.launch(BenchmarkStore.FILE_NAME));
        btnExportAiCsv.setOnClickListener(v -> aiCsvExporter.launch(ModelBenchmarkStore.FILE_NAME));
        findViewById(R.id.m4HistoryButton).setOnClickListener(v ->
                startActivity(new Intent(this, ScanHistoryActivity.class)));

        viewModel.getState().observe(this, this::render);
        viewModel.getMessages().observe(this, message -> {
            String text = message == null ? null : message.consume();
            if (text != null) Toast.makeText(this, text, Toast.LENGTH_LONG).show();
        });

        // "Open with MobiTive" from a file manager / browser download: scan before installing.
        if (savedInstanceState == null) handleViewIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleViewIntent(intent);
    }

    private void handleViewIntent(Intent intent) {
        if (intent != null && Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null) {
            startScan(intent.getData());
        }
    }

    private void startScan(Uri uri) {
        ModelCatalog.Choice choice = selectedModel();
        if (choice == null) return;
        viewModel.scan(uri, displayName(uri), choice, cbForceFullScan.isChecked());
    }

    private void render(MainViewModel.UiState s) {
        progressBar.setVisibility(s.busy ? View.VISIBLE : View.GONE);
        tvFileName.setText(s.fileName);
        tvStatus.setText(s.status);
        tvResult.setText(s.result);
        boolean idle = !s.busy && !models.isEmpty();
        btnSelectApk.setEnabled(idle);
        cbForceFullScan.setEnabled(idle);
        modelSpinner.setEnabled(idle);
        btnAiBenchmark.setEnabled(idle && s.hasVector);
        btnExportCsv.setEnabled(!s.busy && s.scanCsvAvailable);
        btnExportAiCsv.setEnabled(!s.busy && s.aiCsvAvailable);
    }

    private void setupModelSpinner() {
        try {
            models = ModelCatalog.installed(getApplicationContext());
        } catch (Exception e) {
            models = new ArrayList<>();
            viewModel.disableScanning("Thiếu model trong assets/models: " + e.getMessage());
            return;
        }
        List<String> titles = new ArrayList<>();
        for (ModelCatalog.Choice item : models) titles.add(item.title);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, titles);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        modelSpinner.setAdapter(adapter);

        String previous = getPreferences(MODE_PRIVATE).getString(PREF_MODEL_ID, "gru128_fp32");
        for (int i = 0; i < models.size(); i++) {
            if (models.get(i).id.equals(previous)) {
                modelSpinner.setSelection(i);
                break;
            }
        }
        modelSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position >= 0 && position < models.size()) {
                    getPreferences(MODE_PRIVATE).edit()
                            .putString(PREF_MODEL_ID, models.get(position).id).apply();
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) { }
        });
    }

    private ModelCatalog.Choice selectedModel() {
        int position = modelSpinner.getSelectedItemPosition();
        if (position < 0 || position >= models.size()) {
            Toast.makeText(this, "Chưa có model AI phù hợp.", Toast.LENGTH_LONG).show();
            return null;
        }
        return models.get(position);
    }

    private String displayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (index >= 0 && cursor.getString(index) != null) return cursor.getString(index);
            }
        } catch (Exception ignored) {
            // file:// URIs and some providers have no metadata
        }
        String last = uri.getLastPathSegment();
        return last == null ? "Unknown.apk" : last.substring(last.lastIndexOf('/') + 1);
    }
}
