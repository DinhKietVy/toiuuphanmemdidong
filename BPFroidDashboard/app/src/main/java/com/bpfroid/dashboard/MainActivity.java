
package com.bpfroid.dashboard;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends AppCompatActivity {

    private static final String BRIDGE_HOST = "127.0.0.1";
    private static final int BRIDGE_PORT = 8765;

    private static final int POLL_TIMEOUT_MS = 6000;
    // STOP có thể chờ engine thoát và dọn kprobe tới vài giây.
    private static final int CONTROL_TIMEOUT_MS = 15000;

    private static final int MAX_DISPLAYED = 30;
    private static final Pattern ALERT_LINE =
            Pattern.compile("^(\\d+):(BPFROID_DROPPER_ALERT.*)$");
    private static final Pattern ALERT_TYPE = Pattern.compile("\\btype=(\\S+)");

    private TextView txtEngineStatus;
    private TextView txtEventCount;
    private TextView txtExecveCount;
    private TextView txtEvents;

    private Button btnStart;
    private Button btnStop;

    // Chỉ một luồng chạy, nên các trường trạng thái bên dưới không cần đồng bộ.
    private final ScheduledExecutorService executor =
            Executors.newSingleThreadScheduledExecutor();

    // Khóa "<run id>:<số dòng log>" định danh duy nhất một cảnh báo,
    // nên hai lần ghi giống hệt nhau vẫn được đếm riêng.
    private final Set<String> seenKeys = new HashSet<>();
    private final ArrayDeque<String> displayedEvents = new ArrayDeque<>();
    private int totalCount = 0;
    private int elfCount = 0;
    private int zipCount = 0;
    private int dexCount = 0;

    private volatile boolean activityDestroyed = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        txtEngineStatus = findViewById(R.id.txtEngineStatus);
        txtEventCount = findViewById(R.id.txtEventCount);
        txtExecveCount = findViewById(R.id.txtExecveCount);
        txtEvents = findViewById(R.id.txtEvents);

        btnStart = findViewById(R.id.btnStart);
        btnStop = findViewById(R.id.btnStop);

        txtEngineStatus.setText("Connecting to BPFroid bridge...");
        txtEventCount.setText("Total alerts: 0");
        txtExecveCount.setText("Payloads: ELF 0 | ZIP/APK 0 | DEX 0");
        txtEvents.setText("Waiting for dropper alerts...");

        btnStart.setOnClickListener(v -> runControl("START"));
        btnStop.setOnClickListener(v -> runControl("STOP"));

        // Kiểm tra engine và cảnh báo mỗi 2 giây (một kết nối POLL mỗi lần).
        executor.scheduleWithFixedDelay(this::refreshDashboard, 0, 2, TimeUnit.SECONDS);
    }

    private void runControl(String command) {
        setButtonsEnabled(false, false);
        txtEngineStatus.setText(command + "...");

        executor.execute(() -> {
            try {
                String response = sendCommand(command, CONTROL_TIMEOUT_MS);
                runOnUiThread(() -> txtEngineStatus.setText(response));
            } catch (Exception e) {
                runOnUiThread(() ->
                        txtEngineStatus.setText(command + " ERROR: " + e.getMessage()));
            }
            refreshDashboard();
        });
    }

    private void refreshDashboard() {
        if (activityDestroyed) {
            return;
        }

        String response;
        try {
            response = sendCommand("POLL", POLL_TIMEOUT_MS);
        } catch (Exception e) {
            runOnUiThread(() -> {
                txtEngineStatus.setText("BRIDGE DISCONNECTED\n" + e.getMessage());
                setButtonsEnabled(true, true);
            });
            return;
        }

        // Dòng 1: trạng thái; "RUN:<id>": mã lần chạy; còn lại: "<số dòng>:<cảnh báo>".
        String[] lines = response.split("\\r?\\n");
        String status = lines.length > 0 ? lines[0].trim() : "";
        String runId = "0";
        boolean changed = false;

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.startsWith("RUN:")) {
                runId = line.substring("RUN:".length());
                continue;
            }
            Matcher m = ALERT_LINE.matcher(line);
            if (m.matches() && seenKeys.add(runId + ":" + m.group(1))) {
                recordAlert(m.group(2));
                changed = true;
            }
        }

        final boolean running = status.startsWith("RUNNING:");
        final String statusText = running
                ? "ENGINE RUNNING | PID: " + status.substring("RUNNING:".length()).trim()
                : "ENGINE STOPPED";
        final boolean render = changed;
        final String events = render ? String.join("\n\n", displayedEvents) : null;
        final String total = "Total alerts: " + totalCount;
        final String counts = "Payloads: ELF " + elfCount
                + " | ZIP/APK " + zipCount
                + " | DEX " + dexCount;
        final boolean empty = totalCount == 0;

        runOnUiThread(() -> {
            txtEngineStatus.setText(statusText);
            setButtonsEnabled(true, running);
            if (render) {
                txtEventCount.setText(total);
                txtExecveCount.setText(counts);
                txtEvents.setText(events);
            } else if (empty) {
                txtEvents.setText("No dropper alerts detected.");
            }
        });
    }

    private void recordAlert(String alert) {
        totalCount++;

        Matcher type = ALERT_TYPE.matcher(alert);
        if (type.find()) {
            switch (type.group(1)) {
                case "ELF":
                    elfCount++;
                    break;
                case "ZIP/APK":
                    zipCount++;
                    break;
                case "DEX":
                    dexCount++;
                    break;
                default:
                    break;
            }
        }

        displayedEvents.addLast(alert);
        while (displayedEvents.size() > MAX_DISPLAYED) {
            displayedEvents.removeFirst();
        }
    }

    private void setButtonsEnabled(boolean start, boolean stop) {
        btnStart.setEnabled(start);
        btnStop.setEnabled(stop);
    }

    private String sendCommand(String command, int readTimeoutMs) throws IOException {
        StringBuilder response = new StringBuilder();

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(BRIDGE_HOST, BRIDGE_PORT), 3000);
            socket.setSoTimeout(readTimeoutMs);

            try (
                    PrintWriter writer = new PrintWriter(
                            new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8),
                            true
                    );
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)
                    )
            ) {
                writer.println(command);

                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line).append('\n');
                }
            }
        }

        return response.toString().trim();
    }

    @Override
    protected void onDestroy() {
        activityDestroyed = true;
        executor.shutdownNow();
        super.onDestroy();
    }
}
