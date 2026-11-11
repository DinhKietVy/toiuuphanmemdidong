
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

public class MainActivity extends AppCompatActivity {

    private static final String BRIDGE_HOST = "127.0.0.1";
    private static final int BRIDGE_PORT = 8765;

    private TextView txtEngineStatus;
    private TextView txtEventCount;
    private TextView txtExecveCount;
    private TextView txtEvents;

    private Button btnStart;
    private Button btnStop;

    private final ScheduledExecutorService executor =
            Executors.newSingleThreadScheduledExecutor();

    private final Set<String> seenEvents = new HashSet<>();
    private final ArrayDeque<String> displayedEvents = new ArrayDeque<>();

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

        btnStart.setOnClickListener(v -> startEngine());
        btnStop.setOnClickListener(v -> stopEngine());

        // Kiểm tra engine và cảnh báo mỗi 2 giây.
        executor.scheduleWithFixedDelay(
                this::refreshDashboard,
                0,
                2,
                TimeUnit.SECONDS
        );
    }

    private void startEngine() {
        btnStart.setEnabled(false);

        executor.execute(() -> {
            try {
                String response = sendCommand("START");
                String status = sendCommand("STATUS");

                runOnUiThread(() -> {
                    txtEngineStatus.setText(
                            response + "\n" + status
                    );
                    btnStart.setEnabled(true);
                });

                refreshDashboard();

            } catch (Exception e) {
                showError("START", e);
            } finally {
                runOnUiThread(() -> btnStart.setEnabled(true));
            }
        });
    }

    private void stopEngine() {
        btnStop.setEnabled(false);

        executor.execute(() -> {
            try {
                String response = sendCommand("STOP");

                runOnUiThread(() -> {
                    txtEngineStatus.setText(response);
                    btnStop.setEnabled(true);
                });

                refreshDashboard();

            } catch (Exception e) {
                showError("STOP", e);
            } finally {
                runOnUiThread(() -> btnStop.setEnabled(true));
            }
        });
    }

    private void refreshDashboard() {
        if (activityDestroyed) {
            return;
        }

        try {
            String status = sendCommand("STATUS");

            runOnUiThread(() -> {
                if (status.startsWith("RUNNING:")) {
                    String pid = status.substring("RUNNING:".length()).trim();
                    txtEngineStatus.setText("ENGINE RUNNING | PID: " + pid);
                    btnStart.setEnabled(true);
                    btnStop.setEnabled(true);
                } else {
                    txtEngineStatus.setText("ENGINE STOPPED");
                    btnStart.setEnabled(true);
                    btnStop.setEnabled(false);
                }
            });

            // Đọc cảnh báo kể cả khi engine vừa STOP.
            String logs = sendCommand("LOGS");
            updateLogView(logs);

        } catch (Exception e) {
            runOnUiThread(() -> {
                txtEngineStatus.setText(
                        "BRIDGE DISCONNECTED\n" + e.getMessage()
                );
                btnStart.setEnabled(true);
                btnStop.setEnabled(true);
            });
        }
    }

    private String sendCommand(String command) throws IOException {
        StringBuilder response = new StringBuilder();

        try (Socket socket = new Socket()) {
            socket.connect(
                    new InetSocketAddress(BRIDGE_HOST, BRIDGE_PORT),
                    3000
            );

            socket.setSoTimeout(6000);

            try (
                    PrintWriter writer = new PrintWriter(
                            new OutputStreamWriter(
                                    socket.getOutputStream(),
                                    StandardCharsets.UTF_8
                            ),
                            true
                    );

                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(
                                    socket.getInputStream(),
                                    StandardCharsets.UTF_8
                            )
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

    private void updateLogView(String logs) {
        if (activityDestroyed || logs == null || logs.isEmpty()) {
            return;
        }

        String[] lines = logs.split("\\r?\\n");

        for (String line : lines) {
            line = line.trim();

            // Chỉ nhận cảnh báo Dropper Detection.
            if (!line.startsWith("BPFROID_DROPPER_ALERT")) {
                continue;
            }

            if (seenEvents.add(line)) {
                displayedEvents.addLast(line);

                while (displayedEvents.size() > 30) {
                    displayedEvents.removeFirst();
                }
            }
        }

        int elfCount = 0;
        int zipCount = 0;
        int dexCount = 0;

        for (String event : seenEvents) {
            if (event.contains("type=ELF")) {
                elfCount++;
            } else if (event.contains("type=ZIP/APK")) {
                zipCount++;
            } else if (event.contains("type=DEX")) {
                dexCount++;
            }
        }

        StringBuilder output = new StringBuilder();

        for (String event : displayedEvents) {
            output.append(event).append('\n').append('\n');
        }

        final int total = seenEvents.size();
        final int finalElfCount = elfCount;
        final int finalZipCount = zipCount;
        final int finalDexCount = dexCount;
        final String finalOutput = output.toString();

        runOnUiThread(() -> {
            txtEventCount.setText("Total alerts: " + total);

            txtExecveCount.setText(
                    "Payloads: ELF " + finalElfCount
                            + " | ZIP/APK " + finalZipCount
                            + " | DEX " + finalDexCount
            );

            txtEvents.setText(
                    finalOutput.isEmpty()
                            ? "No dropper alerts detected."
                            : finalOutput
            );
        });
    }

    private void showError(String action, Exception e) {
        runOnUiThread(() -> {
            txtEngineStatus.setText(
                    action + " ERROR: " + e.getMessage()
            );
        });
    }

    @Override
    protected void onDestroy() {
        activityDestroyed = true;
        executor.shutdownNow();
        super.onDestroy();
    }
}
