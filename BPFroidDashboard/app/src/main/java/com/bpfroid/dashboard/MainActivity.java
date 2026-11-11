
package com.bpfroid.dashboard;

import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends AppCompatActivity {

    private static final String BRIDGE_HOST = "127.0.0.1";
    private static final int BRIDGE_PORT = 8765;

    private static final int POLL_TIMEOUT_MS = 6000;
    // STOP có thể chờ engine thoát và dọn kprobe tới vài giây.
    private static final int CONTROL_TIMEOUT_MS = 15000;

    // Chu kỳ poll: dày khi engine chạy, thưa khi engine dừng hoặc mất kết nối bridge.
    private static final long POLL_RUNNING_SEC = 2;
    private static final long POLL_IDLE_SEC = 10;
    // Bridge trả tối đa chừng này cảnh báo mỗi lần POLL (POLL_BATCH trong bridge handler);
    // nhận đủ số này nghĩa là còn cảnh báo chưa lấy, nên POLL tiếp ngay.
    private static final int POLL_BATCH = 500;
    private static final int MAX_CATCH_UP_ROUNDS = 20;

    // Token điều khiển: chỉ app này (và bridge chạy root) đọc được file trong filesDir.
    private static final String TOKEN_FILE = "bridge.token";

    private static final int MAX_DISPLAYED = 30;
    private static final Pattern ALERT_LINE =
            Pattern.compile("^(\\d+):(BPFROID_[A-Z]+_ALERT .*)$");
    private static final String PRIVESC_PREFIX = "BPFROID_PRIVESC_ALERT";
    // Engine: "BPFROID_PRIVESC_ALERT prev_uid=.. uid=.. pid=.. tid=.. comm=.."
    private static final Pattern PRIVESC_FIELDS = Pattern.compile(
            "prev_uid=(\\d+) uid=(\\d+) pid=(\\d+) tid=\\d+ comm=(\\S*)");
    // Engine: "BPFROID_DROPPER_ALERT type=.. uid=.. pid=.. comm=.. dev=.. inode=.. path=.."
    private static final Pattern ALERT_FIELDS = Pattern.compile(
            "type=(\\S+) uid=(\\d+) pid=(\\d+) comm=(\\S*) .*?path=(.*)$");
    private static final Pattern ALERT_TYPE = Pattern.compile("\\btype=(\\S+)");
    private static final int FIRST_APP_UID = 10000;

    private final Map<Integer, String> uidLabels = new HashMap<>();

    private TextView txtEngineStatus;
    private TextView txtEventCount;
    private TextView txtExecveCount;
    private TextView txtEvents;

    private Button btnStart;
    private Button btnStop;

    // Chỉ một luồng chạy, nên các trường trạng thái bên dưới không cần đồng bộ.
    private final ScheduledExecutorService executor =
            Executors.newSingleThreadScheduledExecutor();

    // Vị trí đã đọc trong file cảnh báo của bridge: lần chạy engine (run id) + số dòng cuối.
    // POLL chỉ xin phần sau vị trí này, nên không sót cảnh báo và không tải lại phần cũ.
    private String trackedRunId = null;
    private int lastLine = 0;
    private String token = null;

    // Poll chỉ chạy khi Activity đang hiển thị (onStart..onStop).
    private volatile boolean polling = false;
    private ScheduledFuture<?> pollTask = null;

    private final ArrayDeque<String> displayedEvents = new ArrayDeque<>();
    private int totalCount = 0;
    private int elfCount = 0;
    private int zipCount = 0;
    private int dexCount = 0;
    private int privescCount = 0;

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
        txtEvents.setText("Waiting for security alerts...");

        btnStart.setOnClickListener(v -> runControl("START"));
        btnStop.setOnClickListener(v -> runControl("STOP"));

        executor.execute(this::loadOrCreateToken);
    }

    @Override
    protected void onStart() {
        super.onStart();
        // App hiện lên: poll ngay rồi lặp lại theo chu kỳ.
        polling = true;
        executor.execute(() -> {
            cancelPollTask();
            pollLoop();
        });
    }

    @Override
    protected void onStop() {
        // App vào nền: dừng poll, không mở socket nào nữa cho tới khi app hiện lại.
        polling = false;
        executor.execute(this::cancelPollTask);
        super.onStop();
    }

    /** Chạy trên executor: poll một lần rồi tự hẹn lần sau, nhịp tùy trạng thái engine. */
    private void pollLoop() {
        if (!polling || activityDestroyed) {
            return;
        }
        boolean running = refreshDashboard();
        if (polling && !activityDestroyed) {
            long delay = running ? POLL_RUNNING_SEC : POLL_IDLE_SEC;
            pollTask = executor.schedule(this::pollLoop, delay, TimeUnit.SECONDS);
        }
    }

    private void cancelPollTask() {
        if (pollTask != null) {
            pollTask.cancel(false);
            pollTask = null;
        }
    }

    private void loadOrCreateToken() {
        File file = new File(getFilesDir(), TOKEN_FILE);
        try {
            if (file.exists()) {
                byte[] data = Files.readAllBytes(file.toPath());
                String existing = new String(data, StandardCharsets.UTF_8).trim();
                if (existing.matches("[0-9a-f]{64}")) {
                    token = existing;
                    return;
                }
            }
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            StringBuilder hex = new StringBuilder();
            for (byte b : random) {
                hex.append(String.format("%02x", b));
            }
            try (FileOutputStream out = openFileOutput(TOKEN_FILE, MODE_PRIVATE)) {
                out.write(hex.toString().getBytes(StandardCharsets.UTF_8));
            }
            token = hex.toString();
        } catch (IOException e) {
            token = null;
        }
    }

    private void runControl(String command) {
        setButtonsEnabled(false, false);
        txtEngineStatus.setText(command + "...");

        executor.execute(() -> {
            if (token == null) {
                loadOrCreateToken();
            }
            try {
                String response = token == null
                        ? "ERROR: cannot create bridge token"
                        : sendCommand(command + " " + token, CONTROL_TIMEOUT_MS);
                runOnUiThread(() -> txtEngineStatus.setText(response));
            } catch (Exception e) {
                runOnUiThread(() ->
                        txtEngineStatus.setText(command + " ERROR: " + e.getMessage()));
            }
            refreshDashboard();
        });
    }

    /** Chạy trên executor. Trả về true nếu engine đang chạy. */
    private boolean refreshDashboard() {
        if (activityDestroyed) {
            return false;
        }

        String status = "";
        boolean changed = false;

        // Lấy hết phần cảnh báo mới; mỗi vòng bridge trả tối đa POLL_BATCH dòng.
        for (int round = 0; round < MAX_CATCH_UP_ROUNDS; round++) {
            String request = trackedRunId == null
                    ? "POLL"
                    : "POLL " + trackedRunId + " " + lastLine;
            String response;
            try {
                response = sendCommand(request, POLL_TIMEOUT_MS);
            } catch (Exception e) {
                runOnUiThread(() -> {
                    txtEngineStatus.setText("BRIDGE DISCONNECTED\n" + e.getMessage());
                    setButtonsEnabled(true, true);
                });
                return false;
            }

            // Dòng 1: trạng thái; "RUN:<id>": mã lần chạy; còn lại: "<số dòng>:<cảnh báo>".
            String[] lines = response.split("\\r?\\n");
            status = lines.length > 0 ? lines[0].trim() : "";
            int received = 0;

            for (int i = 1; i < lines.length; i++) {
                String line = lines[i].trim();
                if (line.startsWith("RUN:")) {
                    String runId = line.substring("RUN:".length());
                    if (!runId.equals(trackedRunId)) {
                        // Engine vừa START lại: file cảnh báo mới, đọc lại từ dòng 1.
                        // Số đếm trên màn hình vẫn cộng dồn.
                        trackedRunId = runId;
                        lastLine = 0;
                    }
                    continue;
                }
                Matcher m = ALERT_LINE.matcher(line);
                if (!m.matches()) {
                    continue;
                }
                received++;
                int lineNo = Integer.parseInt(m.group(1));
                if (lineNo > lastLine) {
                    lastLine = lineNo;
                    recordAlert(m.group(2));
                    changed = true;
                }
            }

            if (received < POLL_BATCH) {
                break;
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
                + " | DEX " + dexCount
                + "\nPrivilege escalation: " + privescCount;
        final boolean empty = totalCount == 0;

        runOnUiThread(() -> {
            txtEngineStatus.setText(statusText);
            setButtonsEnabled(true, running);
            if (render) {
                txtEventCount.setText(total);
                txtExecveCount.setText(counts);
                txtEvents.setText(events);
            } else if (empty) {
                txtEvents.setText("No security alerts detected.");
            }
        });
        return running;
    }

    private void recordAlert(String alert) {
        totalCount++;

        if (alert.startsWith(PRIVESC_PREFIX)) {
            privescCount++;
            addDisplayed(formatPrivEsc(alert));
            return;
        }

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

        addDisplayed(formatAlert(alert));
    }

    private void addDisplayed(String text) {
        displayedEvents.addLast(text);
        while (displayedEvents.size() > MAX_DISPLAYED) {
            displayedEvents.removeFirst();
        }
    }

    /** "[PRIVESC] shell (uid 2000) → root (uid 0)\n  pid 4567 · su" */
    private String formatPrivEsc(String alert) {
        Matcher m = PRIVESC_FIELDS.matcher(alert);
        if (!m.find()) {
            return alert;
        }
        int prev = Integer.parseInt(m.group(1));
        int cur = Integer.parseInt(m.group(2));
        return "[PRIVESC] " + labelForUid(prev) + " (uid " + prev + ") → "
                + labelForUid(cur) + " (uid " + cur + ")"
                + "\n  pid " + m.group(3) + " · " + m.group(4);
    }

    /** "[DEX] com.example.app (uid 10123)\n  pid 4567 · printf\n  /data/user/0/.../x.dex" */
    private String formatAlert(String alert) {
        Matcher m = ALERT_FIELDS.matcher(alert);
        if (!m.find()) {
            return alert;
        }
        int uid = Integer.parseInt(m.group(2));
        return "[" + m.group(1) + "] " + labelForUid(uid) + " (uid " + uid + ")"
                + "\n  pid " + m.group(3) + " · " + m.group(4)
                + "\n  " + m.group(5);
    }

    private String labelForUid(int uid) {
        String cached = uidLabels.get(uid);
        if (cached != null) {
            return cached;
        }
        String label;
        if (uid == 0) {
            label = "root";
        } else {
            PackageManager pm = getPackageManager();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages != null && packages.length == 1) {
                label = packages[0];
            } else {
                // Không có package, hoặc shared UID nhiều package (vd. 1000) -> tên shared UID.
                String name = pm.getNameForUid(uid);
                label = name != null ? name : (uid < FIRST_APP_UID ? "system" : "unknown app");
            }
        }
        uidLabels.put(uid, label);
        return label;
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
