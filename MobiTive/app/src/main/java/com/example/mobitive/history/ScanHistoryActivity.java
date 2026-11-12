package com.example.mobitive.history;

import android.app.AlertDialog;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** Read-only on-device history; scan benchmark CSV remains separately exportable. */
public final class ScanHistoryActivity extends AppCompatActivity {
    private LinearLayout list;
    private TextView count;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(com.example.mobitive.R.layout.activity_m4_history);
        list = findViewById(com.example.mobitive.R.id.m4HistoryList);
        count = findViewById(com.example.mobitive.R.id.m4HistoryCount);
        findViewById(com.example.mobitive.R.id.m4Back).setOnClickListener(v -> finish());
        findViewById(com.example.mobitive.R.id.m4ClearHistory).setOnClickListener(v ->
                new AlertDialog.Builder(this)
                        .setTitle("Xóa lịch sử quét?")
                        .setMessage("Chỉ xóa lịch sử quét trên máy; file benchmark CSV được giữ nguyên.")
                        .setNegativeButton("Hủy", null)
                        .setPositiveButton("Xóa", (d, which) -> {
                            ScanHistory.clear(this);
                            render();
                        }).show());
        render();
    }

    private TextView line(String text, int sizeSp, boolean bold, int color) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(sizeSp);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private void render() {
        list.removeAllViews();
        List<ScanHistory.Record> records = ScanHistory.read(this);
        count.setText(records.size() + " lượt quét gần nhất · Lưu nội bộ, tối đa 60 lượt");
        if (records.isEmpty()) {
            TextView empty = line("Chưa có lịch sử. Quét một APK từ màn hình chính để bắt đầu.",
                    15, false, Color.rgb(104, 119, 143));
            empty.setPadding(0, 24, 0, 24);
            list.addView(empty);
            return;
        }
        SimpleDateFormat fmt = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.getDefault());
        for (ScanHistory.Record record : records) {
            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setPadding(dp(16), dp(14), dp(16), dp(14));
            card.setBackgroundResource(com.example.mobitive.R.drawable.m4_card_bg);
            LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            cardParams.bottomMargin = dp(12);
            list.addView(card, cardParams);

            card.addView(line(record.fileName, 16, true, Color.rgb(20, 39, 70)));
            TextView status = line(record.label + "  ·  " + record.modelId + "  ·  " + record.cacheMode,
                    13, true, "MALWARE".equals(record.label) ? Color.rgb(182, 51, 63) : Color.rgb(20, 123, 100));
            status.setPadding(0, dp(6), 0, dp(3));
            card.addView(status);
            String detail = String.format(Locale.US, "Malware: %.2f%%   ·   Tổng: %.2f s",
                    record.malwareProbability * 100d, record.totalMs / 1000d);
            card.addView(line(detail, 13, false, Color.rgb(72, 88, 112)));
            TextView time = line(fmt.format(new Date(record.epochMs)), 12, false, Color.rgb(120, 133, 152));
            time.setPadding(0, dp(5), 0, 0);
            card.addView(time);
        }
    }
    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }
}
