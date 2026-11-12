package com.example.mobitive.history;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Local, app-private history. No raw APK, vector, or credentials stored here. */
public final class ScanHistory {
    private static final String PREFS = "m4_scan_history_v1"; // name kept: existing installs keep their history
    private static final String KEY = "records";
    private static final int MAX_RECORDS = 60;
    private ScanHistory() {}

    public static final class Record {
        public final long epochMs;
        public final String fileName, modelId, label, cacheMode;
        public final double malwareProbability, totalMs;
        private Record(JSONObject json) {
            epochMs = json.optLong("time", 0L);
            fileName = json.optString("file", "unknown.apk");
            modelId = json.optString("model", "gru128_fp32");
            label = json.optString("label", "UNKNOWN");
            cacheMode = json.optString("cache", "UNKNOWN");
            malwareProbability = json.optDouble("malware", 0);
            totalMs = json.optDouble("total_ms", 0);
        }
    }

    public static synchronized void append(Context ctx, String fileName, String modelId,
                                           String label, String cacheMode,
                                           float malwareProbability, double totalMs) throws JSONException {
        SharedPreferences prefs = ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        JSONArray before = readJson(prefs);
        JSONArray after = new JSONArray();
        JSONObject record = new JSONObject();
        record.put("time", System.currentTimeMillis());
        record.put("file", safeName(fileName));
        record.put("model", modelId);
        record.put("label", label);
        record.put("cache", cacheMode);
        record.put("malware", (double) malwareProbability);
        record.put("total_ms", totalMs);
        after.put(record);
        for (int i = 0; i < before.length() && after.length() < MAX_RECORDS; i++) {
            JSONObject item = before.optJSONObject(i);
            if (item != null) after.put(item);
        }
        if (!prefs.edit().putString(KEY, after.toString()).commit()) {
            throw new IllegalStateException("Unable to save scan history.");
        }
    }

    public static synchronized List<Record> read(Context ctx) {
        SharedPreferences prefs = ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        JSONArray array = readJson(prefs);
        List<Record> records = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            JSONObject json = array.optJSONObject(i);
            if (json != null) records.add(new Record(json));
        }
        return Collections.unmodifiableList(records);
    }

    public static synchronized void clear(Context ctx) {
        ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().remove(KEY).apply();
    }

    private static JSONArray readJson(SharedPreferences prefs) {
        try { return new JSONArray(prefs.getString(KEY, "[]")); }
        catch (JSONException e) { return new JSONArray(); }
    }

    private static String safeName(String input) {
        if (input == null || input.isEmpty()) return "unknown.apk";
        // Do not store document-provider URI or paths, only name.
        String name = input.replace('\\', '/');
        int slash = name.lastIndexOf('/');
        if (slash >= 0) name = name.substring(slash + 1);
        return name.length() > 140 ? name.substring(0, 140) : name;
    }
}
