"""
M7/M8 — đo MobiTive trên điện thoại thật bằng 1 lệnh.

Làm lần lượt cho từng máy đang cắm USB (hoặc --serial):
  1. build app + test APK (bỏ qua bằng --skip-build)
  2. cài app-debug.apk và app-debug-androidTest.apk
  3. đẩy bộ APK benchmark (MobiTiveAI/data/bench_apks) lên
     /sdcard/Android/data/com.example.mobitive/files/bench/  (chỉ đẩy file thay đổi)
  4. giữ màn hình sáng khi cắm USB, ghi trạng thái pin trước/sau
  5. chạy DeviceScanBenchmark (quét APK) + AccelBenchmark (quantization × CPU/GPU/NNAPI)
  6. kéo CSV/JSON + logcat về MobiTive/device_results/<máy>/<runId>/

Usage (PowerShell, tại thư mục MobiTive):
    python tools\\run_device_benchmark.py
    python tools\\run_device_benchmark.py --repeats 5 --models all
    python tools\\run_device_benchmark.py --serial R58M123ABC --skip-build
Yêu cầu: Python 3, Android SDK (adb), máy đã bật "Gỡ lỗi USB".
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT = Path(__file__).resolve().parents[1]                  # MobiTive/
REPO = PROJECT.parent
DEFAULT_APK_DIR = REPO / "MobiTiveAI" / "data" / "bench_apks"
RESULTS_ROOT = PROJECT / "device_results"

APP_ID = "com.example.mobitive"
TEST_ID = APP_ID + ".test"
RUNNER = TEST_ID + "/androidx.test.runner.AndroidJUnitRunner"
SCAN_CLASS = APP_ID + ".DeviceScanBenchmark"
ACCEL_CLASS = APP_ID + ".AccelBenchmark"
REMOTE_BASE = f"/sdcard/Android/data/{APP_ID}/files"
APP_APK = PROJECT / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
TEST_APK = PROJECT / "app" / "build" / "outputs" / "apk" / "androidTest" / "debug" / "app-debug-androidTest.apk"


# ------------------------------------------------------------------ helpers

def find_adb():
    exe = "adb.exe" if os.name == "nt" else "adb"
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")]
    local_props = PROJECT / "local.properties"
    if local_props.exists():
        for line in local_props.read_text(encoding="utf-8").splitlines():
            if line.startswith("sdk.dir="):
                roots.append(line.split("=", 1)[1].replace("\\:", ":").replace("\\\\", "\\"))
    if os.environ.get("LOCALAPPDATA"):
        roots.append(os.path.join(os.environ["LOCALAPPDATA"], "Android", "Sdk"))
    for root in roots:
        if root and (Path(root) / "platform-tools" / exe).exists():
            return str(Path(root) / "platform-tools" / exe)
    found = shutil.which("adb")
    if found:
        return found
    sys.exit("Không tìm thấy adb. Cài Android SDK Platform-Tools hoặc đặt ANDROID_HOME.")


def run(cmd, check=True, capture=True):
    result = subprocess.run(cmd, capture_output=capture, text=True,
                            encoding="utf-8", errors="replace")
    if check and result.returncode != 0:
        sys.exit(f"Lệnh lỗi ({result.returncode}): {' '.join(map(str, cmd))}\n"
                 f"{result.stdout}\n{result.stderr}")
    return result.stdout.strip() if capture else ""


class Device:
    def __init__(self, adb, serial):
        self.adb, self.serial = adb, serial

    def cmd(self, *args, check=True):
        return run([self.adb, "-s", self.serial, *args], check=check)

    def shell(self, *args, check=True):
        return self.cmd("shell", *args, check=check)

    def prop(self, name):
        return self.shell("getprop", name, check=False)

    @property
    def label(self):
        raw = f"{self.prop('ro.product.manufacturer')}_{self.prop('ro.product.model')}"
        return re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_")

    def is_emulator(self):
        return (self.prop("ro.kernel.qemu") == "1" or "generic" in self.prop("ro.build.fingerprint")
                or "Genymobile" in self.prop("ro.product.manufacturer"))


def connected_devices(adb):
    lines = run([adb, "devices"]).splitlines()[1:]
    ready, other = [], []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            (ready if parts[1] == "device" else other).append(parts)
    for serial, state in other:
        print(f"Bỏ qua {serial}: trạng thái '{state}' "
              f"(unauthorized = hãy bấm 'Cho phép gỡ lỗi USB' trên điện thoại).")
    return [p[0] for p in ready]


# ------------------------------------------------------------------ steps

def build():
    gradlew = PROJECT / ("gradlew.bat" if os.name == "nt" else "gradlew")
    print("==> Build app + test APK ...")
    subprocess.run([str(gradlew), ":app:assembleDebug", ":app:assembleDebugAndroidTest"],
                   cwd=PROJECT, check=True)


def install(dev):
    for apk in (APP_APK, TEST_APK):
        if not apk.exists():
            sys.exit(f"Chưa có {apk}. Chạy lại không dùng --skip-build.")
        print(f"==> Cài {apk.name}")
        dev.cmd("install", "-r", "-t", str(apk))


def push_apks(dev, apk_dir):
    local = sorted(apk_dir.glob("*.apk"))
    if not local:
        sys.exit(f"Không có APK trong {apk_dir}. Chạy trước: "
                 f"python MobiTiveAI\\scripts\\prepare_benchmark_apks.py")
    remote_dir = f"{REMOTE_BASE}/bench"
    dev.shell("mkdir", "-p", remote_dir, f"{REMOTE_BASE}/results")
    dev.shell("rm", "-f", f"{REMOTE_BASE}/results/*", check=False)

    remote = {}
    listing = dev.shell("ls", "-l", remote_dir, check=False)
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[-1].endswith(".apk"):
            remote[parts[-1]] = int(parts[4]) if parts[4].isdigit() else -1
    wanted = {p.name for p in local}
    for name in remote:
        if name not in wanted:
            dev.shell("rm", "-f", f"{remote_dir}/{name}", check=False)

    total = sum(p.stat().st_size for p in local) / 1e6
    print(f"==> Đẩy {len(local)} APK ({total:.0f} MB) lên {remote_dir}")
    for p in local:
        if remote.get(p.name) == p.stat().st_size:
            continue
        print(f"    {p.name}")
        dev.cmd("push", str(p), f"{remote_dir}/{p.name}")


def run_benchmark(dev, args, run_id):
    extra = ["-e", "repeats", str(args.repeats), "-e", "warmup", str(args.warmup),
             "-e", "hitRepeats", str(args.hit_repeats), "-e", "models", args.models,
             "-e", "cooldownMs", str(args.cooldown_ms),
             "-e", "modelBench", "true" if args.model_bench else "false",
             "-e", "backends", args.backends, "-e", "accelPasses", str(args.accel_passes),
             "-e", "runId", run_id]
    classes = [c for c, on in ((SCAN_CLASS, not args.no_scan), (ACCEL_CLASS, not args.no_accel)) if on]
    if not classes:
        sys.exit("--no-scan và --no-accel cùng lúc thì không còn gì để đo.")
    cmd = [dev.adb, "-s", dev.serial, "shell", "am", "instrument", "-w", "-r",
           *extra, "-e", "class", ",".join(classes), RUNNER]
    print("==> Chạy benchmark (có thể mất vài phút, đừng rút cáp) ...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    transcript = []
    in_stream = False  # multi-line values continue on lines without the prefix
    for line in proc.stdout:
        transcript.append(line)
        if line.startswith("INSTRUMENTATION_STATUS: stream="):
            in_stream = True
            text = line.split("=", 1)[1].rstrip()
            if text:
                print("    " + text)
        elif line.startswith("INSTRUMENTATION_"):
            in_stream = False
        elif in_stream and line.strip():
            print("    " + line.rstrip())
        if "FAILURES!!!" in line or "Process crashed" in line:
            print("    " + line.rstrip())
    proc.wait()
    output = "".join(transcript)
    ok = re.search(r"^OK \(\d+ tests?\)", output, re.MULTILINE) is not None and "FAILURES!!!" not in output
    return ok, output


def pull_results(dev, run_id, transcript):
    out_dir = RESULTS_ROOT / dev.label / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    dev.cmd("pull", f"{REMOTE_BASE}/results/.", str(out_dir))
    (out_dir / "instrumentation_output.txt").write_text(transcript, encoding="utf-8")
    log = dev.cmd("logcat", "-d", "-s", "MobiTiveHarness:I", "MobiTiveDexProfile:I", "MobiTiveAccel:I", "tflite:*", check=False)
    (out_dir / "logcat.txt").write_text(log, encoding="utf-8")
    return out_dir


def battery(dev):
    text = dev.shell("dumpsys", "battery", check=False)
    values = dict(re.findall(r"^\s*(level|temperature|voltage|AC powered|USB powered): (\S+)",
                             text, re.MULTILINE))
    return values


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(description="MobiTive on-device benchmark")
    parser.add_argument("--serial", help="chỉ chạy trên máy này (xem 'adb devices')")
    parser.add_argument("--apk-dir", type=Path, default=DEFAULT_APK_DIR)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--hit-repeats", type=int, default=3)
    parser.add_argument("--models", default="gru128_fp32",
                        help="gru128_fp32,mlp64_fp32,... hoặc 'all'")
    parser.add_argument("--cooldown-ms", type=int, default=1000)
    parser.add_argument("--model-bench", action="store_true",
                        help="chạy thêm AI benchmark cũ của nút trong app (đã có AccelBenchmark thay thế)")
    parser.add_argument("--no-scan", action="store_true", help="bỏ phần quét APK (M7)")
    parser.add_argument("--no-accel", action="store_true", help="bỏ phần quantization × backend (M8)")
    parser.add_argument("--backends", default="all",
                        help="cpu1,cpu2,cpu4,cpu1_noxnnpack,gpu_fp32,gpu_fp16,nnapi hoặc 'all'")
    parser.add_argument("--accel-passes", type=int, default=3,
                        help="số lượt chạy hết 112 mẫu test cho mỗi cặp model × backend")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    adb = find_adb()
    serials = [args.serial] if args.serial else connected_devices(adb)
    if not serials:
        sys.exit("Không thấy thiết bị nào. Cắm điện thoại, bật 'Gỡ lỗi USB', chạy 'adb devices'.")

    if not args.skip_build:
        build()

    summary = []
    for serial in serials:
        dev = Device(adb, serial)
        print(f"\n######## {dev.label} ({serial}) ########")
        if dev.is_emulator():
            print("CẢNH BÁO: đây là máy ảo — số liệu không đại diện cho điện thoại thật.")
        install(dev)
        push_apks(dev, args.apk_dir)

        run_id = time.strftime("%Y%m%d_%H%M%S")
        dev.cmd("logcat", "-c", check=False)
        dev.shell("svc", "power", "stayon", "usb", check=False)
        before = battery(dev)
        started = time.time()
        try:
            ok, transcript = run_benchmark(dev, args, run_id)
        finally:
            dev.shell("svc", "power", "stayon", "false", check=False)
        after = battery(dev)
        minutes = (time.time() - started) / 60

        out_dir = pull_results(dev, run_id, transcript)
        (out_dir / "battery.txt").write_text(
            f"before={before}\nafter={after}\nminutes={minutes:.1f}\n", encoding="utf-8")
        status = "OK" if ok else "LỖI (xem instrumentation_output.txt)"
        print(f"==> {status} — {minutes:.1f} phút — kết quả: {out_dir}")
        if before.get("temperature") and after.get("temperature"):
            print(f"    Nhiệt độ pin: {int(before['temperature']) / 10:.1f} → "
                  f"{int(after['temperature']) / 10:.1f} °C")
        summary.append((dev.label, status, out_dir))

    print("\nTÓM TẮT")
    for label, status, out_dir in summary:
        print(f"  {label}: {status} -> {out_dir}")
    print("Phân tích: python MobiTiveAI\\scripts\\analyze_device_benchmarks.py")
    if any(s != "OK" for _, s, _ in summary):
        sys.exit(1)


if __name__ == "__main__":
    main()
