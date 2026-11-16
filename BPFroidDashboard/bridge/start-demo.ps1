# Khởi động demo BPFroid sau khi bật (hoặc khởi động lại) máy ảo.
# Chạy từ thư mục gốc repo:  powershell -ExecutionPolicy Bypass -File BPFroidDashboard\bridge\start-demo.ps1
#
# Làm lần lượt: chọn đúng máy ảo Pixel_6 (bật nếu chưa chạy) -> adb root ->
# kiểm tra file engine -> bật bridge listener nếu chưa có -> START engine (kèm token) -> mở Dashboard.
# Chạy lại nhiều lần không sao: bước nào đã xong thì bỏ qua.

$ErrorActionPreference = "Continue"
$Avd = "Pixel_6"
$Base = "/data/local/tmp"
$TokenPath = "/data/user/0/com.bpfroid.dashboard/files/bridge.token"
$EmulatorExe = Join-Path $env:LOCALAPPDATA "Android\Sdk\emulator\emulator.exe"

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "LOI: $msg" -ForegroundColor Red; exit 1 }

function Find-Device {
    foreach ($line in (adb devices)) {
        if ($line -match '^(emulator-\d+)\s+device$') {
            $serial = $Matches[1]
            $name = (adb -s $serial emu avd name | Select-Object -First 1).Trim()
            if ($name -eq $Avd) { return $serial }
        }
    }
    return $null
}

# 1. Máy ảo Pixel_6 (máy duy nhất có engine BPFroid)
Step "Tim may ao $Avd"
$dev = Find-Device
if (-not $dev) {
    if (-not (Test-Path $EmulatorExe)) { Fail "khong tim thay $EmulatorExe" }
    Step "Chua chay -> bat $Avd"
    Start-Process -FilePath $EmulatorExe -ArgumentList "-avd", $Avd -WindowStyle Minimized
    for ($i = 0; $i -lt 60 -and -not $dev; $i++) { Start-Sleep -Seconds 3; $dev = Find-Device }
    if (-not $dev) { Fail "$Avd khong khoi dong duoc" }
}
for ($i = 0; $i -lt 90; $i++) {
    if ((adb -s $dev shell getprop sys.boot_completed) -match '1') { break }
    Start-Sleep -Seconds 2
}
Write-Host "    $Avd = $dev"

# 2. Root (mất sau mỗi lần khởi động lại máy ảo)
Step "adb root"
if ((adb -s $dev shell id -u).Trim() -ne "0") {
    adb -s $dev root | Out-Null
    Start-Sleep -Seconds 3
    adb -s $dev wait-for-device
    if ((adb -s $dev shell id -u).Trim() -ne "0") { Fail "khong lay duoc quyen root" }
}

# 3. File engine + bridge handler đúng bản trong repo (snapshot máy ảo có thể còn bản cũ)
Step "Dong bo bridge handler tu repo"
$handler = Join-Path $PSScriptRoot "bpfroid-bridge-handler.sh"
adb -s $dev push $handler "$Base/bpfroid-bridge-handler.sh" | Out-Null
adb -s $dev shell "sed -i 's/\r$//' $Base/bpfroid-bridge-handler.sh; chmod 755 $Base/bpfroid-bridge-handler.sh"

Step "Kiem tra file engine"
foreach ($f in "tracee-android", "tracee.bpf.dev.o", "bpfroid-bridge-handler.sh") {
    $r = adb -s $dev shell "[ -f $Base/$f ] && echo ok"
    if ($r -ne "ok") { Fail "thieu $Base/$f tren $dev (xem README muc 2)" }
}

# 4. Bridge listener (là tiến trình nền, mất sau mỗi lần khởi động lại)
Step "Bridge listener"
$status = adb -s $dev shell "echo STATUS | toybox nc -w 3 127.0.0.1 8765"
if (-not $status) {
    adb -s $dev shell "nohup toybox nc -s 127.0.0.1 -p 8765 -L /system/bin/sh $Base/bpfroid-bridge-handler.sh >$Base/bpfroid-bridge.log 2>&1 </dev/null &"
    Start-Sleep -Seconds 2
    $status = adb -s $dev shell "echo STATUS | toybox nc -w 3 127.0.0.1 8765"
    if (-not $status) { Fail "bridge khong phan hoi" }
}
Write-Host "    STATUS: $status"

# 5. Engine: cần token do app Dashboard sinh khi mở lần đầu
Step "Mo Dashboard va START engine"
adb -s $dev shell "am start -n com.bpfroid.dashboard/.MainActivity" | Out-Null
Start-Sleep -Seconds 3
if ($status -notlike "RUNNING*") {
    $token = (adb -s $dev shell "cat $TokenPath 2>/dev/null").Trim()
    if (-not $token) { Fail "chua co token: mo app BPFroid Dashboard mot lan roi chay lai script" }
    $r = adb -s $dev shell "echo START $token | toybox nc -w 15 127.0.0.1 8765"
    Write-Host "    $r"
    if ($r -notlike "OK:RUNNING*") { Fail "engine khong START duoc, xem: adb -s $dev shell tail -n 40 $Base/bpfroid-engine.log" }
}

Step "Xong. Dashboard dang mo tren $dev."
