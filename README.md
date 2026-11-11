# MobiTive

**Phát hiện mã độc Android ngay trên thiết bị bằng phân tích tĩnh APK và mô hình GRU gọn nhẹ.**

MobiTive là dự án nghiên cứu gồm ứng dụng Android và pipeline học máy nhằm phân loại APK thành **benign** hoặc **malware**. Ứng dụng đọc APK do người dùng chọn, trích xuất đặc trưng từ `AndroidManifest.xml` và mã DEX, rồi chạy mô hình TensorFlow Lite ngay trên thiết bị. APK được phân tích tĩnh, không được cài đặt hay thực thi trong quá trình quét.

## Mục tiêu

Phân tích APK trên thiết bị giúp người dùng có thêm một lớp sàng lọc mà không cần tải tệp lên dịch vụ phân tích từ xa. Dự án tập trung vào quy trình gọn, có thể tái lập: trích xuất đặc trưng, huấn luyện và đánh giá mô hình, chuyển mô hình sang TensorFlow Lite, rồi tích hợp vào ứng dụng Android.

## Tính năng

- Chọn APK từ thiết bị để phân tích theo yêu cầu.
- Trích xuất tĩnh các lời gọi API Android/Java từ DEX và các đặc trưng manifest gồm quyền, intent và hardware feature.
- Mã hóa đặc trưng thành vector nhị phân **2.915 chiều**: 2.290 đặc trưng API và 625 đặc trưng manifest.
- Phân loại APK bằng mô hình GRU đóng gói dưới dạng TensorFlow Lite; hiển thị nhãn dự đoán và độ tin cậy.
- Cung cấp pipeline Python để phân tích APK, chuẩn bị dữ liệu, huấn luyện, đánh giá và xuất mô hình.

## Cấu trúc dự án

- `MobiTive/` — ứng dụng Android viết bằng Java; đảm nhiệm chọn APK, phân tích manifest/DEX, tạo vector đặc trưng và suy luận bằng TensorFlow Lite.
- `MobiTiveAI/` — mã nguồn Python cho trích xuất và chuẩn bị dữ liệu, huấn luyện GRU, đánh giá mô hình và các artifact/báo cáo liên quan.

## Mô hình và đánh giá

Mô hình hiện được cấu hình với đầu vào 2.915 đặc trưng, một lớp GRU 128 units và dropout 0,5; đầu ra gồm hai lớp benign và malware. Báo cáo huấn luyện hiện có ghi nhận trên tập test 112 mẫu:

| Chỉ số | Kết quả |
|---|---:|
| Accuracy | 98,21% |
| Precision (malware) | 100,00% |
| Recall (malware) | 91,67% |
| F1-score (malware) | 95,65% |
| ROC-AUC | 99,53% |

Đây là kết quả của tập đánh giá hiện có, không phải cam kết hiệu năng trong thực tế. Tập test nhỏ nên các chỉ số cần được kiểm chứng thêm trên bộ dữ liệu lớn, đa dạng và cập nhật hơn trước khi dùng để đưa ra quyết định bảo mật.

## Liên hệ với paper

Dự án tham khảo hướng tiếp cận và động lực nghiên cứu của **“A Performance-Sensitive Malware Detection System Using Deep Learning on Mobile Devices”** (Chen và cộng sự, *IEEE Transactions on Information Forensics and Security*, 2020; [arXiv:2005.04970](https://arxiv.org/abs/2005.04970)). Paper đề xuất MobiTive như một hướng phát hiện mã độc Android trên thiết bị, đồng thời xem xét các đánh đổi về đặc trưng, độ chính xác và hiệu năng.

Repository này hiện thực hóa một pipeline thử nghiệm theo cùng định hướng on-device, nhưng không nên được hiểu là bản tái lập đầy đủ paper. Cụ thể, mã nguồn hiện tại dùng vector nhị phân gồm các lời gọi API và đặc trưng manifest, mô hình GRU và thao tác quét APK thủ công từ giao diện ứng dụng. Vì vậy, dự án chưa phải bộ giám sát tự động chạy nền hay hệ thống bảo vệ đã được kiểm chứng trên quy mô triển khai thực tế.

## Phạm vi và lưu ý

- Đây là công cụ hỗ trợ nghiên cứu và sàng lọc, không thay thế giải pháp bảo mật hoặc phân tích chuyên sâu.
- Phân tích tĩnh có thể bỏ sót hành vi chỉ xuất hiện khi chạy, mã bị đóng gói/làm rối, hoặc đặc trưng nằm ngoài dictionary của mô hình.
- Nhãn và độ tin cậy là dự đoán của mô hình, không phải kết luận chắc chắn APK an toàn hay độc hại.
- Hãy chỉ phân tích APK từ nguồn phù hợp và xác minh kết quả bằng các phương pháp độc lập khi cần.



# BPFroid Android Demo -- Hướng dẫn chạy trên Windows PowerShell

Tài liệu này hướng dẫn khởi động lại demo BPFroid sau khi bật máy và
trình diễn luồng phát hiện payload trên Android Emulator.

## 1. Mô hình demo

Luồng hoạt động:

1.  Android Emulator chạy ứng dụng **BPFroid Dashboard**.
2.  Bridge TCP lắng nghe tại `127.0.0.1:8765`.
3.  Dashboard gửi `POLL` (trạng thái + cảnh báo trong một kết nối) mỗi
    2 giây, và `START`/`STOP` khi bấm nút. Bridge còn hỗ trợ `STATUS`,
    `LOGS` để kiểm tra thủ công.
4.  Bridge khởi chạy `tracee-android --trace event=write_alert --trace
    event=uid_changed_alert`, tức hai signature mà paper BPFroid đánh
    giá, chạy trên **toàn hệ thống** (mọi app, mọi thư mục):
    -   **Dropper Detection** (`write_alert`): eBPF gắn vào `vfs_write`
        và đọc ngay trong kernel 4 byte đầu của mọi lần ghi file ở
        offset 0. Chỉ khi khớp ELF (`\x7fELF`), DEX (`dex\n`) hoặc
        ZIP/APK/JAR (`PK\x03\x04`) mới gửi sự kiện lên user space.
    -   **Privilege Escalation** (`uid_changed_alert`): eBPF ở tracepoint
        `sys_enter` nhớ UID của từng thread và so sánh giữa hai syscall
        liên tiếp. Engine chỉ báo khi UID **tăng quyền** (thành root,
        hoặc từ UID app xuống UID hệ thống); các lần hạ quyền hợp lệ
        (zygote 0 → UID app khi mở app) bị bỏ qua.
5.  Engine ghi cảnh báo vào `/data/local/tmp/bpfroid-alerts.log` (file
    riêng, chỉ chứa cảnh báo).
6.  Dashboard hiển thị cảnh báo kèm **tên package của app** (tra từ
    UID), đếm theo loại payload và số lần leo thang đặc quyền.

Định dạng cảnh báo:

``` text
BPFROID_DROPPER_ALERT type=DEX uid=10209 pid=13547 comm=unzip dev=266338350 inode=565546 path=/data/user/0/com.bpfroid.dashboard/files/update.dex
BPFROID_PRIVESC_ALERT prev_uid=2000 uid=0 pid=15990 tid=15990 comm=su
```

Mã nguồn engine (fork Tracee của BPFroid) nằm ngoài repo, trong WSL tại
`~/bpfroid-work/BPFroid`. Repo lưu bản vá và script build ở
`BPFroidDashboard/engine/` (`bpfroid-android.patch`,
`build-android.sh`).

> Các kịch bản tấn công ở mục 4 chỉ **mô phỏng hành vi** của malware
> bằng file hệ thống vô hại (`classes.dex` của chính app Dashboard,
> `/system/bin/sh`, `su` của emulator). Không có mã độc thật nào được
> tải về hay thực thi.

## 2. Điều kiện trước khi demo

-   Đã mở Android Emulator có quyền root.
-   Đã cài ứng dụng BPFroid Dashboard.
-   Các file đã được triển khai lên emulator:
    -   `/data/local/tmp/tracee-android`
    -   `/data/local/tmp/tracee.bpf.dev.o`
    -   `/data/local/tmp/bpfroid-bridge-handler.sh`
-   Bridge handler đã được cấu hình dùng cổng `8765`.
-   Engine đã được build và hoạt động thành công trước đó.

Mã nguồn bridge handler nằm ở
`BPFroidDashboard/bridge/bpfroid-bridge-handler.sh`. Sau khi sửa, triển
khai lại (listener gọi script cho mỗi kết nối nên không cần khởi động
lại listener):

``` powershell
adb push BPFroidDashboard\bridge\bpfroid-bridge-handler.sh /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/bpfroid-bridge-handler.sh"
```

Nếu emulator chưa chạy, hãy mở emulator từ Android Studio trước khi chạy
các lệnh bên dưới.

## 3. Khởi động demo -- thực hiện theo thứ tự

Mở **Windows PowerShell**.

### Bước 1 -- Kiểm tra ADB và emulator

``` powershell
adb devices
```

Đảm bảo emulator xuất hiện với trạng thái `device`.

Kiểm tra quyền root:

``` powershell
adb shell "id"
```

Demo hiện tại cần quyền `uid=0(root)`. Nếu emulator chưa cấp root, hãy
xử lý quyền root trước khi tiếp tục.

### Bước 2 -- Khởi động Bridge listener

Trước tiên, kiểm tra Bridge:

``` powershell
adb shell "echo STATUS | toybox nc -w 3 127.0.0.1 8765"
```

Nếu nhận được `STOPPED` hoặc `RUNNING:<PID>`, Bridge đang phản hồi;
chuyển sang Bước 3.

Nếu không nhận được phản hồi, khởi động listener:

``` powershell
adb shell "nohup toybox nc -s 127.0.0.1 -p 8765 -L /system/bin/sh /data/local/tmp/bpfroid-bridge-handler.sh >/data/local/tmp/bpfroid-bridge.log 2>&1 </dev/null &"
Start-Sleep -Seconds 2
adb shell "echo STATUS | toybox nc -w 3 127.0.0.1 8765"
```

Kết quả mong đợi là `STOPPED` hoặc `RUNNING:<PID>`, không phải lỗi kết
nối.

> Chỉ khởi động listener khi lệnh STATUS không phản hồi. Không tạo thêm
> listener nếu Bridge đã hoạt động.

### Bước 3 -- Dọn kprobe cũ (thường không cần)

Tracee không tự gỡ kprobe khi bị dừng; nếu còn sót, START lần sau lỗi
`-17`. Bridge handler đã tự dọn 4 kprobe `pvfs_write`, `rvfs_write`,
`pvfs_writev`, `rvfs_writev` khi STOP và trước khi START, nên bước này
chỉ cần khi engine bị dừng ngoài bridge (ví dụ emulator bị tắt ngang).
Chỉ chạy khi engine đã dừng:

``` powershell
adb shell "cat /sys/kernel/tracing/kprobe_events"
adb shell "cd /sys/kernel/tracing && for e in pvfs_write rvfs_write pvfs_writev rvfs_writev; do echo -:kprobes/`$e >> kprobe_events; done"
```

Lệnh thứ hai chỉ xóa 4 kprobe trên; sau đó lệnh thứ nhất phải không còn
dòng nào chứa `vfs_write`.

### Bước 4 -- Khởi động BPFroid Engine

``` powershell
adb shell "echo START | toybox nc -w 10 127.0.0.1 8765"
```

Kết quả mong đợi:

``` text
OK:RUNNING:<PID>
```

Kiểm tra thêm:

``` powershell
adb shell "pidof tracee-android"
adb shell "echo STATUS | toybox nc -w 3 127.0.0.1 8765"
```

Nếu nhận `ERROR:ENGINE_NOT_STARTED`, xem log:

``` powershell
adb shell "tail -n 60 /data/local/tmp/bpfroid-engine.log"
```

Một lỗi từng gặp là:

``` text
failed to add kprobe 'p:kprobes/pvfs_write vfs_write': -17
```

Bridge handler hiện đã tự dọn kprobe nên lỗi này không nên xuất hiện
nữa. Nếu vẫn gặp, chạy Bước 3 rồi thử START một lần nữa. Nếu vẫn lỗi,
giữ nguyên log để xử lý; không build lại app ngay.

### Bước 5 -- Mở ứng dụng Dashboard

Mở **BPFroid Dashboard** trên emulator.

Kiểm tra: - Engine Status: `RUNNING` - Dashboard không hiển thị
`BRIDGE DISCONNECTED`. - Các nút START và STOP có thể thao tác.

Dashboard tự làm mới trạng thái và danh sách cảnh báo định kỳ.

## 4. Kịch bản tấn công như trong paper BPFroid

Paper BPFroid đánh giá hai signature trên 200 mẫu malware Android thật:

-   **Dropper Detection**: malware vượt qua kiểm duyệt (Google Play,
    antivirus quét tĩnh) bằng cách chỉ mang phần vỏ vô hại; khi đã chạy
    trên máy, nó tải hoặc giải nén **payload thật** (DEX, thư viện/binary
    ELF, APK thứ cấp) ra file rồi nạp/chạy. Paper phát hiện 33 mẫu thả
    file: 9 ELF, 11 DEX, 16 archive (apk/jar/zip).
-   **Privilege Escalation**: root exploit (ví dụ lỗi kernel) làm tiến
    trình của app đột ngột có UID 0. Dấu hiệu kernel nhìn thấy là UID của
    một thread thay đổi giữa hai syscall. Paper không ghi nhận mẫu nào
    thành công vì thiết bị đã vá.

Mục này tái hiện **hành vi** của từng loại tấn công bằng file vô hại.
Các bước "tấn công" chạy dưới UID của một app thường (UID ≥ 10000) nhờ
`run-as` với app Dashboard bản debug, nên engine nhìn thấy đúng như một
app độc hại đang hoạt động.

### Chuẩn bị

Engine phải đang RUNNING. Trong PowerShell, đặt hai biến dùng chung cho
các lệnh bên dưới:

``` powershell
$A = "com.bpfroid.dashboard"
$APK = ((adb shell pm path $A) -replace 'package:','').Trim()
```

-   `$A`: package của app đóng vai "app độc hại".
-   `$APK`: đường dẫn file APK đã cài của app (`/data/app/.../base.apk`),
    dùng làm nguồn DEX/APK thật.

Bảng tóm tắt kết quả mong đợi (đã chạy thử trên emulator):

  Mã   Kịch bản                              Cảnh báo mong đợi
  ---- ------------------------------------- ---------------------------------
  D1   Nạp mã DEX động                       `DROPPER type=DEX`
  D2   Thả và chạy binary ELF native         `DROPPER type=ELF`
  D3   Thả APK thứ cấp                       `DROPPER type=ZIP/APK`
  D4   Ngụy trang payload bằng đuôi file     `DROPPER type=ELF`
  N1   Ghi file bình thường (đối chứng)      Không có
  P1   Leo thang lên root                    `PRIVESC 2000 → 0`
  P2   App thử gọi `su` (bị chặn)            Không có
  P3   Mở app bình thường (đối chứng)        Không có
  L1   Né signature: tách magic bytes        Không có (hạn chế)
  L2   Né signature: chép bằng kernel        Không có (hạn chế)

Sau mỗi lệnh, chờ 1--2 giây rồi xem Dashboard hoặc chạy
`adb shell "echo LOGS | toybox nc -w 5 127.0.0.1 8765"`.

### A. Dropper Detection

#### D1 -- Nạp mã động bằng file DEX (dynamic code loading)

``` powershell
adb shell "run-as $A sh -c 'unzip -p $APK classes.dex > files/update.dex'"
```

-   **Lệnh làm gì:** với UID của app, giải nén `classes.dex` (bytecode
    Dalvik thật) từ APK rồi ghi vào thư mục dữ liệu riêng của app
    `files/update.dex`.
-   **Mô phỏng tấn công:** trojan/dropper tải "bản cập nhật" từ server
    điều khiển (C&C), lưu thành `.dex` rồi nạp bằng `DexClassLoader`.
    Mã độc không nằm trong APK lúc quét, nên **phân tích tĩnh (như
    MobiTive ở phần trên) không thấy**; chỉ giám sát lúc chạy mới bắt
    được.
-   **Cảnh báo:**
    `BPFROID_DROPPER_ALERT type=DEX uid=10209 ... comm=unzip ... path=/data/user/0/com.bpfroid.dashboard/files/update.dex`

#### D2 -- Thả và chạy binary native (ELF)

``` powershell
adb shell "run-as $A sh -c 'cp /system/bin/sh files/libpayload.so && chmod 700 files/libpayload.so && ./files/libpayload.so -c id'"
```

-   **Lệnh làm gì:** chép một binary ELF thật (`/system/bin/sh`) vào thư
    mục app với tên `libpayload.so`, cấp quyền thực thi rồi chạy nó; lệnh
    `id` in ra `uid=10209(...)`, chứng tỏ payload đã chạy dưới danh tính
    app.
-   **Mô phỏng tấn công:** malware thả root exploit, cryptominer hoặc
    backdoor viết bằng C rồi thực thi, thường đặt tên giống thư viện
    `.so` để trông vô hại.
-   **Cảnh báo:** `type=ELF ... comm=cp ... path=.../files/libpayload.so`
    (cảnh báo xuất hiện **ngay lúc ghi file**, trước khi payload chạy).

#### D3 -- Thả APK thứ cấp

``` powershell
adb shell "run-as $A sh -c 'cat $APK > files/update.apk'"
```

-   **Lệnh làm gì:** ghi nguyên một file APK vào thư mục app.
-   **Mô phỏng tấn công:** dropper tải một app độc hại thứ hai (APK) rồi
    hiện hộp thoại "cập nhật" để dụ người dùng cài, hoặc nạp APK/JAR như
    plugin. Đây là nhóm paper gặp nhiều nhất (16 archive).
-   **Cảnh báo:** `type=ZIP/APK ... comm=cat ... path=.../files/update.apk`

#### D4 -- Ngụy trang payload bằng đuôi file

``` powershell
adb shell "run-as $A sh -c 'cp /system/bin/sh files/.thumb.jpg'"
```

-   **Lệnh làm gì:** ghi binary ELF vào một file ẩn có đuôi ảnh `.jpg`.
-   **Mô phỏng tấn công:** malware đổi tên/đuôi file để qua mặt các công
    cụ lọc theo tên hoặc phần mở rộng.
-   **Cảnh báo:** `type=ELF ... path=.../files/.thumb.jpg`. BPFroid xét
    **nội dung** (magic bytes) chứ không xét tên file, nên ngụy trang
    không có tác dụng.

#### N1 -- Đối chứng: ghi file bình thường

``` powershell
adb shell "run-as $A sh -c 'echo hello > files/note.txt; cp /system/etc/hosts files/hosts.txt'"
```

-   **Lệnh làm gì:** app ghi file text như mọi app bình thường.
-   **Ý nghĩa:** chứng minh engine **không** báo động cho mọi lần ghi.
    Kết quả mong đợi: **không có cảnh báo**.

### B. Privilege Escalation

#### P1 -- Leo thang từ người dùng thường lên root

``` powershell
adb shell "su 2000 su 0 id"
```

-   **Lệnh làm gì:** `su 2000` hạ quyền xuống UID 2000 (người dùng
    `shell`, không có đặc quyền); trong tiến trình đó, `su 0` leo
    ngược lên root và chạy `id`, in ra `uid=0(root)`.
-   **Mô phỏng tấn công:** một root exploit biến tiến trình không đặc
    quyền thành root. Ở đây `su` của emulator đóng vai exploit; với
    kernel, dấu hiệu là như nhau: cùng một thread, UID đổi từ 2000 sang
    0 giữa hai syscall.
-   **Cảnh báo:**
    `BPFROID_PRIVESC_ALERT prev_uid=2000 uid=0 pid=... comm=su`.
    Dashboard hiển thị `[PRIVESC] com.android.shell (uid 2000) → root
    (uid 0)`. Lần hạ quyền 0 → 2000 ở đầu lệnh **không** bị báo.

#### P2 -- App thường thử chiếm root (bị chặn)

``` powershell
adb shell "run-as $A su 0 id"
```

-   **Lệnh làm gì:** từ UID của app, cố gọi `su` để lấy root.
-   **Kết quả:** `run-as: exec failed for su: Permission denied`. SELinux
    và quyền file chặn app chạy `su`, UID không đổi nên **không có cảnh
    báo**. BPFroid chỉ báo khi việc leo thang thực sự thành công.

#### P3 -- Đối chứng: mở app bình thường

``` powershell
adb shell "am start -W -n com.android.settings/.Settings"
adb shell "input keyevent HOME"
```

-   **Lệnh làm gì:** mở app Cài đặt rồi về màn hình chính.
-   **Ý nghĩa:** mỗi lần mở app, zygote fork một tiến trình root rồi hạ
    xuống UID của app, tức là UID **có** đổi. Engine bỏ qua các lần hạ
    quyền này. Kết quả mong đợi: **không có cảnh báo PRIVESC**.

### C. Hạn chế: những cách né mà signature không bắt được

Hai kịch bản này cho thấy giới hạn thật của signature (paper cũng chỉ
hook `vfs_write` và chỉ xét offset 0).

#### L1 -- Tách magic bytes thành hai lần ghi

``` powershell
adb shell "run-as $A sh -c '(printf \\177E; printf LF\\002\\001\\001) > files/split.bin'"
```

-   **Lệnh làm gì:** ghi header ELF thành hai lần: lần một chỉ 2 byte
    `\177E`, lần hai `LF...`. File cuối cùng vẫn bắt đầu bằng `\177ELF`.
-   **Vì sao lọt:** eBPF chỉ đọc magic khi **một** lần ghi ở offset 0 dài
    hơn 4 byte. Kết quả: **không có cảnh báo**.

#### L2 -- Chép file bằng cơ chế trong kernel

``` powershell
adb shell "run-as $A sh -c 'cp $APK files/copy.apk'"
```

-   **Lệnh làm gì:** chép APK bằng `cp` trong cùng một phân vùng.
-   **Vì sao lọt:** khi nguồn và đích cùng phân vùng, `cp` (toybox) để
    kernel tự chép dữ liệu (kiểu `copy_file_range`/`sendfile`) mà không
    gọi `vfs_write` với buffer từ user space, nên không đi qua điểm
    hook. Kết quả: **không có cảnh báo**. (So với D2/D4: nguồn
    `/system` khác phân vùng nên `cp` phải đọc/ghi bình thường và bị bắt.)

Muốn bịt các lỗ này cần hook thêm (ví dụ `vfs_copy_file_range`,
`do_splice_direct`) hoặc kiểm tra header file khi đóng/thực thi file.

### Dọn file thử nghiệm

``` powershell
adb shell "run-as $A sh -c 'rm -f files/update.dex files/libpayload.so files/update.apk files/.thumb.jpg files/note.txt files/hosts.txt files/split.bin files/copy.apk'"
```

### Kiểm tra trên Dashboard

Sau khi chạy hết D1--D4, N1, P1--P3, L1--L2 trong cùng một lần START,
Dashboard hiển thị:

-   Total alerts: 5
-   Payloads: ELF 2 | ZIP/APK 1 | DEX 1
-   Privilege escalation: 1
-   Mỗi cảnh báo ghi tên package (ví dụ `com.bpfroid.dashboard`), PID,
    tên tiến trình và đường dẫn.

Số lượng có thể lớn hơn nếu có tiến trình hệ thống ghi APK/ELF cùng lúc
(cài app qua adb, Play Store, `dex2oat`) hoặc nếu chạy lại lệnh. Dashboard
đếm cộng dồn qua các lần STOP/START cho tới khi app được mở lại.

## 5. Demo chức năng STOP / START

Có thể trình diễn trực tiếp bằng các nút trên Dashboard.

1.  Nhấn **STOP**.
2.  Kiểm tra:

``` powershell
adb shell "echo STATUS | toybox nc -w 3 127.0.0.1 8765"
```

Kết quả mong đợi:

``` text
STOPPED
```

3.  Nhấn **START**.
4.  Kiểm tra lại:

``` powershell
adb shell "echo STATUS | toybox nc -w 3 127.0.0.1 8765"
```

Kết quả mong đợi:

``` text
RUNNING:<PID>
```

5.  Tạo một payload mới để xác nhận Engine tiếp tục phát hiện:

``` powershell
adb shell "run-as com.bpfroid.dashboard sh -c 'cp /system/bin/sh files/after-restart.so'"
Start-Sleep -Seconds 2
adb shell "echo LOGS | toybox nc -w 5 127.0.0.1 8765"
adb shell "run-as com.bpfroid.dashboard rm -f files/after-restart.so"
```

## 6. Tắt demo

Khi kết thúc, nhấn **STOP** trên Dashboard hoặc chạy:

``` powershell
adb shell "echo STOP | toybox nc -w 3 127.0.0.1 8765"
```

Xác nhận:

``` powershell
adb shell "echo STATUS | toybox nc -w 3 127.0.0.1 8765"
```

Kết quả mong đợi: `STOPPED`.

## 7. Xử lý lỗi nhanh

  ---------------------------------------------------------------------------
  Hiện tượng                          Cách xử lý
  ----------------------------------- ---------------------------------------
  `adb devices` không thấy emulator   Mở emulator, kiểm tra ADB rồi chạy lại
                                      `adb devices`.

  Bridge không phản hồi               Khởi động listener theo Bước 2.

  Dashboard báo `BRIDGE DISCONNECTED` Kiểm tra listener bằng lệnh STATUS; nếu
                                      cần, khởi động lại listener.

  START trả                           Xem
  `ERROR:ENGINE_NOT_STARTED`          `/data/local/tmp/bpfroid-engine.log`;
                                      nếu có lỗi kprobe `-17`, chạy Bước 3
                                      rồi START lại.

  Engine RUNNING nhưng không có cảnh  Kiểm tra dữ liệu ghi bắt đầu bằng magic
  báo                                 bytes ở offset 0 và dài hơn 4 byte, và
                                      không rơi vào L1/L2 ở mục 4; xem
                                      output LOGS.

  `run-as: package not debuggable`    Cài bản **debug** của Dashboard
                                      (`gradlew :app:installDebug`).

  Dashboard chưa cập nhật cảnh báo    Đợi chu kỳ refresh tiếp theo; đối chiếu
                                      trực tiếp bằng lệnh LOGS.
  ---------------------------------------------------------------------------

Các lệnh xem log hữu ích:

``` powershell
adb shell "tail -n 60 /data/local/tmp/bpfroid-engine.log"
adb shell "cat /data/local/tmp/bpfroid-alerts.log"
adb shell "cat /data/local/tmp/bpfroid-bridge.log"
adb shell "pidof tracee-android"
```

### Build lại engine

Trong WSL (đã có NDK r30, elfutils và libbpf như lần build trước):

``` bash
cd ~/bpfroid-work/BPFroid
bash scripts/build-android.sh      # = BPFroidDashboard/engine/build-android.sh
```

Nếu sửa `tracee/tracee.bpf.c` thì build lại cả object BPF (bản vá hiện
tại có sửa: xóa UID đã lưu của thread khi thread thoát, tránh báo động
giả khi TID được tái sử dụng):

``` bash
make -j"$(nproc)" bpf VERSION=dev ARCH=x86_64 \
  KERN_SRC_PATH="$HOME/android-kernel" KERN_BLD_PATH="$HOME/android-kernel"
```

Sau đó STOP engine, `adb push` `dist/tracee-android` và
`dist/tracee.bpf.dev.o` vào `/data/local/tmp/` rồi START lại.

## 8. Kịch bản demo ngắn khi thuyết trình

1.  Mở emulator và BPFroid Dashboard; khởi động Bridge và Engine theo
    Bước 2--4; cho người xem thấy `ENGINE RUNNING`.
2.  Giới thiệu bối cảnh: malware né phân tích tĩnh bằng cách tải payload
    lúc chạy (mục 4, phần mở đầu).
3.  Chạy **D1** (DEX động) và **D2** (ELF native, cho thấy payload chạy
    với `uid=10209`): mỗi lệnh hiện ngay một cảnh báo ghi rõ app
    `com.bpfroid.dashboard` thả file gì, ở đâu.
4.  Chạy **D4**: đổi đuôi thành `.jpg` vẫn bị bắt vì BPFroid xét nội dung.
5.  Chạy **N1** và **P3**: hoạt động bình thường không gây báo động.
6.  Chạy **P1**: Dashboard hiện `[PRIVESC] com.android.shell (uid 2000)
    → root (uid 0)`; rồi **P2**: app không leo được thì không báo.
7.  Chạy **L1** hoặc **L2** để thảo luận hạn chế của signature.
8.  Nhấn STOP rồi START trên Dashboard, chạy lại D2 để chứng minh engine
    tiếp tục phát hiện; dọn file thử nghiệm và kết thúc bằng STOP.

**Lưu ý:** Engine giám sát việc ghi file trên toàn hệ thống và nhận
diện định dạng dựa trên magic bytes. Cảnh báo nghĩa là "một tiến trình
vừa ghi ra file thực thi/gói ứng dụng", không có nghĩa file đó chắc chắn
độc hại: các tiến trình hệ thống hợp lệ (cài app qua adb, Play Store,
`dex2oat`, cập nhật) cũng sinh cảnh báo. Cần xem UID/package và đường
dẫn, rồi kiểm chứng file bằng công cụ khác (ví dụ VirusTotal như trong
paper). Cảnh báo PRIVESC cũng có thể đến từ công cụ quản trị hợp lệ
(ví dụ `su` trên máy đã root) chứ không chỉ từ exploit.
