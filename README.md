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
4.  Bridge khởi chạy `tracee-android`.
5.  Tracee theo dõi sự kiện ghi file và kiểm tra magic bytes trong thư
    mục: `/data/local/tmp/dropper-demo/`
6.  Dashboard hiển thị các cảnh báo ELF, ZIP/APK và DEX.

> Các file tạo trong phần kiểm thử chỉ là payload giả lập chứa magic
> bytes, không phải APK/DEX hoàn chỉnh và không thực thi mã độc.

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

## 4. Trình diễn phát hiện payload

Mở PowerShell và chạy từng bài kiểm thử. Engine phải đang ở trạng thái
RUNNING.

### Test 1 -- ELF

``` powershell
adb shell "mkdir -p /data/local/tmp/dropper-demo"
adb shell "printf '\177ELF\001\001\001\000' > /data/local/tmp/dropper-demo/demo-elf.bin"
Start-Sleep -Seconds 2
```

Cảnh báo mong đợi có dạng:

``` text
BPFROID_DROPPER_ALERT type=ELF pid=<PID> path=/data/local/tmp/dropper-demo/demo-elf.bin
```

### Test 2 -- ZIP/APK

``` powershell
adb shell "printf 'PK\003\004\024\000\000\000' > /data/local/tmp/dropper-demo/demo-apk.apk"
Start-Sleep -Seconds 2
```

Cảnh báo mong đợi:

``` text
BPFROID_DROPPER_ALERT type=ZIP/APK pid=<PID> path=/data/local/tmp/dropper-demo/demo-apk.apk
```

### Test 3 -- DEX

``` powershell
adb shell "printf 'dex\n035\000' > /data/local/tmp/dropper-demo/demo-dex.dex"
Start-Sleep -Seconds 2
```

Cảnh báo mong đợi:

``` text
BPFROID_DROPPER_ALERT type=DEX pid=<PID> path=/data/local/tmp/dropper-demo/demo-dex.dex
```

### Kiểm tra danh sách cảnh báo từ Bridge

``` powershell
adb shell "echo LOGS | toybox nc -w 5 127.0.0.1 8765"
```

Kết quả sẽ chứa các dòng `BPFROID_DROPPER_ALERT` đã phát hiện.

### Kiểm tra trên Dashboard

Chờ tối đa vài giây để Dashboard làm mới. Với ba payload vừa tạo, kết
quả mong đợi:

-   Total alerts: 3
-   ELF: 1
-   ZIP/APK: 1
-   DEX: 1
-   Danh sách sự kiện hiển thị đường dẫn và PID tương ứng.

Số lượng có thể lớn hơn nếu bạn chạy lại lệnh tạo payload nhiều lần, vì
mỗi lần ghi tạo một cảnh báo mới. Dashboard đếm cộng dồn qua các lần
STOP/START cho tới khi app được mở lại.

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
adb shell "printf '\177ELF\001\001\001\000' > /data/local/tmp/dropper-demo/after-restart.bin"
Start-Sleep -Seconds 2
adb shell "echo LOGS | toybox nc -w 5 127.0.0.1 8765"
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

  Engine RUNNING nhưng không có cảnh  Kiểm tra đã ghi file vào đúng thư mục
  báo                                 `/data/local/tmp/dropper-demo/` và xem
                                      output LOGS.

  Dashboard chưa cập nhật cảnh báo    Đợi chu kỳ refresh tiếp theo; đối chiếu
                                      trực tiếp bằng lệnh LOGS.
  ---------------------------------------------------------------------------

Các lệnh xem log hữu ích:

``` powershell
adb shell "tail -n 60 /data/local/tmp/bpfroid-engine.log"
adb shell "cat /data/local/tmp/bpfroid-bridge.log"
adb shell "pidof tracee-android"
```

## 8. Kịch bản demo ngắn khi thuyết trình

1.  Mở emulator và BPFroid Dashboard.
2.  Khởi động Bridge và Engine theo Bước 2--4.
3.  Cho người xem thấy trạng thái Engine `RUNNING`.
4.  Tạo lần lượt payload ELF, ZIP/APK và DEX.
5.  Cho người xem thấy các cảnh báo xuất hiện trên Dashboard.
6.  Nhấn STOP để chứng minh có thể dừng Engine.
7.  Nhấn START, tạo payload mới và chứng minh Engine tiếp tục phát hiện.
8.  Kết thúc bằng STOP.

**Lưu ý:** Demo hiện tại kiểm tra dấu hiệu ghi file trong thư mục thử
nghiệm và nhận diện định dạng dựa trên magic bytes. Đây là bản trình
diễn cơ chế phát hiện, không nên mô tả là đã phân tích đầy đủ hành vi
hoặc xác định payload độc hại chỉ dựa trên định dạng file.
