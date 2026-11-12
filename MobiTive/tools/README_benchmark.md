# Đo MobiTive trên điện thoại thật (M7 + M8)

Mỗi thành viên dùng **điện thoại của mình**, không cần máy ảo. Một lần đo mất khoảng 5–15 phút.

## Chuẩn bị (1 lần trên PC)
1. Cài Python 3 và Android SDK Platform-Tools (có sẵn nếu đã cài Android Studio).
2. Tải bộ APK benchmark (18 APK benign từ F-Droid, mỗi nhóm 5/10/20/30/40/50 MB có 3 APK):
   ```powershell
   cd MobiTiveAI
   python scripts\prepare_benchmark_apks.py
   ```
   Danh sách cố định nằm trong `data/bench_apks/bench_apks.csv`, nên mọi máy đều quét đúng cùng bộ APK.

## Chuẩn bị điện thoại
1. Vào **Cài đặt → Thông tin điện thoại**, bấm **Số hiệu bản tạo** 7 lần.
2. Vào **Tuỳ chọn nhà phát triển**, bật **Gỡ lỗi USB**. Trên Xiaomi bật thêm **Cài đặt qua USB**.
3. Sạc pin trên 50%, tắt tiết kiệm pin, đóng các app khác, để máy nguội.
4. Cắm cáp, bấm **Cho phép** khi máy hỏi, rồi kiểm tra bằng `adb devices`.

## Chạy đo (1 lệnh)
```powershell
cd MobiTive
python tools\run_device_benchmark.py
```
- Lệnh này tự build, cài app và test APK, đẩy APK lên máy, rồi đo 2 phần và kéo kết quả về `MobiTive/device_results/<tên máy>/<thời điểm>/`:
  - **M7, quét APK:** 18 APK × 5 lần (FORCED), cộng 3 lần qua cache.
  - **M8, quantization × phần cứng (paper 2):** 12 model (GRU-128, GRU-64, MLP-64 × FP32/FP16/DYNAMIC/INT8) × 7 backend (CPU 1/2/4 luồng, CPU không XNNPACK, GPU FP32/FP16, NNAPI). Mỗi cặp đo init, p50/p95 và **accuracy/F1 ngay trên máy** với 112 mẫu test, kèm mức khớp với kết quả desktop.
- **Đừng rút cáp và đừng dùng điện thoại** trong lúc đo.
- Nếu có nhiều máy cắm cùng lúc, script đo lần lượt từng máy. Muốn chọn 1 máy thì thêm `--serial <mã máy>`.
- Tuỳ chọn khác: `--repeats 10` để lặp nhiều hơn, `--models all` để quét bằng cả 5 model, `--skip-build` nếu đã build rồi, `--no-scan` hoặc `--no-accel` để chỉ chạy một phần, `--backends cpu1,gpu_fp16` để chọn backend.

## Gộp kết quả và vẽ biểu đồ
Gom thư mục `device_results/` của mọi người vào chung một chỗ (hoặc commit lên git), rồi chạy:
```powershell
cd MobiTiveAI
pip install matplotlib
python scripts\analyze_device_benchmarks.py
```
Kết quả gồm:
- `reports/device_info.csv`: bảng cấu hình các máy.
- `reports/device_scan_summary.csv`: median và IQR theo máy × nhóm dung lượng.
- `reports/device_accel_summary.csv`: p50, init, accuracy và tốc độ so với CPU-1 FP32 cho từng máy × model × backend (giống Table V–X của paper 2).
- `reports/figures/*.png`: biểu đồ cho báo cáo.

## Lưu ý phương pháp (ghi vào báo cáo)
- Thứ tự quét **xen kẽ** các APK (A B C, A B C, …) để nhiệt độ máy tăng dần không làm lệch riêng APK cuối.
- Lần quét warm-up đầu tiên (`iteration < 0`) được ghi lại để phân tích khởi động lạnh, nhưng **không** tính vào median.
- Mỗi dòng CSV có trạng thái nhiệt (`thermal_status`, > 0 nghĩa là máy đang bị giảm xung), số lần và thời gian GC, SoC và RAM của máy.
- Số liệu từ máy ảo bị script cảnh báo và không nên đưa vào báo cáo.
- GPU/NNAPI trả về `SKIP`/`ERROR` khi máy không hỗ trợ, đó **là kết quả** cần ghi lại, không phải lỗi. Ví dụ: GRU không chạy được qua NNAPI.
- Model và tập test cho M8 do `MobiTiveAI/scripts/export_model_variants.py` sinh ra (cần TensorFlow 2.15.1) và nằm trong test APK, nên app sản phẩm không nặng thêm.

## Lỗi thường gặp
| Lỗi | Cách xử lý |
|---|---|
| `unauthorized` | Mở khoá máy, bấm "Cho phép gỡ lỗi USB" |
| `INSTALL_FAILED_USER_RESTRICTED` (Xiaomi) | Bật "Cài đặt qua USB" trong Tuỳ chọn nhà phát triển |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | `adb uninstall com.example.mobitive` rồi chạy lại |
| `Không có APK trong ...` | Chạy `prepare_benchmark_apks.py` trước |
| Có lần quét lỗi | Xem cột `error` trong `scan_*.csv` và file `instrumentation_output.txt` |
