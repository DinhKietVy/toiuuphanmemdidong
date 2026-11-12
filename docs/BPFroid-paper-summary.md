# BPFroid – Phát hiện mã độc Android thời gian thực bằng eBPF

Cập nhật: 2026-11-11 · Bản online: https://claude.ai/artifact/J97BSCVw2GaPtttS8usE8e

Tài liệu tóm tắt paper BPFroid (Agman & Hendler, 2021) cho môn Tối ưu phần mềm di động, đề tài Security on device: cách paper giám sát hành vi app ngay trong kernel Android, các kết quả chính, và phần nhóm đã hiện thực lại.

## 1. Thông tin paper

| Mục | Nội dung |
| --- | --- |
| Tên | BPFroid: Robust Real Time Android Malware Detection Framework |
| Tác giả | Yaniv Agman, Danny Hendler (Ben-Gurion University of the Negev, Israel) |
| Công bố | arXiv:2105.14344, cs.CR, 29/05/2021 (22 trang) |
| Link | [arxiv.org/abs/2105.14344](https://arxiv.org/abs/2105.14344) |
| Mã nguồn | [github.com/yanivagman/tracee/tree/BPFroid](https://github.com/yanivagman/tracee/tree/BPFroid), xây trên Tracee của Aqua Security |
| Thiết bị thử nghiệm | Google Pixel 3a XL, Android 11, Linux kernel 4.9 (đã backport uprobes cho ARM64) |

Ý tưởng một câu: dùng **eBPF** (máy ảo trong kernel Linux) để theo dõi liên tục hành vi của mọi app **ngay trên điện thoại thật**, không sửa hệ điều hành hay app, và báo động tức thì khi khớp một signature hành vi.

## 2. Bài toán và động lực

Phân tích tĩnh không đủ, còn phân tích động trong sandbox thì bị malware né; paper đề xuất giám sát động **thường trực trên thiết bị thật**, kiểu một module EDR (Endpoint Detection and Response) chạy nền.

**Vì sao phân tích tĩnh thất bại.** Malware hiện đại dùng làm rối mã (obfuscation), Java reflection và nạp mã động (dynamic code loading). Mã độc chỉ xuất hiện lúc chạy nên máy quét APK không thấy. Paper dẫn nghiên cứu cho thấy đa số sản phẩm anti-malware bị ảnh hưởng nặng chỉ vì obfuscation đơn giản.

**Vì sao sandbox không đủ.**

- Malware nhận ra môi trường giả lập (IMEI, thông tin sóng, phần cứng) rồi giả vờ vô hại, trở thành false negative và được cài lên máy thật.
- Payload có thể chỉ kích hoạt sau một sự kiện (khởi động lại, hẹn giờ), nên sandbox chạy ngắn không bắt được, nhất là với tấn công zero-day.
- Sandbox cần môi trường đặc biệt và tốn tài nguyên, không chạy được trên máy người dùng.

**Khoảng trống nghiên cứu.** Các giải pháp động trước đó hoặc phải sửa hệ điều hành/app, hoặc chạy cùng quyền với app nên bị phát hiện và vô hiệu hóa, hoặc chỉ thấy syscall mà không thấy lời gọi Android API. Theo paper, chưa có phương pháp phát hiện thời gian thực trên thiết bị nào vừa nhẹ vừa hiệu quả; BPFroid là framework phát hiện malware Android đầu tiên dùng eBPF.

**Vì sao giám sát nhiều tầng.** Một app muốn gây hại phải giao tiếp với hệ thống qua Android framework API, qua thư viện native, hoặc gọi thẳng syscall. Chỉ hook một tầng thì malware đi vòng qua tầng khác, nên BPFroid theo dõi cả bốn tầng: API, native, syscall và hàm nội bộ của kernel.

## 3. Yêu cầu thiết kế và so sánh với các hướng khác

Paper đặt 10 yêu cầu cho một bộ phát hiện malware có thể cài sẵn trong Android, và cho rằng chỉ cách dùng eBPF đạt đủ R1–R8.

| Mã | Yêu cầu | Ý nghĩa |
| --- | --- | --- |
| R1 | Ranh giới bảo mật mạnh | Bộ giám sát không được cùng mức quyền với app, nếu không app sẽ phát hiện và vô hiệu hóa nó |
| R2 | Giám sát mọi tương tác hệ thống | Thấy được framework API, thư viện native và syscall |
| R3 | Không sửa system image | Không sửa Android hay mã kernel |
| R4 | Không sửa app | Không đổi APK/bytecode (sẽ phá chữ ký hoặc bị integrity check phát hiện) |
| R5 | Độc lập nền tảng | Chạy được trên thiết bị thật |
| R6 | Dễ port | Thêm/bớt điểm hook dễ dàng khi Android ra phiên bản mới |
| R7 | Mở rộng được | Giám sát nhiều app cùng lúc |
| R8 | An toàn | Lỗi trong bộ giám sát không được làm sập app hay hệ thống |
| R9 | Ẩn mình | Khó bị phát hiện, nếu không malware sẽ giả vờ vô hại |
| R10 | Chi phí thấp | Chỉ dùng một phần nhỏ tài nguyên của máy |

So sánh theo R1–R8 (✓ đạt, ✗ không đạt, – paper không nêu trong phần văn bản; ký hiệu dựng lại từ lời văn, nên đối chiếu Table 1 trong PDF):

| Hướng tiếp cận | Ví dụ | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Sửa AOSP | TaintDroid, TraceDroid | – | ✗ | ✗ | ✓ | ✓ | ✗ | ✓ | – |
| Kernel module | MADAM, DroidRevealer | ✓ | ✗ | ✗ | – | ✓ | – | ✓ | ✗ |
| Sửa app (viết lại APK/oat/dex) | – | ✗ | ✗ | – | ✗ | – | – | ✗ | – |
| Tiêm thư viện | Xposed, Frida, ADBI | ✗ | – | ✓ | ✓ | – | – | – | ✗ |
| Introspection máy ảo (VMI) | CopperDroid, DroidScope | ✓ | ✗ | ✓ | ✓ | ✗ | – | – | – |
| **BPFroid (eBPF)** | – | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

eBPF đạt R1 vì chạy trong kernel, R8 vì mọi chương trình BPF phải qua **verifier** của kernel (không thể làm sập hệ thống hay truy cập bộ nhớ sai), và R3/R4 vì eBPF đã có sẵn trên Android mới. R9 (ẩn mình) và R10 (chi phí) được đánh giá riêng ở mục 6.

## 4. Kiến trúc và cách hoạt động

BPFroid gắn các chương trình eBPF vào bốn tầng của Android, lọc sự kiện ngay trong kernel, rồi đẩy sự kiện qua ring buffer lên một tiến trình user space chạy signature.

**Nền tảng kỹ thuật.**

- **eBPF:** máy ảo trong kernel Linux cho phép nạp bytecode và chạy khi một sự kiện xảy ra. Bytecode được verifier kiểm tra rồi JIT sang mã máy, nên vừa an toàn vừa nhanh. Chương trình có thể lọc sự kiện trong kernel và chia sẻ dữ liệu với user space qua map và buffer.
- **kprobe / uprobe:** đặt điểm dừng động tại gần như mọi địa chỉ mã trong kernel (kprobe) hoặc trong user space (uprobe); tracepoint `raw_syscalls` bắt mọi syscall.
- **ART + oat:** từ Android 5, framework được biên dịch trước (AOT) thành file oat (thực chất là ELF). Công cụ `oatdump` có sẵn trên máy cho biết offset của từng phương thức Java đã biên dịch.
- **Zygote:** mọi app là bản fork của zygote, nên framework và thư viện native nằm ở **cùng địa chỉ** trong mọi app. Chỉ cần tính địa chỉ một lần từ zygote là gắn uprobe được cho tất cả app.

**Các tầng được giám sát** (khai báo trong file cấu hình hook):

| Tầng | Cơ chế hook | Ví dụ |
| --- | --- | --- |
| Android framework API | uprobe trên mã oat đã biên dịch | `openDexFile`, gửi SMS |
| Thư viện native | uprobe trên symbol trong `.so` | hàm libc `open` |
| Syscall Linux | tracepoint `raw_syscalls` vào/ra | `execve`, `write` |
| Hàm nội bộ kernel | kprobe | `vfs_write` |

**Luồng xử lý:**

1. **Hooks Configuration File:** người dùng chọn các sự kiện cần theo dõi.
2. **Address Extractor:** đọc `/proc/<pid zygote64>/maps` lấy địa chỉ nền của các file `.oat`/`.so`; chạy `oatdump` lấy offset phương thức và kiểu tham số; cộng lại thành địa chỉ đặt uprobe.
3. **BPF Initializer:** nạp chương trình BPF vào kernel, gắn vào syscall tracepoint, kprobe, uprobe; tạo map và perf buffer.
4. **Probe Handlers (trong kernel):** khi sự kiện xảy ra, kiểm tra bộ lọc (UID, PID…), thu ngữ cảnh (pid, tid, ppid, uid, timestamp, tên tiến trình) và tham số, ghi vào ring buffer. Một handler uprobe chung dùng địa chỉ lệnh làm khóa tra metadata.
5. **Event Dispatcher + Parser (user space):** đọc buffer, giải mã, đổi địa chỉ thành tên lớp/phương thức.
6. **Behavioral Signatures:** áp luật lên sự kiện và báo động theo thời gian thực.

Vì mọi app có UID riêng, muốn giám sát một app chỉ cần lọc theo UID hoặc tên package; cũng có thể giám sát toàn bộ app.

## 5. Hai signature hành vi

Paper minh họa sức mạnh của eBPF bằng hai luật đơn giản chạy ngay trong kernel: phát hiện app **thả payload** và phát hiện app **leo thang đặc quyền**.

### 5.1 Dropper Detection

- **Mối đe dọa:** "dropper" là app trông vô hại, xin ít quyền, nên lọt qua Play Store. Khi đã chạy, nó giải nén hoặc tải về payload giai đoạn hai mạnh hơn nhiều.
- **Luật:** hook hàm kernel `vfs_write`/`vfs_writev` (được gọi mỗi khi ghi file). Nếu lần ghi chạm vào 4 byte đầu của file và 4 byte đó là magic number của ELF (`\x7fELF`), DEX (`dex\n`) hoặc archive APK/JAR/ZIP (`PK\x03\x04`) thì báo động kèm đường dẫn, device ID và inode.
- **Vì sao hook kernel thay vì syscall:** nếu chỉ theo dõi syscall `write`, phải tự theo dõi bảng file descriptor và offset của từng tiến trình qua nhiều syscall. `vfs_write` nhận thẳng `struct file` (có device ID, inode, đường dẫn) và offset, nên biết ngay lần ghi có sửa header file hay không.
- **Thu bằng chứng:** BPFroid còn chép toàn bộ dữ liệu được ghi qua buffer chung kernel–user space, để lưu lại payload phục vụ điều tra (forensics).

### 5.2 Privilege Escalation Detection

- **Mối đe dọa:** exploit như DirtyCow đã được FinSpy và Pegasus cho Android (Chrysaor) dùng để chiếm root trên máy chưa root, từ đó toàn quyền kiểm soát thiết bị.
- **Luật:** mỗi app Android có UID riêng và không đổi trong suốt thời gian chạy. Sau khi tiến trình app được fork, lưu PID → UID vào một hash map eBPF; giữa hai syscall liên tiếp, nếu UID khác thì báo động.
- **Ưu điểm:** không cần biết exploit cụ thể, nên có thể bắt cả exploit zero-day ngay khi nó thành công.

## 6. Thực nghiệm và kết quả

Trên 200 mẫu malware thật (2019–2020), BPFroid bắt được 33 mẫu thả file, tìm ra 7 file độc chưa từng có trên VirusTotal, với chi phí hiệu năng 2–12% tùy cấu hình.

### 6.1 Kết quả phát hiện

Thiết lập: Pixel 3a XL, Android 11 với bản vá mới nhất; 200 mẫu malware từ kho AndroidMalware_2019/2020 và skptr.me.

| Signature | Kết quả |
| --- | --- |
| Dropper | 33 mẫu thả file: 9 mẫu thả ELF, 11 mẫu thả DEX, 16 mẫu thả archive (apk/jar/zip) |
| Dropper – đối chiếu VirusTotal | 20 file thả ra đã bị VirusTotal biết là độc; 11 file chưa từng có, tải lên lần đầu thì 7 file là độc |
| Privilege escalation | 0 mẫu leo quyền thành công; đúng kỳ vọng vì thiết bị đã vá |

Ví dụ file bị thả mà paper ghi lại: `/data/user/0/org.rabbit/files/rssocks` (ELF), `.../com.firebear.androil/files/AdDex.4.0.1.dex` (DEX), `/storage/emulated/0/Aarogya Setu Support/base.apk` (APK). Payload hay được đặt trong thư mục riêng của app với tên ngụy trang như `libexec.so`, `.jiagu/libjiagu.so`, `DAOO.json`. Trong mẫu Covid Cerberus, BPFroid ghi được cả chuỗi: syscall và hàm libc mở `classes.dex` → cảnh báo ghi file → lời gọi API `openDexFile` nạp nó; file DEX bắt được bị VirusTotal xác định là trojan.

### 6.2 Chi phí hiệu năng (R10)

Geekbench 5, trung bình 5 lần, điểm càng cao càng tốt; phần trăm là mức giảm so với không chạy BPFroid. Bộ "đa tầng" gồm 50 hàm API, 4 hàm native, 49 syscall, 3 hàm kernel; bộ "mọi syscall" gồm toàn bộ syscall.

| App được theo dõi | Bộ sự kiện | Đơn nhân | Đa nhân |
| --- | --- | --- | --- |
| Không chạy BPFroid | – | 337 | 1225 |
| Không app nào | Đa tầng | 323 (−4,15%) | 1200 (−2,04%) |
| Không app nào | Mọi syscall | 323 (−4,15%) | 1200 (−2,04%) |
| Chỉ Geekbench | Đa tầng | 313 (−7,12%) | 1185 (−3,27%) |
| Chỉ Geekbench | Mọi syscall | 301 (−10,68%) | 1095 (−10,61%) |
| Mọi app (UID > 10000) | Đa tầng | 313 (−7,12%) | 1172 (−4,33%) |
| Mọi app (UID > 10000) | Mọi syscall | 301 (−10,68%) | 1078 (−12%) |

Nhận xét của paper:

- Chạy nền không theo dõi app nào vẫn tốn 2–4%, vì tracepoint `raw_syscalls` kích hoạt ở mọi syscall của hệ thống để kiểm tra bộ lọc.
- Bắt mọi syscall tốn hơn vì gồm các lời gọi rất dày như `read`, `write`; bỏ chúng khỏi danh sách sẽ giảm chi phí.
- Điểm đơn nhân không đổi giữa theo dõi một app hay mọi app, vì xử lý sự kiện ở user space chỉ cần một nhân; điểm đa nhân giảm dần vì phải chia CPU với BPFroid.

### 6.3 Khả năng bị malware phát hiện (R9)

- Chạy trên máy thật nên các kiểm tra chống giả lập thất bại.
- Không dùng ptrace hay JDWP nên kiểm tra debugger thất bại.
- Không tiêm thư viện, không sửa bộ nhớ hay file của app nên integrity check thất bại.
- Liệt kê chương trình BPF cần `CAP_SYS_ADMIN`, app thường không có.
- Điểm yếu: kiểm tra root sẽ thành công vì BPFroid cần root; uprobe là breakpoint trong bộ nhớ thư viện hệ thống nên về lý thuyết app có thể dò ra trong tương lai.

## 7. Hạn chế và hướng phát triển

Hạn chế lớn nhất là BPFroid cần quyền root để nạp chương trình BPF; paper đề xuất phân phối nó như một thành phần của system image.

**Hạn chế paper thừa nhận:**

1. Nạp BPF cần `CAP_SYS_ADMIN`, nên hiện phải chạy với quyền root (và việc máy đã root lại bị malware kiểm tra được).
2. Chỉ hook được API đã biên dịch AOT; hàm được JIT thì không. Hai hàm khác nhau có thể trỏ cùng một đoạn mã đã biên dịch (ví dụ hàm rỗng `Service.onCreate()` và `onDestroy()`).
3. Chưa đọc tham số của lời gọi Android API (phải hiểu cách Java lưu String… trong bộ nhớ).
4. App build ở chế độ `debuggable` chạy bằng trình thông dịch, nên lời gọi API của nó không bị bắt.
5. Verifier giới hạn chương trình BPF: không vòng lặp tùy ý, kích thước mã có hạn.

**Hướng phát triển paper đề xuất:**

- Không chỉ cảnh báo mà **chặn** hành vi độc: ghi đè giá trị trả về của syscall, hoặc dùng LSM BPF (kernel 5.7+).
- Viết lại bằng eBPF API chính thức của Google để nhà sản xuất dễ tích hợp vào system image.
- Dùng perf event / bộ đếm CPU để phát hiện tấn công dựa trên phần cứng.
- Kết hợp với phân tích tĩnh, hoặc đưa dữ liệu thu được vào mô hình học máy (có thể chạy trên server).

**Hạn chế nhóm tự kiểm chứng thêm khi hiện thực** (chi tiết ở mục 9): signature Dropper bị né nếu tách magic bytes thành hai lần ghi nhỏ hơn 4 byte, hoặc nếu chép file bằng cơ chế trong kernel (`cp` cùng phân vùng) không đi qua điểm hook `vfs_write`.

## 8. Liên hệ với đề tài Security on device và tối ưu di động

BPFroid là ví dụ điển hình của bài toán tối ưu trên thiết bị di động: muốn giám sát liên tục mọi app mà chỉ được tốn vài phần trăm CPU, nên phải đẩy việc lọc xuống kernel và chỉ đưa lên user space những gì thật sự cần.

**Vì sao là "on device".** Phát hiện ngay trên máy giúp: báo động tức thì khi payload vừa được ghi ra; không phải gửi file hay hành vi của người dùng lên server; vẫn hoạt động khi không có mạng; và bắt được malware chỉ kích hoạt trên máy thật, điều mà sandbox trên cloud bỏ lỡ.

**Các kỹ thuật tối ưu trong thiết kế BPFroid:**

| Kỹ thuật | Tác dụng |
| --- | --- |
| Lọc sự kiện trong kernel (theo UID, PID, loại sự kiện) | Không tốn chi phí sao chép và phân tích sự kiện không liên quan ở user space |
| So khớp signature ngay trong kernel (đọc 4 byte magic tại `vfs_write`) | Chỉ lần ghi khớp mới được gửi lên, thay vì hàng triệu lần ghi |
| BPF được JIT sang mã máy | Handler chạy nhanh như mã kernel gốc |
| Tận dụng zygote + AOT | Tính địa chỉ hook một lần cho mọi app, không phải vá từng app |
| Cho phép chọn tập sự kiện | Bỏ syscall dày đặc (`read`, `write`) để hạ chi phí từ ~11% xuống ~4–7% |
| Cấu hình thích ứng | Giám sát cả hệ thống với signature nhẹ, hoặc chỉ theo dõi kỹ app mới cài trong một thời gian |

**Đánh đổi cần thảo luận:** độ phủ (bắt nhiều sự kiện) ngược chiều với hiệu năng; signature đơn giản thì rẻ nhưng sinh cảnh báo với cả hoạt động hợp lệ (cài app, `dex2oat`), cần thêm ngữ cảnh như UID/package để phân biệt. Câu hỏi mở: paper chỉ đo CPU bằng Geekbench, chưa đo mức tiêu thụ pin và bộ nhớ.

**So với hướng phân tích tĩnh (MobiTive – phần trước của đồ án):**

| Tiêu chí | MobiTive (tĩnh, GRU + TFLite) | BPFroid (động, eBPF) |
| --- | --- | --- |
| Thời điểm | Trước khi cài/chạy, quét APK theo yêu cầu | Liên tục trong lúc app chạy |
| Dữ liệu | API call và manifest trong APK | Sự kiện thật: ghi file, đổi UID, syscall, API |
| Nạp mã động, làm rối mã | Dễ bị qua mặt | Bắt được lúc payload xuất hiện |
| Quyền cần có | App thường | Root hoặc cài sẵn trong hệ thống |
| Chi phí | Một lần suy luận mỗi lần quét | 2–12% CPU khi chạy nền |

Hai hướng bổ sung cho nhau, đúng như paper gợi ý ở phần hướng phát triển: lớp tĩnh sàng lọc trước khi cài, lớp động bắt những gì lọt qua lúc chạy.

## 9. Hiện thực trong đồ án

Nhóm tái hiện cả hai signature của paper trên Android Emulator x86_64 (đã root), giám sát toàn hệ thống, và hiển thị cảnh báo theo tên app trên một app Dashboard.

**Thành phần:**

1. **Engine `tracee-android`:** bản BPFroid (fork Tracee) build bằng Android NDK r30 cho `android/amd64`. Chạy hai sự kiện `write_alert` (Dropper) và `uid_changed_alert` (Privilege Escalation). Bản vá và script build: `BPFroidDashboard/engine/`.
2. **Bridge:** script shell nghe TCP `127.0.0.1:8765`, nhận lệnh `START`, `STOP`, `STATUS`, `LOGS`, `POLL`; tự dọn kprobe cũ khi dừng để lần khởi động sau không lỗi. Mã nguồn: `BPFroidDashboard/bridge/bpfroid-bridge-handler.sh`.
3. **App BPFroid Dashboard (Java):** hỏi bridge mỗi 2 giây, đổi UID thành tên package, đếm cảnh báo theo loại (ELF, ZIP/APK, DEX, leo thang đặc quyền).

**Điều chỉnh so với mã gốc của BPFroid:**

- Chỉ gắn kprobe `vfs_write` mà không gửi từng lần ghi lên user space; chỉ lần ghi khớp magic mới tạo sự kiện. Log engine giảm từ **155 MB xuống khoảng 3 KB**, cảnh báo ghi ra file riêng.
- Signature leo quyền chỉ báo khi UID **tăng quyền** (thành root, hoặc từ UID app xuống UID hệ thống). Bản gốc báo mọi lần đổi UID, nên mỗi lần zygote hạ quyền để mở app (0 → UID app) đều thành báo động giả.
- Xóa UID đã lưu của thread khi thread thoát, tránh báo động giả khi TID được tái sử dụng.

**Kết quả các kịch bản demo** (hành vi malware được mô phỏng bằng file vô hại, chạy dưới UID của một app thường qua `run-as`; lệnh chi tiết ở mục 4 của `README.md`):

| Mã | Kịch bản | Mô phỏng tấn công | Kết quả |
| --- | --- | --- | --- |
| D1 | App giải nén `classes.dex` ra thư mục riêng | Nạp mã DEX động từ máy chủ điều khiển | Cảnh báo DEX |
| D2 | App thả binary ELF thành `libpayload.so` rồi chạy | Exploit, cryptominer, backdoor native | Cảnh báo ELF |
| D3 | App ghi một file APK | Tải app độc thứ hai để dụ cài | Cảnh báo ZIP/APK |
| D4 | Ghi ELF thành `.thumb.jpg` | Ngụy trang bằng đuôi file | Cảnh báo ELF |
| N1 | Ghi file text | Đối chứng | Không báo |
| P1 | `su 2000 su 0 id` | Exploit chiếm root | Cảnh báo leo quyền 2000 → 0 |
| P2 | App gọi `su` | App thường cố chiếm root | Bị SELinux chặn, không báo |
| P3 | Mở app Cài đặt | Đối chứng (zygote hạ quyền) | Không báo |
| L1 | Tách magic thành 2 lần ghi | Né signature | Lọt (hạn chế) |
| L2 | `cp` APK trong cùng phân vùng | Né signature (kernel tự chép) | Lọt (hạn chế) |

Khác biệt với paper cần nêu khi trình bày: chạy trên emulator x86_64 thay vì Pixel 3a ARM64; chỉ dùng hai sự kiện tầng kernel/syscall, chưa hook Android API qua uprobe; chưa chạy mẫu malware thật và chưa đo chi phí hiệu năng bằng Geekbench.

## Nguồn

- Y. Agman, D. Hendler. [BPFroid: Robust Real Time Android Malware Detection Framework](https://arxiv.org/abs/2105.14344), arXiv:2105.14344, 2021. Mọi số liệu ở mục 1–7 lấy từ bản PDF này.
- Mã nguồn BPFroid: [yanivagman/tracee, nhánh BPFroid](https://github.com/yanivagman/tracee/tree/BPFroid).
- Mục 9 dựa trên mã nguồn và kết quả chạy thử của nhóm (repo đồ án, thư mục `BPFroidDashboard/`); mục 8 so sánh với [MobiTive, arXiv:2005.04970](https://arxiv.org/abs/2005.04970).
