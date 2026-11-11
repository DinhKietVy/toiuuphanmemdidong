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
