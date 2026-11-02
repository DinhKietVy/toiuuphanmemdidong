
from pathlib import Path
import hashlib

from androguard.misc import AnalyzeAPK


def calculate_sha256(file_path: str) -> str:
    """Tính SHA-256 của APK để định danh file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def parse_apk(file_path: str) -> dict:
    """
    Đọc APK và trả về các đối tượng APK, DEX, Analysis
    cùng thông tin cơ bản.

    Không cài đặt hoặc thực thi APK.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"APK không tồn tại: {file_path}")

    if path.suffix.lower() != ".apk":
        raise ValueError("File đầu vào phải có đuôi .apk")

    print(f"[APK] Đang phân tích: {path.name}")

    apk, dex_list, analysis = AnalyzeAPK(str(path))

    result = {
        "file_name": path.name,
        "file_path": str(path.resolve()),
        "file_size": path.stat().st_size,
        "sha256": calculate_sha256(str(path)),
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": apk.get_permissions(),
        "activities": apk.get_activities(),
        "services": apk.get_services(),
        "receivers": apk.get_receivers(),
        "dex_count": len(dex_list),
    }

    print("[APK] Đọc APK thành công")
    print(f"[APK] Package: {result['package_name']}")
    print(f"[APK] DEX files: {result['dex_count']}")

    return {
        "apk": apk,
        "dex_list": dex_list,
        "analysis": analysis,
        "metadata": result,
    }
