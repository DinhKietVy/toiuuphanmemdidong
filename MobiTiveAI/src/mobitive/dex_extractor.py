"""
Trích xuất API calls từ DEX.

M5 (mặc định): đọc trực tiếp bảng method_ids của DEX — đúng phương pháp
"binary code" của paper MobiTive (Feng et al., 2020, Sec. III-B.3).
Đây là bản port 1:1 của
MobiTive/app/src/main/java/com/example/mobitive/analyzer/DexMethodTable.java
và DexExtractor.java, để vector lúc train và lúc chạy trên điện thoại khớp nhau.

Định nghĩa feature:
    method_ids có defining class bắt đầu bằng FRAMEWORK_PREFIXES
    và KHÔNG bắt đầu bằng BUNDLED_LIBRARY_PREFIXES (Landroid/support/, Landroid/arch/).
    Không loại class "tự định nghĩa trong APK": R8 chèn stub class_defs cho
    API framework mới hơn minSdk (AppComponentFactory, Toast$Callback, ...).

Legacy (M0–M3.4): duyệt từng lệnh invoke-* bằng Androguard. Giữ lại chỉ để
đo parity/tốc độ (scripts/compare_dex_extractors.py).
"""

import re
import struct
import zipfile

# Các namespace API hệ thống cần giữ lại.
FRAMEWORK_PREFIXES = (
    "Landroid/",
    "Ljava/",
    "Ljavax/",
    "Ldalvik/",
    "Lorg/json/",
    "Lorg/xml/",
    "Lorg/w3c/",
    "Lorg/xmlpull/",
)

# Thư viện support/arch cũ nằm dưới Landroid/ nhưng là code đóng gói kèm app.
BUNDLED_LIBRARY_PREFIXES = (
    "Landroid/support/",
    "Landroid/arch/",
)

DEX_ENTRY = re.compile(r"classes(\d+)?\.dex")

MAX_DEX_BYTES = 128 * 1024 * 1024
MAX_TOTAL_DEX_BYTES = 512 * 1024 * 1024

HEADER_SIZE = 0x70
ENDIAN_CONSTANT = 0x12345678


def is_framework_api(method_descriptor: str) -> bool:
    """Kiểm tra method/class có thuộc namespace API hệ thống hay không."""

    return method_descriptor.startswith(FRAMEWORK_PREFIXES)


# ============================================================
# DEX method table parser (mirror of DexMethodTable.java)
# ============================================================

class DexFormatError(ValueError):
    pass


def _decode_mutf8(raw: bytes) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        pass

    units = []
    i, n = 0, len(raw)
    while i < n:
        a = raw[i]
        i += 1
        if a < 0x80:
            units.append(a)
        elif (a & 0xE0) == 0xC0:
            if i >= n:
                raise DexFormatError("MUTF-8 hỏng")
            units.append(((a & 0x1F) << 6) | (raw[i] & 0x3F))
            i += 1
        elif (a & 0xF0) == 0xE0:
            if i + 1 >= n:
                raise DexFormatError("MUTF-8 hỏng")
            units.append(((a & 0x0F) << 12) | ((raw[i] & 0x3F) << 6) | (raw[i + 1] & 0x3F))
            i += 2
        else:
            raise DexFormatError("MUTF-8 hỏng")

    return struct.pack(f"<{len(units)}H", *units).decode("utf-16-le", "surrogatepass")


class DexMethodTable:

    def __init__(self, data: bytes):
        if data is None or len(data) < HEADER_SIZE:
            raise DexFormatError("DEX quá nhỏ hoặc rỗng")
        if data[:4] != b"dex\n":
            raise DexFormatError("Sai DEX magic")

        self.data = data
        if self._u4(0x28) != ENDIAN_CONSTANT:
            raise DexFormatError("DEX endian không được hỗ trợ")

        self.string_ids_size = self._count(0x38)
        self.string_ids_off = self._u4(0x3C)
        self.type_ids_size = self._count(0x40)
        self.type_ids_off = self._u4(0x44)
        self.proto_ids_size = self._count(0x48)
        self.proto_ids_off = self._u4(0x4C)
        self.method_ids_size = self._count(0x58)
        self.method_ids_off = self._u4(0x5C)
        self.class_defs_size = self._count(0x60)
        self.class_defs_off = self._u4(0x64)

        self._check(self.string_ids_off, self.string_ids_size, 4)
        self._check(self.type_ids_off, self.type_ids_size, 4)
        self._check(self.proto_ids_off, self.proto_ids_size, 12)
        self._check(self.method_ids_off, self.method_ids_size, 8)
        self._check(self.class_defs_off, self.class_defs_size, 32)

        self._type_cache = {}
        self._proto_cache = {}

    # ---------------- low level ----------------

    def _u2(self, off):
        if off < 0 or off + 2 > len(self.data):
            raise DexFormatError("Đọc ngoài DEX")
        return self.data[off] | (self.data[off + 1] << 8)

    def _u4(self, off):
        if off < 0 or off + 4 > len(self.data):
            raise DexFormatError("Đọc ngoài DEX")
        return struct.unpack_from("<I", self.data, off)[0]

    def _count(self, off):
        value = self._u4(off)
        if value > len(self.data):
            raise DexFormatError("Kích thước section không hợp lệ")
        return value

    def _check(self, off, size, item_bytes):
        if size and (off < 0 or off + size * item_bytes > len(self.data)):
            raise DexFormatError("Section nằm ngoài DEX")

    def _string(self, idx):
        if idx >= self.string_ids_size:
            raise DexFormatError("string_idx ngoài phạm vi")
        off = self._u4(self.string_ids_off + idx * 4)
        data = self.data
        if off >= len(data):
            raise DexFormatError("string_data_off ngoài phạm vi")
        p = off
        for k in range(6):
            if p >= len(data) or k == 5:
                raise DexFormatError("ULEB128 hỏng")
            b = data[p]
            p += 1
            if not b & 0x80:
                break
        end = data.find(b"\x00", p)
        if end < 0:
            raise DexFormatError("Chuỗi DEX không kết thúc")
        return _decode_mutf8(data[p:end])

    def _type(self, idx):
        cached = self._type_cache.get(idx)
        if cached is None:
            if idx >= self.type_ids_size:
                raise DexFormatError("type_idx ngoài phạm vi")
            cached = self._string(self._u4(self.type_ids_off + idx * 4))
            self._type_cache[idx] = cached
        return cached

    def _proto(self, idx):
        cached = self._proto_cache.get(idx)
        if cached is None:
            if idx >= self.proto_ids_size:
                raise DexFormatError("proto_idx ngoài phạm vi")
            item = self.proto_ids_off + idx * 12
            params_off = self._u4(item + 8)
            params = []
            if params_off:
                size = self._count(params_off)
                self._check(params_off + 4, size, 2)
                params = [self._type(self._u2(params_off + 4 + k * 2)) for k in range(size)]
            cached = "(" + " ".join(params) + ")" + self._type(self._u4(item + 4))
            self._proto_cache[idx] = cached
        return cached

    # ---------------- public ----------------

    def defined_classes(self):
        return {
            self._type(self._u4(self.class_defs_off + i * 32))
            for i in range(self.class_defs_size)
        }

    def method_refs(self, class_filter):
        """Yield (defining_class, descriptor) cho method_ids qua được class_filter."""
        base = self.method_ids_off
        for i in range(self.method_ids_size):
            item = base + i * 8
            defining_class = self._type(self._u2(item))
            if not class_filter(defining_class):
                continue
            name = self._string(self._u4(item + 4))
            yield defining_class, f"{defining_class}->{name}{self._proto(self._u2(item + 2))}"


# ============================================================
# M5 extractor
# ============================================================

def read_dex_entries(apk_path):
    """Đọc classes*.dex ở gốc APK vào bộ nhớ (không ghi file tạm)."""
    total = 0
    result = []
    with zipfile.ZipFile(apk_path) as zf:
        for info in zf.infolist():
            if not DEX_ENTRY.fullmatch(info.filename):
                continue
            if info.file_size > MAX_DEX_BYTES:
                raise DexFormatError(f"DEX quá lớn: {info.filename}")
            data = zf.read(info)
            total += len(data)
            if total > MAX_TOTAL_DEX_BYTES:
                raise DexFormatError("Tổng dung lượng DEX vượt giới hạn")
            result.append((info.filename, data))
    return result


def extract_api_calls_from_dex_bytes(dex_entries) -> dict:
    """dex_entries: list[(name, bytes)]. Trả về cùng schema với app Android."""

    api_call_count = {}      # descriptor -> số DEX tham chiếu
    bundled_library_ref_count = 0

    class_def_count = 0
    method_ref_count = 0
    framework_method_ref_count = 0

    for _, data in dex_entries:
        table = DexMethodTable(data)
        class_def_count += table.class_defs_size
        method_ref_count += table.method_ids_size

        for defining_class, descriptor in table.method_refs(is_framework_api):
            framework_method_ref_count += 1
            # <clinit> là định nghĩa (vd. stub R8), không bao giờ là lời gọi.
            if ";-><clinit>(" in descriptor:
                continue
            if defining_class.startswith(BUNDLED_LIBRARY_PREFIXES):
                bundled_library_ref_count += 1
                continue
            api_call_count[descriptor] = api_call_count.get(descriptor, 0) + 1

    if not dex_entries:
        raise DexFormatError("Không tìm thấy classes.dex trong APK")

    api_calls = sorted(api_call_count)

    return {
        "extraction_method": "dex_method_ids_v2",
        "api_calls": api_calls,
        "api_call_count": api_call_count,
        "unique_api_call_count": len(api_calls),
        "dex_file_count": len(dex_entries),
        "class_def_count": class_def_count,
        "method_ref_count": method_ref_count,
        "framework_method_ref_count": framework_method_ref_count,
        "bundled_library_ref_count": bundled_library_ref_count,
    }


def extract_api_calls(apk_path) -> dict:
    """M5: trích xuất API calls từ bảng method_ids của mọi DEX trong APK."""

    return extract_api_calls_from_dex_bytes(read_dex_entries(apk_path))


# ============================================================
# Legacy extractor (M0–M3.4) — chỉ dùng để so sánh
# ============================================================

INVOKE_PREFIX = "invoke-"

METHOD_PATTERN = re.compile(
    r"(L[^;\s,]+;->[^\s,(]+\([^)]*\)[^\s,]*)"
)


def extract_api_calls_legacy(dex_list) -> dict:
    """
    Duyệt từng lệnh invoke-* bằng Androguard (cách cũ, chậm).
    dex_list: danh sách DalvikVMFormat từ androguard.misc.AnalyzeAPK.
    """

    api_calls = set()
    invoke_instruction_count = 0

    for dex in dex_list:
        for class_def in dex.get_classes():
            for method in class_def.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                for instruction in code.get_bc().get_instructions():
                    if not instruction.get_name().startswith(INVOKE_PREFIX):
                        continue
                    invoke_instruction_count += 1
                    match = METHOD_PATTERN.search(instruction.get_output() or "")
                    if match and is_framework_api(match.group(1).strip()):
                        api_calls.add(match.group(1).strip())

    return {
        "extraction_method": "androguard_invoke_walk",
        "api_calls": sorted(api_calls),
        "unique_api_call_count": len(api_calls),
        "invoke_instruction_count": invoke_instruction_count,
    }
