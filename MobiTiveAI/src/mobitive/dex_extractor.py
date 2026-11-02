
import re

INVOKE_PREFIX = "invoke-"

METHOD_PATTERN = re.compile(
    r"(L[^;\s,]+;->[^\s,(]+\([^)]*\)[^\s,]*)"
)

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


def is_framework_api(method_descriptor: str) -> bool:
    """Kiểm tra method có thuộc namespace API hệ thống hay không."""

    return method_descriptor.startswith(FRAMEWORK_PREFIXES)


def extract_api_calls(dex_list) -> dict:
    """
    Trích xuất các method được gọi từ DEX.

    Chỉ giữ các method thuộc namespace Android/Java phổ biến.
    Không thực thi APK.
    """

    api_calls = set()
    api_call_count = {}

    invoke_instruction_count = 0
    matched_method_count = 0
    framework_invoke_count = 0

    parsed_class_count = 0
    parsed_method_count = 0

    for dex_index, dex in enumerate(dex_list):
        print(f"[DEX] Đang phân tích DEX #{dex_index + 1}")

        for class_def in dex.get_classes():
            parsed_class_count += 1

            for method in class_def.get_methods():
                parsed_method_count += 1

                code = method.get_code()

                if code is None:
                    continue

                bytecode = code.get_bc()

                for instruction in bytecode.get_instructions():
                    instruction_name = instruction.get_name()

                    if not instruction_name.startswith(INVOKE_PREFIX):
                        continue

                    invoke_instruction_count += 1

                    output = instruction.get_output()

                    if not output:
                        continue

                    match = METHOD_PATTERN.search(output)

                    if not match:
                        continue

                    descriptor = match.group(1).strip()
                    matched_method_count += 1

                    if not is_framework_api(descriptor):
                        continue

                    framework_invoke_count += 1

                    api_calls.add(descriptor)

                    api_call_count[descriptor] = (
                        api_call_count.get(descriptor, 0) + 1
                    )

    sorted_api_calls = sorted(api_calls)

    return {
        "api_calls": sorted_api_calls,
        "api_call_count": api_call_count,
        "unique_api_call_count": len(sorted_api_calls),
        "invoke_instruction_count": invoke_instruction_count,
        "matched_method_count": matched_method_count,
        "framework_invoke_count": framework_invoke_count,
        "parsed_class_count": parsed_class_count,
        "parsed_method_count": parsed_method_count,
    }
