
from collections import defaultdict


ANDROID_NS = (
    "http://schemas.android.com/apk/res/android"
)

ANDROID_NAME = f"{{{ANDROID_NS}}}name"


def extract_manifest_features(apk) -> dict:
    """
    Trích xuất ba nhóm đặc trưng từ AndroidManifest.xml:

    1. Permissions
    2. Intents (actions và categories)
    3. Hardware features
    """

    manifest = apk.get_android_manifest_xml()

    if manifest is None:
        raise ValueError("Không đọc được AndroidManifest.xml")

    # -----------------------------------
    # 1. Permissions
    # -----------------------------------

    permissions = set(apk.get_permissions() or [])

    # -----------------------------------
    # 2. Intents
    # -----------------------------------

    intents = set()

    component_tags = {
        "activity",
        "activity-alias",
        "service",
        "receiver",
    }

    for component in manifest.iter():
        tag = component.tag

        if not isinstance(tag, str):
            continue

        # Loại bỏ namespace nếu có
        tag_name = tag.split("}")[-1]

        if tag_name not in component_tags:
            continue

        for intent_filter in component:
            filter_tag = intent_filter.tag.split("}")[-1]

            if filter_tag != "intent-filter":
                continue

            for child in intent_filter:
                child_tag = child.tag.split("}")[-1]

                if child_tag in {"action", "category"}:
                    name = child.get(ANDROID_NAME)

                    if name:
                        intents.add(name)

    # -----------------------------------
    # 3. Hardware features
    # -----------------------------------

    hardware_features = set()

    for element in manifest.iter():
        tag = element.tag

        if not isinstance(tag, str):
            continue

        tag_name = tag.split("}")[-1]

        if tag_name != "uses-feature":
            continue

        feature_name = element.get(ANDROID_NAME)

        if feature_name:
            hardware_features.add(feature_name)

    return {
        "permissions": sorted(permissions),
        "intents": sorted(intents),
        "hardware_features": sorted(hardware_features),
    }
