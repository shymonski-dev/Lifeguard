#!/usr/bin/env python3
from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, metadata


TARGET_PACKAGES = {
    "langchain": ("mit",),
    "langgraph": ("mit",),
}


def _license_is_approved(license_value: str, classifiers: list[str], keywords: tuple[str, ...]) -> bool:
    normalized_license = license_value.lower()
    normalized_classifiers = " ".join(classifiers).lower()
    for keyword in keywords:
        if keyword in normalized_license:
            return True
        if keyword in normalized_classifiers:
            return True
    return False


def _check_package(name: str, keywords: tuple[str, ...]) -> tuple[bool, str]:
    try:
        package_metadata = metadata(name)
    except PackageNotFoundError:
        return False, f"{name}: package is not installed."

    license_value = (package_metadata.get("License") or "").strip()
    classifiers = package_metadata.get_all("Classifier") or []
    if _license_is_approved(license_value, list(classifiers), keywords):
        return True, f"{name}: approved license detected."

    classifier_text = "; ".join(classifiers) if classifiers else "none"
    return (
        False,
        f"{name}: unapproved license. License field='{license_value or 'empty'}'; "
        f"classifiers='{classifier_text}'.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Checks that approved open source licenses are used for runtime graph packages.",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Do not fail when target packages are not installed.",
    )
    args = parser.parse_args(argv)

    failures: list[str] = []
    for package_name, keywords in TARGET_PACKAGES.items():
        ok, message = _check_package(package_name, keywords)
        if ok:
            print(f"PASS: {message}")
            continue

        if "not installed" in message and args.allow_missing:
            print(f"SKIP: {message}")
            continue

        print(f"FAIL: {message}")
        failures.append(message)

    if failures:
        print("License check failed.")
        return 1

    print("License check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
