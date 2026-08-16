"""
Generate an HTML summary of embedded classes inside an APK.

This script scans a provided APK, extracts embedded class names, builds a
hierarchical tree, and writes the result into an HTML page for quick review.
"""

import argparse
from collections import defaultdict
from pathlib import Path

from androguard.misc import AnalyzeAPK
from bs4 import BeautifulSoup
from exodus_core.analysis.static_analysis import StaticAnalysis


def tree():
    """Return a nested defaultdict structure for building a class tree."""
    return defaultdict(tree)


def add_leafs(root, path_parts):
    """Insert a class path into the nested tree structure."""
    current = root
    for node in path_parts:
        current = current[node]
    return root


def find_apk_path(raw_path: str | Path) -> Path:
    """Resolve an APK path from a file path or directory containing one APK."""
    candidate = Path(raw_path)
    if candidate.is_dir():
        apk_files = sorted(candidate.glob("*.apk"))
        if not apk_files:
            raise FileNotFoundError(f"No .apk file found in '{candidate}'")
        return apk_files[0]
    if candidate.suffix.lower() == ".apk":
        return candidate

    matching = sorted(Path(".").glob(str(candidate)))
    if matching:
        return matching[0]
    raise FileNotFoundError(f"APK file not found: '{raw_path}'")


def build_classes_tree(embedded_classes):
    """Convert the embedded class list into a nested tree for HTML output."""
    classes_tree = tree()
    for embedded_class in sorted(set(embedded_classes)):
        try:
            class_parts = [part for part in str(embedded_class).split("/") if part]
            if class_parts:
                add_leafs(classes_tree, class_parts)
        except Exception as error_msg:
            print(f"ERROR: {error_msg}")
    return classes_tree


def print_classes_tree(tree_data, result, level):
    """Render the nested class tree into an HTML details structure."""
    for leaf in list(tree_data):
        level_indent = "-" * level
        leaf_name = str(leaf)
        if level == 1:
            leaf_name = f"<b>{leaf_name}</b>"
        result += (
            "\t<details><summary>|"
            + str(level_indent)
            + "> "
            + str(leaf_name)
            + "</summary>\n"
        )

        if dict(tree_data[leaf]):
            result = print_classes_tree(tree_data[leaf], result, level + 1)
        result += "</details>"
    return result


def main():
    """Analyze an APK and write a class hierarchy summary to an HTML file."""
    parser = argparse.ArgumentParser(
        description="Analyze an APK and build an HTML overview of embedded classes."
    )
    parser.add_argument(
        "apk",
        nargs="?",
        default="TinyWeatherForecastGermanyScan",
        help="Path to an APK file or a directory containing one.",
    )
    parser.add_argument(
        "--output",
        default="index.html",
        help="HTML file path to write the generated tree to.",
    )
    args = parser.parse_args()

    apk_path = find_apk_path(args.apk)
    output_path = Path(args.output)

    _, _, dx = AnalyzeAPK(str(apk_path.absolute()))
    _ = dx

    analysis = StaticAnalysis(str(apk_path.absolute()))
    embedded_classes = analysis.get_embedded_classes() or []
    classes_tree = build_classes_tree(embedded_classes)

    html_result = (
        "<details><summary>"
        + str(len(embedded_classes))
        + " class(es) detected</summary>\n"
    )
    html_result = str(print_classes_tree(dict(classes_tree), html_result, 1))
    html_result += "</details>\n"
    html_result = str(BeautifulSoup(html_result, features="html.parser").prettify())

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w+", encoding="utf-8") as file_handle:
        file_handle.write(html_result)

    print(f"Wrote summary to {output_path}")


if __name__ == "__main__":
    main()
