"""
Search an APK's extracted smali code for URLs, emails, and IP addresses and
save the unique matches into a JSON file.

license: GPLv3

author: Jean-Luc Tibaux

DISCLAIMER:
Use only at your own risk. Your mileage may vary.
No warranty of any kind is provided.
"""

import argparse
import json
import logging
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path
from pprint import pprint

import regex
from ripgrepy import Ripgrepy


def configure_logger(log_path: Path):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        format="%(asctime)-s %(levelname)s [%(name)s]: %(message)s",
        level=logging.INFO,
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def find_apk_files(directory: Path):
    apk_files = sorted(directory.glob("*.apk"))
    if not apk_files:
        raise FileNotFoundError(f"No APK files found in '{directory}'")
    return apk_files


def parse_ripgrepy_matches(matches):
    if not matches:
        return []
    return matches


def dedupe_counter(matches):
    cleaned_matches = OrderedDict()
    for value in matches:
        if value not in cleaned_matches:
            cleaned_matches[value] = 1
        else:
            cleaned_matches[value] += 1
    return cleaned_matches


def normalize_http_matches(match_list):
    cleaned_matches = OrderedDict()
    url_re_pattern = regex.compile(
        r'(?im)\b((?:[a-z][\w-]+:(?:\/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'
    )

    for match_dict in match_list:
        try:
            match_text = str(match_dict.get("data", {}).get("lines", {}).get("text", "")).strip()
            if not match_text:
                continue

            extracted = regex.findall(url_re_pattern, match_text)
            if not extracted:
                continue

            url_temp = str(extracted[0][0]).strip()
            if url_temp:
                cleaned_matches[url_temp] = cleaned_matches.get(url_temp, 0) + 1
        except Exception as error_msg:
            logging.error(f"Failed to parse URL match -> error: {error_msg}")

    return OrderedDict(sorted(cleaned_matches.items()))


def normalize_email_matches(match_list):
    cleaned_matches = OrderedDict()
    for match_dict in match_list:
        try:
            email_temp = str(match_dict.get("data", {}).get("lines", {}).get("text", "")).strip()
            if email_temp:
                cleaned_matches[email_temp] = cleaned_matches.get(email_temp, 0) + 1
        except Exception as error_msg:
            logging.error(f"Failed to parse email match -> error: {error_msg}")
    return OrderedDict(sorted(cleaned_matches.items()))


def normalize_ip_matches(match_list):
    cleaned_matches = OrderedDict()
    for match_dict in match_list:
        try:
            ip_temp = str(match_dict.get("data", {}).get("lines", {}).get("text", "")).strip()
            if ip_temp:
                cleaned_matches[ip_temp] = cleaned_matches.get(ip_temp, 0) + 1
        except Exception as error_msg:
            logging.error(f"Failed to parse IP match -> error: {error_msg}")
    return OrderedDict(sorted(cleaned_matches.items()))


def run_apktool(apk_file: Path, output_dir: Path):
    logging.debug(f"Reverse engineering '{apk_file}' using apktool ...")
    result = subprocess.run(
        ["apktool", "d", str(apk_file), "-o", str(output_dir), "-f"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"apktool failed for '{apk_file}' with exit code {result.returncode}: {result.stderr}"
        )
    logging.debug(f"Saved extracted APK contents to '{output_dir}'")


def main():
    parser = argparse.ArgumentParser(
        description="Search extracted APK smali code for URLs, emails, and IP addresses."
    )
    parser.add_argument(
        "--apk-dir",
        default="TinyWeatherForecastGermanyScan",
        help="Directory containing the APK to be decompiled.",
    )
    parser.add_argument(
        "--smali-dir",
        default="TinyWeatherForecastGermanyApk",
        help="Directory where apktool outputs the decompiled smali tree.",
    )
    parser.add_argument(
        "--output-json",
        default="TinyWeatherForecastGermanyScan/rg-pattern-matches.json",
        help="Path to the output JSON file.",
    )
    args = parser.parse_args()

    working_dir = Path(args.apk_dir)
    working_dir.mkdir(parents=True, exist_ok=True)
    configure_logger(working_dir / "debug.log")

    apk_files = find_apk_files(working_dir)
    pprint(apk_files)
    apk_file_p = apk_files[0]

    smali_dir = Path(args.smali_dir)
    run_apktool(apk_file_p, smali_dir)

    rg_pattern = "(?im)http(s)*://"
    rg = Ripgrepy(rg_pattern, str(smali_dir / "smali"))
    http_matches_list = parse_ripgrepy_matches(rg.H().n().json().run().as_dict)
    logging.info("Found %s URL matches in smali code", len(http_matches_list))
    http_cleaned_matches = normalize_http_matches(http_matches_list)

    rg = Ripgrepy(
        r"(?im)^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$",
        str(smali_dir / "smali"),
    )
    email_matches_list = parse_ripgrepy_matches(rg.H().n().json().run().as_dict)
    logging.info("Found %s email matches in smali code", len(email_matches_list))
    email_cleaned_matches = normalize_email_matches(email_matches_list)

    rg = Ripgrepy(r"(?im)\b(?:\d{1,3}\.){3}\d{1,3}\b", str(smali_dir / "smali"))
    ip_matches = parse_ripgrepy_matches(rg.H().n().json().run().as_dict)
    ipaddress_cleaned_matches = normalize_ip_matches(ip_matches)

    pprint(dict(http_cleaned_matches))
    pprint(dict(email_cleaned_matches))
    pprint(dict(ipaddress_cleaned_matches))

    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with output_json.open("w+", encoding="utf-8") as file_handle:
        file_handle.write(
            json.dumps(
                {
                    "http": dict(http_cleaned_matches),
                    "emails": dict(email_cleaned_matches),
                    "ipaddress": dict(ipaddress_cleaned_matches),
                },
                indent=4,
            )
        )

    print(f"Saved match summary to {output_json}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover - command-line failure path
        logging.exception("Scan failed: %s", exc)
        sys.exit(1)
