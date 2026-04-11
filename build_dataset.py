"""
Script to build a training dataset from a folder of .eml files.

Usage:
    uv run python build_dataset.py data/raw/phishing data/raw/legitimate data/processed/dataset.csv
"""

import sys
import csv
from pathlib import Path

from phish_detector.parser import parse_eml
from phish_detector.features import extract_features


def build_dataset(phishing_dir: Path, legitimate_dir: Path, output_path: Path):
    rows = []

    for label, folder in [("phishing", phishing_dir), ("legitimate", legitimate_dir)]:
        # Accept any file, not just .eml
        all_files = [f for f in folder.iterdir() if f.is_file()]
        if not all_files:
            print(f"Warning: no files found in {folder}")
            continue

        print(f"Processing {len(all_files)} {label} files...")
        ok = 0
        skipped = 0

        for file_path in all_files:
            try:
                parsed = parse_eml(file_path)
                features = extract_features(parsed)
                features["label"] = label
                features["file"] = file_path.name
                rows.append(features)
                ok += 1
            except Exception as e:
                skipped += 1

        print(f"  {ok} processed, {skipped} skipped")

    if not rows:
        print("No emails processed. Check your input folders.")
        sys.exit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDataset saved to {output_path} ({len(rows)} emails total)")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python build_dataset.py <phishing_dir> <legitimate_dir> <output_csv>")
        sys.exit(1)

    build_dataset(
        phishing_dir=Path(sys.argv[1]),
        legitimate_dir=Path(sys.argv[2]),
        output_path=Path(sys.argv[3]),
    )