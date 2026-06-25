import argparse
import json
from pathlib import Path


def merge_json_files(input_dir: Path, output_file: Path) -> int:
    json_files = sorted(input_dir.glob("*.json"))
    if not json_files:
        raise FileNotFoundError(f"Tidak ada file .json di folder: {input_dir}")

    invalid_files: list[tuple[Path, str]] = []
    written = 0

    with output_file.open("w", encoding="utf-8") as out:
        out.write("[\n")

        for json_file in json_files:
            try:
                with json_file.open("r", encoding="utf-8") as source:
                    data = json.load(source)
            except json.JSONDecodeError as exc:
                invalid_files.append((json_file, f"JSON tidak valid: {exc}"))
                continue
            except OSError as exc:
                invalid_files.append((json_file, f"Gagal membaca file: {exc}"))
                continue

            if written > 0:
                out.write(",\n")

            json.dump(data, out, ensure_ascii=False, separators=(",", ":"))
            written += 1

        out.write("\n]\n")

    print(f"Berhasil menggabungkan {written} file ke: {output_file}")

    if invalid_files:
        print(f"\nDilewati karena error ({len(invalid_files)} file):")
        for path, reason in invalid_files:
            print(f"- {path.name}: {reason}")

    return 0 if written > 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Gabungkan seluruh file JSON OSV NuGet menjadi satu array JSON."
    )
    parser.add_argument(
        "--input",
        default="OSV_NuGet_Data",
        type=Path,
        help="Folder berisi file .json OSV NuGet.",
    )
    parser.add_argument(
        "--output",
        default="github-advisory-db.json",
        type=Path,
        help="Nama file output array JSON.",
    )
    args = parser.parse_args()

    input_dir = args.input
    if not input_dir.is_dir():
        raise NotADirectoryError(f"Folder input tidak ditemukan: {input_dir}")

    return merge_json_files(input_dir, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
