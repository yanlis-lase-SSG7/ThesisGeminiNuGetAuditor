import argparse
import json
import re
import time
from pathlib import Path

from google import genai
from google.genai import types


OUTPUT_DIR = Path("Thesis_Dataset_1000")
PROJECT_ID = "gen-lang-client-0569088861"
LOCATION = "us-central1"
DEFAULT_MODEL = "gemini-2.5-pro"
TOTAL_BATCHES = 20
FILES_PER_BATCH = 50
DELAY_SECONDS = 3


def build_prompt(batch_number: int, start_index: int, end_index: int) -> str:
    return f"""
Buatkan {FILES_PER_BATCH} file .csproj untuk aplikasi .NET 10.
Variasikan jenis aplikasinya: Web API, MVC, Console, dan Worker Service.
Masukkan 3 hingga 5 elemen <PackageReference> secara acak di setiap file.
Gunakan paket NuGet populer seperti Newtonsoft.Json, Dapper, Serilog,
Microsoft.Extensions.Hosting, Microsoft.EntityFrameworkCore, Swashbuckle.AspNetCore,
Polly, AutoMapper, FluentValidation, Npgsql, Microsoft.Data.SqlClient, dan paket populer lain.
Variasikan versinya antara versi yang sangat lama/usang dan versi terbaru.

Ketentuan penting:
- Ini batch ke-{batch_number}.
- Gunakan filename unik dari App{start_index}.csproj sampai App{end_index}.csproj.
- Set TargetFramework ke net10.0.
- Untuk Web API dan MVC, gunakan SDK Microsoft.NET.Sdk.Web.
- Untuk Console dan Worker Service, gunakan SDK Microsoft.NET.Sdk.
- Jangan gunakan PackageReference untuk Microsoft.AspNetCore.App karena itu framework reference,
  bukan paket NuGet biasa. Jika perlu, gunakan <FrameworkReference Include="Microsoft.AspNetCore.App" />.
- Pastikan XML valid.

Kembalikan output HANYA dalam format JSON array.
Setiap object wajib punya properti:
- "filename", contoh "App1.csproj"
- "content", isi XML .csproj lengkap sebagai string
""".strip()


def extract_json_array(text: str) -> list[dict[str, str]]:
    cleaned = text.strip()

    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\[\s*\{.*\}\s*\]", cleaned, flags=re.DOTALL)
        if not match:
            raise
        data = json.loads(match.group(0))

    if not isinstance(data, list):
        raise ValueError("Respons API bukan JSON array.")

    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Item #{index} bukan object JSON.")
        if not isinstance(item.get("filename"), str) or not item["filename"].endswith(".csproj"):
            raise ValueError(f"Item #{index} tidak memiliki filename .csproj yang valid.")
        if not isinstance(item.get("content"), str) or "<Project" not in item["content"]:
            raise ValueError(f"Item #{index} tidak memiliki content XML .csproj yang valid.")

    return data


def safe_output_path(filename: str) -> Path:
    path = OUTPUT_DIR / Path(filename).name
    if path.suffix.lower() != ".csproj":
        raise ValueError(f"Ekstensi file tidak valid: {filename}")
    return path


def generate_batch(client: genai.Client, model: str, batch_number: int) -> list[dict[str, str]]:
    start_index = ((batch_number - 1) * FILES_PER_BATCH) + 1
    end_index = batch_number * FILES_PER_BATCH
    prompt = build_prompt(batch_number, start_index, end_index)

    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.9,
        ),
    )

    if not response.text:
        raise ValueError("Respons API kosong.")

    return extract_json_array(response.text)


def save_files(files: list[dict[str, str]]) -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    saved = 0
    for item in files:
        output_path = safe_output_path(item["filename"])
        output_path.write_text(item["content"].strip() + "\n", encoding="utf-8")
        saved += 1

    return saved


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate 1.000 file .csproj .NET 10 menggunakan Gemini API."
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Default: {DEFAULT_MODEL}")
    parser.add_argument("--batches", type=int, default=TOTAL_BATCHES, help="Default: 20")
    parser.add_argument("--start-batch", type=int, default=1, help="Default: 1")
    parser.add_argument("--files-per-batch", type=int, default=FILES_PER_BATCH, help="Default: 50")
    args = parser.parse_args()

    if args.files_per_batch != FILES_PER_BATCH:
        raise ValueError(
            "Script ini sengaja dikunci ke 50 file per batch agar prompt dan indexing tetap konsisten."
        )

    client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    total_saved = 0

    if args.start_batch < 1 or args.start_batch > args.batches:
        raise ValueError("--start-batch harus berada di antara 1 dan nilai --batches.")

    for batch_number in range(args.start_batch, args.batches + 1):
        try:
            print(
                f"[Batch {batch_number}/{args.batches}] Meminta {FILES_PER_BATCH} file ke Gemini...",
                flush=True,
            )
            files = generate_batch(client, args.model, batch_number)

            if len(files) != FILES_PER_BATCH:
                print(
                    f"[Batch {batch_number}] Peringatan: respons berisi {len(files)} file, "
                    f"bukan {FILES_PER_BATCH}.",
                    flush=True,
                )

            saved = save_files(files)
            total_saved += saved
            print(
                f"[Batch {batch_number}] Tersimpan {saved} file. Total sementara sesi ini: {total_saved}.",
                flush=True,
            )

        except Exception as exc:
            print(f"[Batch {batch_number}] Gagal: {exc}", flush=True)

        if batch_number < args.batches:
            time.sleep(DELAY_SECONDS)

    print(f"Selesai. Total file tersimpan sesi ini: {total_saved}. Folder output: {OUTPUT_DIR.resolve()}", flush=True)


if __name__ == "__main__":
    main()
