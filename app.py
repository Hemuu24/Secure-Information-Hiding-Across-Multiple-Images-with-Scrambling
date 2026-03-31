from __future__ import annotations

import io
import os
import shutil
import uuid
import zipfile
from pathlib import Path

from cryptography.fernet import InvalidToken
from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from encryption import decrypt_message, encrypt_message, generate_key
from steganography import decode_from_images, encode_into_images

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-in-production")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024

# ✅ Ensure folders exist
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

ENCODE_JOBS = {}


def _is_allowed_image(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def _save_uploaded_images(files, destination: Path):
    saved_paths = []
    for idx, file_storage in enumerate(files):
        if not file_storage or not file_storage.filename:
            continue

        if not _is_allowed_image(file_storage.filename):
            raise ValueError(f"Unsupported format: {file_storage.filename}")

        safe_name = f"{idx:03d}_{secure_filename(file_storage.filename)}"
        target = destination / safe_name
        file_storage.save(target)

        saved_paths.append(str(target))

    return saved_paths


@app.route("/")
def index():
    return render_template("index.html")


# 🔐 ENCODE
@app.route("/encode", methods=["GET", "POST"])
def encode():
    if request.method == "GET":
        return render_template("encode.html")

    message = request.form.get("secret_message", "").strip()
    images = request.files.getlist("images")

    if not message:
        flash("Enter message", "error")
        return redirect(url_for("encode"))

    if len([f for f in images if getattr(f, "filename", "")]) < 2:
        flash("Upload at least 2 images", "error")
        return redirect(url_for("encode"))

    job_id = uuid.uuid4().hex
    job_upload_dir = UPLOAD_DIR / job_id
    job_output_dir = OUTPUT_DIR / job_id

    try:
        job_upload_dir.mkdir(parents=True, exist_ok=True)
        job_output_dir.mkdir(parents=True, exist_ok=True)

        image_paths = _save_uploaded_images(images, job_upload_dir)

        key = generate_key()
        ciphertext = encrypt_message(message, key)

        stego_paths = encode_into_images(image_paths, ciphertext, str(job_output_dir))

        if not stego_paths:
            raise ValueError("Encoding failed")

        key_path = job_output_dir / "encryption.key"
        key_path.write_bytes(key)

        ENCODE_JOBS[job_id] = {
            "output_dir": job_output_dir,
            "key_path": key_path,
            "stego_paths": stego_paths,
        }

        flash("Encoding successful", "success")

        return render_template(
            "encode.html",
            job_id=job_id,
            stego_files=[Path(p).name for p in stego_paths],
        )

    except Exception as e:
        shutil.rmtree(job_upload_dir, ignore_errors=True)
        shutil.rmtree(job_output_dir, ignore_errors=True)
        flash(f"Error: {e}", "error")
        return redirect(url_for("encode"))


# 🔓 DECODE
@app.route("/decode", methods=["GET", "POST"])
def decode():
    if request.method == "GET":
        return render_template("decode.html")

    images = request.files.getlist("stego_images")
    key_file = request.files.get("key_file")

    if not images:
        flash("Upload stego images", "error")
        return redirect(url_for("decode"))

    if not key_file:
        flash("Upload key file", "error")
        return redirect(url_for("decode"))

    job_dir = UPLOAD_DIR / f"decode_{uuid.uuid4().hex}"
    job_dir.mkdir(parents=True, exist_ok=True)

    try:
        image_paths = _save_uploaded_images(images, job_dir)
        key = key_file.read()

        payload = decode_from_images(image_paths)
        message = decrypt_message(payload, key)

        flash("Decoded successfully", "success")

        return render_template("decode.html", recovered_message=message)

    except InvalidToken:
        flash("Wrong key or image order", "error")
        return redirect(url_for("decode"))

    except Exception as e:
        flash(f"Error: {e}", "error")
        return redirect(url_for("decode"))

    finally:
        shutil.rmtree(job_dir, ignore_errors=True)


# 📥 DOWNLOAD KEY (FIXED)
@app.route("/download/key/<job_id>")
def download_key(job_id):
    job = ENCODE_JOBS.get(job_id)

    if not job:
        flash("Session expired", "error")
        return redirect(url_for("encode"))

    key_path = job["key_path"]

    return send_file(
        key_path,
        as_attachment=True,
        download_name="encryption.key"
    )


# 📦 DOWNLOAD ZIP (IMAGES)
@app.route("/download/zip/<job_id>")
def download_zip(job_id):
    job = ENCODE_JOBS.get(job_id)

    if not job:
        return redirect(url_for("encode"))

    memory_file = io.BytesIO()

    with zipfile.ZipFile(memory_file, "w") as zf:
        for path in job.get("stego_paths", []):
            zf.write(path, arcname=Path(path).name)

    memory_file.seek(0)

    return send_file(
        memory_file,
        as_attachment=True,
        download_name="stego_images.zip",
    )


if __name__ == "__main__":
    app.run(debug=True)
