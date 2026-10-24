import io
import os
import struct
from pathlib import Path

from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
import base64

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MiB upload limit

# File format: MAGIC (8 bytes) + 16-byte salt + Fernet token
MAGIC = b"IMGCRYPT"
SALT_LEN = 16
ITERATIONS = 600_000
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"}
IMAGE_SIGNATURES = (
    b"\x89PNG\r\n\x1a\n",          # PNG
    b"\xff\xd8\xff",               # JPEG
    b"GIF87a", b"GIF89a",          # GIF
    b"BM",                         # BMP
    b"RIFF",                       # WebP (also check WEBP marker below)
    b"II*\x00", b"MM\x00*",        # TIFF
)

def derive_fernet_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Enter a password.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def is_supported_image(data: bytes) -> bool:
    if data.startswith(b"RIFF"):
        return len(data) >= 12 and data[8:12] == b"WEBP"
    return any(data.startswith(sig) for sig in IMAGE_SIGNATURES if sig != b"RIFF")

def image_extension(data: bytes, original_name: str = "") -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if data.startswith(b"BM"):
        return ".bmp"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return ".webp"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return ".tiff"
    ext = Path(secure_filename(original_name)).suffix.lower()
    return ext if ext in ALLOWED_EXTENSIONS else ".img"

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/encrypt")
def encrypt_image():
    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    if not uploaded or not uploaded.filename:
        return render_template("index.html", error="Choose an image file first.")
    name = secure_filename(uploaded.filename) or "image"
    if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
        return render_template("index.html", error="Unsupported file type. Choose a PNG, JPG, WEBP, GIF, BMP, or TIFF image.")
    raw = uploaded.read()
    if not raw:
        return render_template("index.html", error="The selected file is empty.")
    if not is_supported_image(raw):
        return render_template("index.html", error="The uploaded file does not appear to be a supported image.")
    if not password:
        return render_template("index.html", error="Enter a password for encryption.")
    salt = os.urandom(SALT_LEN)
    key = derive_fernet_key(password, salt)
    token = Fernet(key).encrypt(raw)
    encrypted_blob = MAGIC + salt + token
    output_name = Path(name).stem + ".enc"
    return send_file(
        io.BytesIO(encrypted_blob),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=output_name,
    )

@app.post("/decrypt")
def decrypt_image():
    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    if not uploaded or not uploaded.filename:
        return render_template("index.html", error="Choose an encrypted .enc file first.")
    if not password:
        return render_template("index.html", error="Enter the password used to encrypt this image.")
    encrypted_blob = uploaded.read()
    header_len = len(MAGIC) + SALT_LEN
    if len(encrypted_blob) <= header_len or not encrypted_blob.startswith(MAGIC):
        return render_template("index.html", error="This is not a valid image-encryption file.")
    salt = encrypted_blob[len(MAGIC):header_len]
    token = encrypted_blob[header_len:]
    try:
        key = derive_fernet_key(password, salt)
        raw = Fernet(key).decrypt(token)
    except (InvalidToken, ValueError, TypeError):
        return render_template("index.html", error="Decryption failed. Check the password or file integrity.")
    if not is_supported_image(raw):
        return render_template("index.html", error="Decrypted data is not a supported image.")
    original_ext = image_extension(raw, uploaded.filename)
    output_name = Path(secure_filename(uploaded.filename) or "image").stem
    if output_name.endswith(".enc"):
        output_name = output_name[:-4]
    if not output_name:
        output_name = "decrypted_image"
    if Path(output_name).suffix.lower() in ALLOWED_EXTENSIONS:
        output_name = Path(output_name).stem
    return send_file(
        io.BytesIO(raw),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=output_name + original_ext,
    )

@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    return render_template("index.html", error="File too large. The maximum upload size is 16 MiB."), 413

if __name__ == "__main__":
    import os

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )