# PixelVault — Image Encryption & Decryption Website

A small Flask website that encrypts image file bytes and lets users download the result as `.enc`. Decryption requires the same password.

## Features
- Web interface for image encryption and decryption
- Fernet authenticated encryption
- PBKDF2-HMAC-SHA256 password-based key derivation with a random salt
- Original image format detected from its file signature
- File upload limit: 16 MiB
- Uploads are processed in memory rather than intentionally written to disk

## Requirements
- Python 3.10+
- pip

## Run on Windows
1. Extract this ZIP.
2. Open Command Prompt or PowerShell in the extracted `image_encryption_web` folder.
3. Create and activate a virtual environment (recommended):

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

5. Start the website:

   ```powershell
   python app.py
   ```

6. Open `http://127.0.0.1:5000` in your browser.

To stop it, press `Ctrl+C` in the terminal.

## How it works
- Encryption: image bytes → password-derived Fernet key → encrypted token. The file stores a magic header, random salt, and token.
- Decryption: reads the salt, derives the key from the password, verifies/decrypts the token, then returns the original image bytes.
- A wrong password or altered encrypted file fails authentication.

## Important notes
- Keep passwords private and make backups of encrypted files.
- If you lose the password, the image cannot be recovered.
- Fernet operates on the full file in memory, so this implementation is for small-to-medium images rather than very large files.
- The Flask development server is for local testing only. For deployment on the public internet, use a production WSGI server, HTTPS, rate limiting, CSRF protection, logging, and a security review. Do not expose the development server directly to the internet.
- This is an educational project, not a formally audited encryption product.
