# Secure Image Encryption Using Python

## Features
- AES-256-GCM encryption and authenticated decryption
- Random 256-bit key and 96-bit nonce
- Separate key file
- Image validation using Pillow
- Command-line interface and error messages
- Detects incorrect keys and modified encrypted files

## 1. Install Python
Install Python 3.10 or newer from https://www.python.org/downloads/.
During installation on Windows, enable **Add Python to PATH**.

Check:
```bash
python --version
```

## 2. Open the project in VS Code
1. Extract this ZIP file.
2. Open VS Code.
3. Select **File > Open Folder**.
4. Select the extracted `secure_image_encryption_project` folder.
5. Open **Terminal > New Terminal**.

## 3. Create a virtual environment (recommended)
Windows:
```bash
python -m venv venv
venv\Scripts\activate
```
If PowerShell blocks activation, use Command Prompt in VS Code, or run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

## 4. Install dependencies
```bash
python -m pip install -r requirements.txt
```

## 5. Add an image
Copy a test image (for example `sample.png`) into this project folder.
Supported formats: PNG, JPEG, BMP, GIF, TIFF and WEBP.

## 6. Encrypt the image
```bash
python image_encryptor.py encrypt sample.png encrypted_image.enc --keyfile secret.key
```
Expected files:
- `encrypted_image.enc` — encrypted image data
- `secret.key` — key required for decryption

## 7. Decrypt the image
```bash
python image_encryptor.py decrypt encrypted_image.enc recovered.png --keyfile secret.key
```
Open `recovered.png` to confirm it matches the original image.

## 8. Test security
- Try decrypting with a different key file: decryption should fail.
- Do not edit the `.enc` file: modified encrypted data should fail authentication.
- Keep `secret.key` private and backed up securely. Do not upload it to GitHub.
- Never lose the key: the encrypted image cannot be recovered without it.

## Project structure
```text
secure_image_encryption_project/
|-- image_encryptor.py
|-- requirements.txt
|-- README.md
|-- .gitignore
```

## Important security note
This implementation uses AES-256-GCM rather than the AES-CBC mode shown in the supplied report. GCM provides authentication, which helps detect tampering and incorrect keys. The key is saved separately from the encrypted image. Anyone who obtains both the encrypted file and its key can decrypt the image, so protect the key carefully.
