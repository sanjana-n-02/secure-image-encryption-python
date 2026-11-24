"""
Secure Image Encryption using Python and AES-256-GCM.

Commands:
  python image_encryptor.py encrypt sample.png encrypted_image.enc --keyfile secret.key
  python image_encryptor.py decrypt encrypted_image.enc recovered.png --keyfile secret.key
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, UnidentifiedImageError

MAGIC = b"IMGX1"
KEY_SIZE = 32       # 32 bytes = 256 bits
NONCE_SIZE = 12     # Recommended nonce size for AES-GCM
SUPPORTED_FORMATS = {"JPEG", "PNG", "BMP", "GIF", "TIFF", "WEBP"}

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


def validate_image(path: Path) -> bytes:
    """Read an image and check that Pillow recognizes it as a valid image."""
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")

    data = path.read_bytes()
    if not data:
        raise ValueError("The input file is empty.")

    try:
        from io import BytesIO
        with Image.open(BytesIO(data)) as image:
            image_format = (image.format or "").upper()
            image.verify()
        if image_format not in SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported image format: {image_format}")
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("The input file is not a valid supported image.") from exc

    return data


def generate_and_save_key(key_path: Path, force: bool = False) -> bytes:
    """Generate a random AES-256 key and save it separately."""
    if key_path.exists() and not force:
        raise FileExistsError(
            f"Key file already exists: {key_path}. Choose another name "
            "or use --force-key only if you intend to replace it."
        )

    key = AESGCM.generate_key(bit_length=256)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)

    # Restrict permissions on platforms that support chmod.
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        logging.warning("Could not restrict key-file permissions on this system.")

    return key


def load_key(key_path: Path) -> bytes:
    if not key_path.is_file():
        raise FileNotFoundError(f"Key file not found: {key_path}")
    key = key_path.read_bytes()
    if len(key) != KEY_SIZE:
        raise ValueError("Invalid key file. An AES-256 key must be exactly 32 bytes.")
    return key


def encrypt_image(input_path: Path, output_path: Path,
                  key_path: Path, force_key: bool = False) -> None:
    image_data = validate_image(input_path)
    key = generate_and_save_key(key_path, force=force_key)
    nonce = os.urandom(NONCE_SIZE)

    # AES-GCM authenticates the encrypted data and detects tampering.
    encrypted_data = AESGCM(key).encrypt(nonce, image_data, MAGIC)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(MAGIC + nonce + encrypted_data)

    logging.info("Image encrypted successfully.")
    logging.info("Encrypted file: %s", output_path)
    logging.info("Encryption key: %s", key_path)
    logging.warning("Keep the key file safe. Without it, decryption is not possible.")


def decrypt_image(input_path: Path, output_path: Path, key_path: Path) -> None:
    if not input_path.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    encrypted_file = input_path.read_bytes()
    header_length = len(MAGIC) + NONCE_SIZE

    if len(encrypted_file) <= header_length or not encrypted_file.startswith(MAGIC):
        raise ValueError("Invalid encrypted file or unsupported file format.")

    nonce = encrypted_file[len(MAGIC):header_length]
    ciphertext = encrypted_file[header_length:]
    key = load_key(key_path)

    # Invalid key or modified ciphertext raises InvalidTag.
    from cryptography.exceptions import InvalidTag
    try:
        image_data = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag as exc:
        raise ValueError(
            "Decryption failed: the key is incorrect or the encrypted file was modified."
        ) from exc

    # Confirm decrypted bytes are a valid image before saving.
    from io import BytesIO
    try:
        with Image.open(BytesIO(image_data)) as image:
            image.verify()
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("Decrypted data is not a valid image.") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(image_data)
    logging.info("Image decrypted successfully.")
    logging.info("Recovered image: %s", output_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt images using AES-256-GCM."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt an image.")
    encrypt_parser.add_argument("input", help="Path to the original image.")
    encrypt_parser.add_argument("output", help="Path for the encrypted .enc file.")
    encrypt_parser.add_argument(
        "--keyfile", default="secret.key", help="Path to save the generated key."
    )
    encrypt_parser.add_argument(
        "--force-key", action="store_true",
        help="Replace an existing key file (this makes older files using it unrecoverable)."
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt an .enc file.")
    decrypt_parser.add_argument("input", help="Path to the encrypted .enc file.")
    decrypt_parser.add_argument("output", help="Path for the recovered image.")
    decrypt_parser.add_argument(
        "--keyfile", default="secret.key", help="Path to the existing key file."
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    key_path = Path(args.keyfile)

    try:
        if input_path.resolve() == output_path.resolve():
            raise ValueError("Input and output paths must be different.")
        if args.mode == "encrypt":
            encrypt_image(input_path, output_path, key_path, args.force_key)
        else:
            decrypt_image(input_path, output_path, key_path)
        return 0
    except (OSError, ValueError) as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
