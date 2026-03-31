# Secure Multi-Image Steganography (Web)

A **Flask** web application that hides secret messages inside multiple carrier images using **LSB (Least Significant Bit) steganography** combined with **AES-256 encryption** (Fernet). The message is encrypted first, then split and embedded across several images.

---

## How It Works

### Overview

1. **Encryption** → Your secret message is encrypted with a symmetric key (Fernet/AES-256).
2. **Splitting** → The encrypted payload is split across multiple carrier images based on their pixel capacity.
3. **Embedding** → Each chunk is hidden in the least significant bits of the images' red, green, and blue channels.
4. **Output** → You get stego images (`*_stego.png`) plus a `.key` file needed for decryption.

### Encoding Flow

```
Secret Message → Encrypt (AES-256) → Ciphertext → Split across images → LSB Embed → Stego Images
```

- **Carrier images**: At least 2 images are required.
- **Capacity**: Each image can store `(width × height × 3) / 8` bytes (1 bit per RGB channel per pixel).
- **First image**: Stores a 4-byte length header + first chunk of ciphertext.
- **Other images**: Store subsequent chunks of the payload.

### Decoding Flow

```
Stego Images (same order) + Key file → Extract LSB data → Reassemble ciphertext → Decrypt → Original Message
```

- Use the **`_stego.png`** files (not the original carriers).
- Images must be uploaded in the **same order** as when encoding.
- The correct `.key` file is required for decryption.

### LSB Steganography (Technical)

Each pixel has RGB values (0–255). We modify only the **least significant bit** of each channel. Data is stored as a stream of bits across all pixels, left-to-right, top-to-bottom.

---

## Installation

- Python 3.10+
- Dependencies: Flask, Pillow, cryptography, gunicorn (for production)

```bash
pip install -r requirements.txt
```

---

## Usage (local)

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### Encode

1. Go to **Encode**.
2. Upload at least **two** carrier images.
3. Enter your secret message and submit.
4. Download the **ZIP** of stego images and the **`.key`** file. Keep the key safe.

### Decode

1. Go to **Decode**.
2. Upload the stego images **in the same order** as encoding.
3. Upload the **`.key`** file and submit.
4. The recovered message appears on the page.

---

## Deploy (example: Render)

- **Build:** `pip install -r requirements.txt`
- **Start:** `gunicorn app:app`
- Set environment variable **`SECRET_KEY`** to a long random string.

Free tiers may sleep when idle; disk for uploaded files is not guaranteed between restarts.

---

## Project Structure

```
├── app.py              # Flask routes
├── encryption.py       # Fernet encrypt/decrypt
├── splitter.py         # Payload splitting by image capacity
├── steganography.py    # LSB embed/extract
├── requirements.txt
├── templates/          # HTML pages
├── static/             # CSS, JS
├── uploads/            # Runtime uploads (optional .gitignore)
├── outputs/            # Generated stego files (optional .gitignore)
└── README.md
```

---

## Security Notes

- **Never commit `.key` files** or real user uploads to version control.
- Anyone with the key and stego images can recover the message.
- Wrong image order or wrong images causes decryption failure or garbage output.

---

## License

This project is part of a capstone submission.
