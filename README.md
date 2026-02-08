# Secure Multi-Image Steganography

A desktop application that hides secret messages inside multiple carrier images using **LSB (Least Significant Bit) steganography** combined with **AES-256 encryption**. The message is encrypted first, then split and embedded across several images—making it harder to detect or extract without all stego images and the correct key.

---

## How It Works

### Overview

1. **Encryption** → Your secret message is encrypted with a symmetric key (Fernet/AES-256).
2. **Splitting** → The encrypted payload is split across multiple carrier images based on their pixel capacity.
3. **Embedding** → Each chunk is hidden in the least significant bits of the images' red, green, and blue channels.
4. **Output** → You get stego images (`*_stego.png`) that look identical to the originals, plus a `.key` file needed for decryption.

### Encoding Flow

```
Secret Message → Encrypt (AES-256) → Ciphertext → Split across images → LSB Embed → Stego Images
```

- **Carrier images**: At least 2 PNG/JPG images are required.
- **Capacity**: Each image can store `(width × height × 3) / 8` bytes (1 bit per RGB channel per pixel).
- **First image**: Stores a 4-byte length header + first chunk of ciphertext.
- **Other images**: Store subsequent chunks of the payload.
- **Stego images**: Saved as `originalname_stego.png` in the folder you choose.

### Decoding Flow

```
Stego Images (same order) + Key file → Extract LSB data → Reassemble ciphertext → Decrypt → Original Message
```

- You must use the **`_stego.png`** files (not the original carriers).
- Images must be loaded in the **same order** as when encoding.
- The correct `.key` file is required for decryption.

### LSB Steganography (Technical)

Each pixel has RGB values (0–255). We modify only the **least significant bit** of each channel:

- Original: `R=10110110`, `G=11001100`, `B=11110000`
- To store bit `1` in R: `R=10110111` (change last bit)
- Change is invisible to the human eye (≤1 intensity difference per channel)

Data is stored as a stream of bits across all pixels, left-to-right, top-to-bottom.

---

## Installation

### Requirements

- Python 3.10+
- Pillow (image processing)
- cryptography (Fernet/AES-256)

### Setup

```bash
pip install -r requirements.txt
```

---

## Usage

### Run the application

```bash
python app.py
```
