"""
LSB steganography helpers for encoding and decoding across multiple images.
"""

from __future__ import annotations

import struct
import os
from pathlib import Path

from PIL import Image

from splitter import bytes_per_image, split_payload_by_capacities


def _encode_lsb(image: Image.Image, data: bytes) -> Image.Image:
    total_bits = len(data) * 8
    pixels = image.load()
    width, height = image.size

    capacity_bits = width * height * 3
    if total_bits > capacity_bits:
        raise ValueError("Data too large for selected image.")

    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    idx = 0
    for y in range(height):
        for x in range(width):
            if idx >= len(bits):
                return image

            r, g, b = pixels[x, y][:3]

            if idx < len(bits):
                r = (r & 0xFE) | bits[idx]
                idx += 1
            if idx < len(bits):
                g = (g & 0xFE) | bits[idx]
                idx += 1
            if idx < len(bits):
                b = (b & 0xFE) | bits[idx]
                idx += 1

            pixels[x, y] = (r, g, b)

    return image


def _decode_lsb_raw(image: Image.Image, max_bytes: int) -> bytes:
    pixels = image.load()
    width, height = image.size

    bits = []

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y][:3]
            bits.extend((r & 1, g & 1, b & 1))

    out = bytearray()
    max_bits = min(max_bytes * 8, len(bits))

    for i in range(0, max_bits, 8):
        if i + 8 > len(bits):
            break
        value = 0
        for j in range(8):
            value = (value << 1) | bits[i + j]
        out.append(value)

    return bytes(out)


def encode_into_images(image_paths: list[str], payload: bytes, output_dir: str) -> list[str]:
    os.makedirs(output_dir, exist_ok=True)

    # Resize before embedding so saved pixels match split capacities and LSBs are not
    # destroyed by thumbnailing after encode.
    images: list[Image.Image] = []
    capacities: list[int] = []
    for image_path in image_paths:
        with Image.open(image_path) as image:
            image = image.convert("RGB").copy()
            image.thumbnail((1024, 1024))
            w, h = image.size
            capacities.append(bytes_per_image(w, h))
            images.append(image)

    chunks = split_payload_by_capacities(payload, capacities)
    output_paths: list[str] = []

    for index, (image, image_path) in enumerate(zip(images, image_paths, strict=True)):
        _encode_lsb(image, chunks[index])
        output_name = f"{Path(image_path).stem}_stego.png"
        output_path = os.path.join(output_dir, output_name)
        image.save(output_path, format="PNG")
        output_paths.append(output_path)

    return output_paths


def decode_from_images(image_paths: list[str]) -> bytes:
    if not image_paths:
        return b""

    capacities: list[int] = []
    for image_path in image_paths:
        with Image.open(image_path) as image:
            width, height = image.size
            capacities.append(bytes_per_image(width, height))

    # Encoder only writes ceil(bits/8) bytes per image, not full capacity — reading
    # unused LSBs adds noise and breaks Fernet. Read exact chunk sizes like split.
    header = bytearray()
    for image_path, cap in zip(image_paths, capacities):
        if len(header) >= 4:
            break
        need = 4 - len(header)
        take = min(cap, need)
        with Image.open(image_path) as image:
            image = image.convert("RGB")
            header.extend(_decode_lsb_raw(image, take))

    if len(header) < 4:
        return b""

    total_len = struct.unpack(">I", bytes(header[:4]))[0]
    blob_len = 4 + total_len
    total_cap = sum(capacities)
    if total_len < 0 or blob_len > total_cap:
        return b""

    lengths: list[int] = []
    offset = 0
    for cap in capacities:
        if offset >= blob_len:
            lengths.append(0)
        else:
            take = min(cap, blob_len - offset)
            lengths.append(take)
            offset += take

    blob = bytearray()
    for image_path, take in zip(image_paths, lengths):
        if take <= 0:
            continue
        with Image.open(image_path) as image:
            image = image.convert("RGB")
            blob.extend(_decode_lsb_raw(image, take))

    if len(blob) < blob_len:
        return b""

    return bytes(blob[4:blob_len])
