"""
LSB steganography helpers for encoding and decoding across multiple images.
"""

from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image

from splitter import bytes_per_image, split_payload_for_images


def _encode_lsb(image: Image.Image, data: bytes) -> Image.Image:
    """Embed bytes in RGB LSBs."""
    total_bits = len(data) * 8
    pixels = image.load()
    width, height = image.size
    capacity_bits = width * height * 3
    if total_bits > capacity_bits:
        raise ValueError("Data too large for selected image.")

    bits: list[int] = []
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
            pixels[x, y] = (r, g, b) if len(pixels[x, y]) == 3 else (r, g, b, pixels[x, y][3])

    return image


def _decode_lsb_raw(image: Image.Image, max_bytes: int) -> bytes:
    """Extract raw bytes from RGB LSBs (without interpreting headers)."""
    pixels = image.load()
    width, height = image.size
    bits: list[int] = []

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
    """Split payload and embed chunks into images."""
    chunks = split_payload_for_images(payload, image_paths)
    output_paths: list[str] = []

    for index, image_path in enumerate(image_paths):
        with Image.open(image_path) as image:
            image = image.convert("RGB")
            _encode_lsb(image, chunks[index])
            output_name = f"{Path(image_path).stem}_stego.png"
            output_path = Path(output_dir) / output_name
            image.save(output_path)
            output_paths.append(str(output_path))

    return output_paths


def decode_from_images(image_paths: list[str]) -> bytes:
    """Extract payload bytes from ordered stego images."""
    if not image_paths:
        return b""

    capacities: list[int] = []
    for image_path in image_paths:
        with Image.open(image_path) as image:
            width, height = image.size
            capacities.append(bytes_per_image(width, height))

    with Image.open(image_paths[0]) as image:
        image = image.convert("RGB")
        first_blob = _decode_lsb_raw(image, capacities[0])

    if len(first_blob) < 4:
        return b""

    total_len = struct.unpack(">I", first_blob[:4])[0]
    reconstructed = bytearray(first_blob[4:])

    for image_path, cap in zip(image_paths[1:], capacities[1:]):
        with Image.open(image_path) as image:
            image = image.convert("RGB")
            reconstructed.extend(_decode_lsb_raw(image, cap))
        if len(reconstructed) >= total_len:
            break

    return bytes(reconstructed[:total_len])
