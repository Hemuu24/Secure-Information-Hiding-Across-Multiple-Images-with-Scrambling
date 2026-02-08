"""
LSB steganography utilities for hiding bytes in images.
Supports splitting payload across multiple carrier images.
"""

import struct
from pathlib import Path
from PIL import Image


def _bytes_per_image(width: int, height: int) -> int:
    """Maximum bytes storable in one image (3 LSBs per pixel)."""
    return (width * height * 3) // 8


def _encode_lsb(image: Image.Image, data: bytes) -> Image.Image:
    """
    Hide data in the LSB of R,G,B of each pixel.
    First 4 bytes (big-endian) store the length of data.
    """
    total_bits = len(data) * 8
    # We store 4-byte length + data; length prefix is part of 'data' passed as (length_bytes + payload)
    pixels = image.load()
    width, height = image.size
    capacity_bits = width * height * 3
    if total_bits > capacity_bits:
        raise ValueError("Data too large for this image")
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
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
    """
    Extract up to max_bytes from LSB of R,G,B (no length prefix).
    """
    pixels = image.load()
    width, height = image.size
    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y][:3]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
    result = []
    for i in range(0, min(max_bytes * 8, len(bits)), 8):
        if i + 8 > len(bits):
            break
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        result.append(b)
    return bytes(result)


def split_payload_for_images(payload: bytes, image_paths: list[str]) -> list[bytes]:
    """
    Split payload across images. First image gets 4-byte total length + first chunk;
    others get subsequent chunks. Raises if total payload too large for all images.
    """
    images_info = []
    for p in image_paths:
        with Image.open(p) as im:
            im.load()
            w, h = im.size
            cap = _bytes_per_image(w, h)
            images_info.append((cap, w, h))
    total_cap = sum(cap for cap, _, _ in images_info)
    # First image stores 4-byte length + chunk1; we need 4 + len(payload) <= total_cap
    needed = 4 + len(payload)
    if needed > total_cap:
        raise ValueError(
            f"Payload size {len(payload)} bytes + 4 byte length header exceeds "
            f"total capacity {total_cap} bytes across {len(image_paths)} images."
        )
    # Build blob: 4-byte big-endian length + payload
    length_header = struct.pack(">I", len(payload))
    blob = length_header + payload
    chunks = []
    offset = 0
    for i, (cap, _, _) in enumerate(images_info):
        if i == 0:
            # First image: up to cap bytes (includes 4-byte length)
            take = min(cap, len(blob) - offset)
        else:
            take = min(cap, len(blob) - offset)
        chunk = blob[offset : offset + take]
        offset += take
        chunks.append(chunk)
    return chunks


def encode_into_images(image_paths: list[str], payload: bytes, output_dir: str) -> list[str]:
    """
    Encode payload into carrier images using LSB. Saves stego images under output_dir.
    Returns list of paths to saved stego images.
    """
    chunks = split_payload_for_images(payload, image_paths)
    output_paths = []
    for i, path in enumerate(image_paths):
        with Image.open(path) as im:
            im = im.convert("RGB")
            # For first image, chunk includes 4-byte length + data; for others, just data
            _encode_lsb(im, chunks[i])
            out_name = Path(path).stem + "_stego.png"
            out_path = Path(output_dir) / out_name
            im.save(out_path)
            output_paths.append(str(out_path))
    return output_paths


def decode_from_images(image_paths: list[str]) -> bytes:
    """
    Extract payload from stego images. First image's LSB stream: 4-byte length + chunk1; others raw chunks.
    """
    if not image_paths:
        return b""
    capacities = []
    for p in image_paths:
        with Image.open(p) as im:
            w, h = im.size
            capacities.append(_bytes_per_image(w, h))
    # First image: extract cap1 bytes; first 4 = total_len, rest = chunk1
    with Image.open(image_paths[0]) as im:
        im = im.convert("RGB")
        first_blob = _decode_lsb_raw(im, capacities[0])
    if len(first_blob) < 4:
        return b""
    total_len = struct.unpack(">I", first_blob[:4])[0]
    reconstructed = bytearray(first_blob[4:])
    for path, cap in zip(image_paths[1:], capacities[1:]):
        with Image.open(path) as im:
            im = im.convert("RGB")
            chunk = _decode_lsb_raw(im, cap)
            reconstructed.extend(chunk)
        if len(reconstructed) >= total_len:
            break
    return bytes(reconstructed[:total_len])
