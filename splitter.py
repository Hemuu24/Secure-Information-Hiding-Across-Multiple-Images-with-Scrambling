"""
Payload splitting helpers for multi-image steganography.
"""

import struct
from PIL import Image


def bytes_per_image(width: int, height: int) -> int:
    """Maximum storable bytes using 1 LSB per RGB channel."""
    return (width * height * 3) // 8


def split_payload_for_images(payload: bytes, image_paths: list[str]) -> list[bytes]:
    """
    Split payload across images.
    First image starts with 4-byte payload length header.
    """
    capacities: list[int] = []
    for path in image_paths:
        with Image.open(path) as image:
            width, height = image.size
            capacities.append(bytes_per_image(width, height))

    total_capacity = sum(capacities)
    needed = 4 + len(payload)
    if needed > total_capacity:
        raise ValueError(
            f"Payload ({len(payload)} bytes) exceeds total capacity ({total_capacity} bytes)."
        )

    blob = struct.pack(">I", len(payload)) + payload
    chunks: list[bytes] = []
    offset = 0
    for cap in capacities:
        take = min(cap, len(blob) - offset)
        chunks.append(blob[offset : offset + take])
        offset += take
    return chunks
