#!/usr/bin/env python3
"""Assemble a Windows .ico from per-size images produced by sips.

macOS has no native .ico encoder and we do not want to depend on ImageMagick,
so generate-icons.sh rasterises each size with sips and this script wraps the
results in an ICO container.

Sizes up to 128px are stored as classic 32-bpp BGRA DIBs (read by every version
of Windows and by old resource tooling); 256px is stored as a PNG, which is the
Vista+ convention and keeps the file roughly 250KB smaller.

Usage: make_ico.py OUT.ico SIZE:image.bmp [SIZE:image.png ...]
"""

import struct
import sys


def bmp24_to_dib32(path):
    """Read a 24-bpp BMP written by sips and return an ICO-ready 32-bpp DIB.

    An ICO image entry is a BITMAPINFOHEADER whose height covers the colour
    rows *and* the 1-bpp AND mask that follows them, with no file header.
    """
    data = open(path, "rb").read()
    if data[:2] != b"BM":
        raise ValueError(f"{path}: not a BMP")

    pixel_offset = struct.unpack("<I", data[10:14])[0]
    width, height = struct.unpack("<ii", data[18:26])
    bpp = struct.unpack("<H", data[28:30])[0]
    compression = struct.unpack("<I", data[30:34])[0]
    if bpp != 24 or compression != 0:
        raise ValueError(f"{path}: expected uncompressed 24-bpp BMP, got {bpp}-bpp comp={compression}")

    top_down = height < 0
    height = abs(height)
    src_stride = (width * 3 + 3) & ~3

    # ICO colour data is always bottom-up, so emit rows in reverse order.
    rows = []
    for y in range(height - 1, -1, -1):
        src_y = y if top_down else (height - 1 - y)
        start = pixel_offset + src_y * src_stride
        row = data[start:start + width * 3]
        out = bytearray(width * 4)
        for x in range(width):
            out[x * 4:x * 4 + 3] = row[x * 3:x * 3 + 3]  # BGR, already in BMP order
            out[x * 4 + 3] = 0xFF                        # opaque
        rows.append(bytes(out))
    pixels = b"".join(rows)

    # Fully opaque AND mask: all zero bits, rows padded to 4 bytes.
    mask_stride = ((width + 31) // 32) * 4
    mask = b"\x00" * (mask_stride * height)

    header = struct.pack(
        "<IiiHHIIiiII",
        40,              # biSize
        width,
        height * 2,      # biHeight includes the AND mask
        1,               # biPlanes
        32,              # biBitCount
        0,               # biCompression = BI_RGB
        len(pixels) + len(mask),
        0, 0, 0, 0,      # resolution / palette fields
    )
    return header + pixels + mask


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)

    out_path = argv[1]
    images = []
    for spec in argv[2:]:
        size_text, _, path = spec.partition(":")
        size = int(size_text)
        if path.endswith(".png"):
            payload = open(path, "rb").read()
        else:
            payload = bmp24_to_dib32(path)
        images.append((size, payload))

    images.sort(key=lambda item: item[0])

    header = struct.pack("<HHH", 0, 1, len(images))  # reserved, type=icon, count
    offset = len(header) + 16 * len(images)
    directory = b""
    for size, payload in images:
        directory += struct.pack(
            "<BBBBHHII",
            0 if size >= 256 else size,  # width, 0 means 256
            0 if size >= 256 else size,  # height
            0,                           # palette colours
            0,                           # reserved
            1,                           # colour planes
            32,                          # bits per pixel
            len(payload),
            offset,
        )
        offset += len(payload)

    with open(out_path, "wb") as handle:
        handle.write(header + directory + b"".join(payload for _, payload in images))


if __name__ == "__main__":
    main(sys.argv)
