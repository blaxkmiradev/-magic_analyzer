#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           Magic Number & File Header Analyzer               ║
║   Detect true file type, metadata, and header details       ║
╚══════════════════════════════════════════════════════════════╝
Usage:
    python magic_analyzer.py <file>
    python magic_analyzer.py <file> --hex-dump
    python magic_analyzer.py <file> --json
"""

import sys
import os
import struct
import hashlib
import datetime
import argparse
import json
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# MAGIC SIGNATURES DATABASE
# Format: (offset, bytes_to_match, file_type, description, ext)
# ─────────────────────────────────────────────────────────────
MAGIC_SIGNATURES = [
    # ── Images ──────────────────────────────────────────────
    (0, b'\x89PNG\r\n\x1a\n',       "PNG Image",            "image/png",              ".png"),
    (0, b'\xff\xd8\xff',             "JPEG Image",           "image/jpeg",             ".jpg"),
    (0, b'GIF87a',                   "GIF Image (87a)",      "image/gif",              ".gif"),
    (0, b'GIF89a',                   "GIF Image (89a)",      "image/gif",              ".gif"),
    (0, b'BM',                       "BMP Image",            "image/bmp",              ".bmp"),
    (0, b'RIFF',                     "RIFF Container",       "application/riff",       ".riff"),  # refined below
    (0, b'\x00\x00\x01\x00',        "ICO Icon",             "image/x-icon",           ".ico"),
    (0, b'\x00\x00\x02\x00',        "CUR Cursor",           "image/x-cursor",         ".cur"),
    (0, b'II\x2a\x00',              "TIFF Image (LE)",      "image/tiff",             ".tif"),
    (0, b'MM\x00\x2a',              "TIFF Image (BE)",      "image/tiff",             ".tif"),
    (0, b'\x38\x42\x50\x53',        "PSD/PSB Photoshop",    "image/vnd.adobe.photoshop",".psd"),
    (0, b'WEBP',                     "WebP Image",           "image/webp",             ".webp"),  # offset handled
    (0, b'\x00\x00\x00\x0cjP  ',   "JPEG 2000",            "image/jp2",              ".jp2"),
    (0, b'\xff\x4f\xff\x51',        "JPEG 2000 (codestream)","image/jp2",             ".j2k"),

    # ── Audio ────────────────────────────────────────────────
    (0, b'ID3',                      "MP3 Audio (ID3 tag)",  "audio/mpeg",             ".mp3"),
    (0, b'\xff\xfb',                 "MP3 Audio",            "audio/mpeg",             ".mp3"),
    (0, b'\xff\xf3',                 "MP3 Audio",            "audio/mpeg",             ".mp3"),
    (0, b'\xff\xf2',                 "MP3 Audio",            "audio/mpeg",             ".mp3"),
    (0, b'fLaC',                     "FLAC Audio",           "audio/flac",             ".flac"),
    (0, b'OggS',                     "OGG Container",        "audio/ogg",              ".ogg"),
    (0, b'FORM',                     "AIFF Audio",           "audio/aiff",             ".aiff"),
    (0, b'\x30\x26\xb2\x75\x8e\x66\xcf\x11', "WMA/WMV/ASF","video/x-ms-asf",        ".asf"),

    # ── Video ────────────────────────────────────────────────
    (4, b'ftyp',                     "MP4/M4V/MOV Video",    "video/mp4",              ".mp4"),
    (0, b'\x1a\x45\xdf\xa3',        "MKV/WebM Video",       "video/x-matroska",       ".mkv"),
    (0, b'\x00\x00\x01\xba',        "MPEG-PS Video",        "video/mpeg",             ".mpg"),
    (0, b'\x00\x00\x01\xb3',        "MPEG Video",           "video/mpeg",             ".mpg"),
    (0, b'FLV\x01',                  "Flash Video",          "video/x-flv",            ".flv"),
    (0, b'\x30\x26\xb2\x75',        "WMV Video",            "video/x-ms-wmv",         ".wmv"),

    # ── Documents ────────────────────────────────────────────
    (0, b'%PDF',                     "PDF Document",         "application/pdf",        ".pdf"),
    (0, b'PK\x03\x04',              "ZIP / Office Open XML","application/zip",         ".zip"),  # refined below
    (0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',"MS Office (OLE2)","application/msoffice",".doc"),
    (0, b'{\\rtf',                   "RTF Document",         "text/rtf",               ".rtf"),
    (0, b'<html',                    "HTML Document",        "text/html",              ".html"),
    (0, b'<!DOCTYPE',               "HTML Document",        "text/html",              ".html"),
    (0, b'<?xml',                    "XML Document",         "text/xml",               ".xml"),

    # ── Archives ─────────────────────────────────────────────
    (0, b'\x1f\x8b',                 "GZIP Archive",         "application/gzip",       ".gz"),
    (0, b'BZh',                      "BZIP2 Archive",        "application/x-bzip2",    ".bz2"),
    (0, b'\xfd7zXZ\x00',            "XZ Archive",           "application/x-xz",       ".xz"),
    (0, b'7z\xbc\xaf\x27\x1c',     "7-ZIP Archive",        "application/x-7z-compressed",".7z"),
    (0, b'Rar!\x1a\x07\x00',       "RAR Archive (v1.5)",   "application/x-rar",      ".rar"),
    (0, b'Rar!\x1a\x07\x01\x00',  "RAR Archive (v5)",     "application/x-rar",      ".rar"),
    (0, b'\x1f\x9d',                 "LZW Compressed",       "application/x-compress", ".Z"),
    (0, b'\x04\x22\x4d\x18',        "LZ4 Archive",          "application/x-lz4",      ".lz4"),
    (0, b'\x28\xb5\x2f\xfd',        "Zstandard Archive",    "application/zstd",       ".zst"),
    (257, b'ustar',                  "TAR Archive",          "application/x-tar",      ".tar"),

    # ── Executables ──────────────────────────────────────────
    (0, b'MZ',                       "Windows PE Executable","application/vnd.microsoft.portable-executable",".exe"),
    (0, b'\x7fELF',                  "ELF Binary (Linux)",   "application/x-elf",      ""),
    (0, b'\xfe\xed\xfa\xce',        "Mach-O Binary (32-bit)","application/x-mach-binary",""),
    (0, b'\xfe\xed\xfa\xcf',        "Mach-O Binary (64-bit)","application/x-mach-binary",""),
    (0, b'\xca\xfe\xba\xbe',        "Mach-O Fat Binary",    "application/x-mach-binary",""),
    (0, b'#!',                       "Shell Script",         "text/x-shellscript",     ".sh"),

    # ── Fonts ────────────────────────────────────────────────
    (0, b'\x00\x01\x00\x00\x00',   "TrueType Font",        "font/ttf",               ".ttf"),
    (0, b'OTTO',                     "OpenType Font",        "font/otf",               ".otf"),
    (0, b'wOFF',                     "WOFF Font",            "font/woff",              ".woff"),
    (0, b'wOF2',                     "WOFF2 Font",           "font/woff2",             ".woff2"),

    # ── Databases ────────────────────────────────────────────
    (0, b'SQLite format 3\x00',     "SQLite Database",      "application/x-sqlite3",  ".db"),

    # ── Crypto / Keys ────────────────────────────────────────
    (0, b'-----BEGIN',              "PEM Certificate/Key",  "application/x-pem-file", ".pem"),

    # ── Disk Images ──────────────────────────────────────────
    (0, b'QEMU QCOW',               "QCOW Disk Image",      "application/octet-stream",".qcow"),
    (0, b'conectix',                "VHD Disk Image",       "application/octet-stream",".vhd"),

    # ── Misc ─────────────────────────────────────────────────
    (0, b'\xcafeBABE',             "Java Class File",      "application/java-vm",    ".class"),  # overlaps Mach-O fat
    (0, b'CAFEBABE',               "Java Class File",      "application/java-vm",    ".class"),
    (0, b'\x50\x4b\x05\x06',      "ZIP (empty)",          "application/zip",         ".zip"),
    (0, b'\x25\x21\x50\x53',      "PostScript",           "application/postscript",  ".ps"),
]

# ─────────────────────────────────────────────────────────────
# RIFF sub-type refinement (bytes 8–12 carry the real type)
# ─────────────────────────────────────────────────────────────
RIFF_SUBTYPES = {
    b'WAVE': ("WAV Audio",    "audio/wav",        ".wav"),
    b'AVI ': ("AVI Video",    "video/x-msvideo",  ".avi"),
    b'WEBP': ("WebP Image",   "image/webp",       ".webp"),
    b'RMID': ("MIDI Audio",   "audio/midi",       ".mid"),
    b'CDR ': ("CorelDRAW",    "image/x-cdr",      ".cdr"),
}

# ─────────────────────────────────────────────────────────────
# Office Open XML refinement (look for specific entries in ZIP)
# ─────────────────────────────────────────────────────────────
OPC_CONTENT_TYPES = {
    "word/":        ("Word Document",      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",   ".docx"),
    "xl/":          ("Excel Workbook",     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",         ".xlsx"),
    "ppt/":         ("PowerPoint Presentation","application/vnd.openxmlformats-officedocument.presentationml.presentation",".pptx"),
    "META-INF/":    ("ODF Document",       "application/vnd.oasis.opendocument",                                        ".odt"),
    "AndroidManifest.xml": ("Android APK","application/vnd.android.package-archive",                                   ".apk"),
}

# ─────────────────────────────────────────────────────────────
# ELF details
# ─────────────────────────────────────────────────────────────
ELF_CLASS   = {1: "32-bit", 2: "64-bit"}
ELF_DATA    = {1: "Little-Endian", 2: "Big-Endian"}
ELF_TYPE    = {0: "None", 1: "Relocatable", 2: "Executable", 3: "Shared Object", 4: "Core Dump"}
ELF_MACHINE = {
    0x00: "No machine", 0x02: "SPARC", 0x03: "x86", 0x08: "MIPS",
    0x14: "PowerPC", 0x16: "S390", 0x28: "ARM", 0x2A: "SuperH",
    0x32: "IA-64", 0x3E: "x86-64", 0x8C: "TMS320C6000",
    0xB7: "AArch64", 0xF3: "RISC-V",
}

# ─────────────────────────────────────────────────────────────
# PE details helpers
# ─────────────────────────────────────────────────────────────
PE_MACHINE = {
    0x014c: "x86 (i386)", 0x0200: "IA-64", 0x8664: "x86-64",
    0xAA64: "ARM64", 0x01C4: "ARMv7", 0x01C0: "ARM",
}
PE_SUBSYSTEM = {
    1: "Native", 2: "Windows GUI", 3: "Windows CUI",
    5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE GUI",
    10: "EFI Application", 14: "Xbox",
}


# ─────────────────────────────────────────────────────────────
# CORE DETECTION ENGINE
# ─────────────────────────────────────────────────────────────

def read_bytes(path: str, n: int = 512) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def detect_magic(data: bytes) -> dict:
    """Match magic signatures against raw file bytes."""
    best = None
    for offset, sig, ftype, mime, ext in MAGIC_SIGNATURES:
        end = offset + len(sig)
        if len(data) >= end and data[offset:end] == sig:
            # Prefer longer / more specific matches
            if best is None or len(sig) > len(best["sig"]):
                best = {"type": ftype, "mime": mime, "ext": ext,
                        "sig": sig, "offset": offset}

    if best is None:
        return {"type": "Unknown", "mime": "application/octet-stream",
                "ext": "", "sig": b"", "offset": 0}

    # ── Refine RIFF ──────────────────────────────────────────
    if best["type"] == "RIFF Container" and len(data) >= 12:
        sub = data[8:12]
        if sub in RIFF_SUBTYPES:
            t, m, e = RIFF_SUBTYPES[sub]
            best.update({"type": t, "mime": m, "ext": e})

    # ── Refine ZIP → Office Open XML / APK ───────────────────
    if best["type"] in ("ZIP / Office Open XML", "ZIP (empty)"):
        best = _refine_zip(data, best)

    return best


def _refine_zip(data: bytes, base: dict) -> dict:
    """Peek inside a ZIP's local-file-header names."""
    try:
        import zipfile, io
        with zipfile.ZipFile(io.BytesIO(data + b'\x00' * 100), 'r') as z:
            names = z.namelist()
    except Exception:
        return base

    for prefix, (t, m, e) in OPC_CONTENT_TYPES.items():
        if any(n.startswith(prefix) or n == prefix.rstrip("/") for n in names):
            base.update({"type": t, "mime": m, "ext": e})
            return base
    return base


# ─────────────────────────────────────────────────────────────
# FORMAT-SPECIFIC HEADER PARSERS
# ─────────────────────────────────────────────────────────────

def parse_png_header(data: bytes) -> dict:
    if len(data) < 24:
        return {}
    width, height = struct.unpack(">II", data[16:24])
    bit_depth  = data[24] if len(data) > 24 else "?"
    color_type = data[25] if len(data) > 25 else "?"
    ct_map = {0:"Grayscale", 2:"RGB", 3:"Indexed", 4:"Grayscale+Alpha", 6:"RGBA"}
    compress   = data[26] if len(data) > 26 else "?"
    filter_m   = data[27] if len(data) > 27 else "?"
    interlace  = "Adam7" if (len(data) > 28 and data[28]) else "None"
    return {
        "Width":         f"{width} px",
        "Height":        f"{height} px",
        "Bit Depth":     bit_depth,
        "Color Type":    ct_map.get(color_type, color_type),
        "Compression":   compress,
        "Filter Method": filter_m,
        "Interlace":     interlace,
    }


def parse_jpeg_header(data: bytes) -> dict:
    info = {}
    i = 2
    while i + 3 < len(data):
        if data[i] != 0xFF:
            break
        marker = data[i+1]
        length = struct.unpack(">H", data[i+2:i+4])[0] if i+4 <= len(data) else 0
        # SOF markers carry image dimensions
        if marker in (0xC0, 0xC2):
            if i + 9 < len(data):
                precision = data[i+4]
                height, width = struct.unpack(">HH", data[i+5:i+9])
                components    = data[i+9]
                info["Width"]      = f"{width} px"
                info["Height"]     = f"{height} px"
                info["Precision"]  = f"{precision}-bit"
                info["Components"] = components
        elif marker == 0xE0 and length >= 14:  # JFIF APP0
            info["Format"] = "JFIF"
            if i+12 < len(data):
                unit = {0:"No units (pixel ratio)", 1:"DPI", 2:"DPCM"}.get(data[i+11], "?")
                xd, yd = struct.unpack(">HH", data[i+12:i+16]) if i+16 <= len(data) else (0,0)
                info["Density"] = f"{xd}×{yd} ({unit})"
        elif marker == 0xE1 and length >= 4:   # EXIF APP1
            info["Contains EXIF"] = "Yes"
        if length == 0:
            break
        i += 2 + length
    return info


def parse_gif_header(data: bytes) -> dict:
    if len(data) < 13:
        return {}
    version        = data[3:6].decode("ascii", errors="replace")
    width, height  = struct.unpack("<HH", data[6:10])
    packed         = data[10]
    color_table    = bool(packed & 0x80)
    color_res      = ((packed >> 4) & 0x07) + 1
    gct_size       = 2 ** ((packed & 0x07) + 1) if color_table else 0
    bg_color_index = data[11]
    aspect_ratio   = data[12]
    return {
        "Version":           version,
        "Width":             f"{width} px",
        "Height":            f"{height} px",
        "Global Color Table":str(color_table),
        "Color Resolution":  color_res,
        "GCT Size":          gct_size,
        "BG Color Index":    bg_color_index,
        "Aspect Ratio":      aspect_ratio,
    }


def parse_bmp_header(data: bytes) -> dict:
    if len(data) < 54:
        return {}
    file_size     = struct.unpack("<I", data[2:6])[0]
    data_offset   = struct.unpack("<I", data[10:14])[0]
    width         = struct.unpack("<i", data[18:22])[0]
    height        = struct.unpack("<i", data[22:26])[0]
    planes        = struct.unpack("<H", data[26:28])[0]
    bpp           = struct.unpack("<H", data[28:30])[0]
    compression   = struct.unpack("<I", data[30:34])[0]
    comp_map = {0:"None (BI_RGB)", 1:"RLE8", 2:"RLE4", 3:"BITFIELDS", 4:"JPEG", 5:"PNG"}
    return {
        "File Size":    f"{file_size:,} bytes",
        "Data Offset":  f"{data_offset} bytes",
        "Width":        f"{abs(width)} px",
        "Height":       f"{abs(height)} px {'(top-down)' if height < 0 else '(bottom-up)'}",
        "Planes":       planes,
        "Bit Depth":    f"{bpp} bpp",
        "Compression":  comp_map.get(compression, compression),
    }


def parse_pdf_header(data: bytes) -> dict:
    line = data[:20].decode("latin-1", errors="replace").strip()
    version = line[5:8] if len(line) >= 8 else "?"
    info = {"PDF Version": version}
    text = data.decode("latin-1", errors="replace")
    if "/Encrypt" in text:
        info["Encrypted"] = "Yes"
    if "/XFA" in text:
        info["Contains XFA Forms"] = "Yes"
    return info


def parse_elf_header(data: bytes) -> dict:
    if len(data) < 52:
        return {}
    ei_class   = data[4]
    ei_data    = data[5]
    ei_version = data[6]
    ei_osabi   = data[7]
    osabi_map  = {
        0: "System V", 1: "HP-UX", 2: "NetBSD", 3: "Linux",
        6: "Solaris", 8: "FreeBSD", 9: "Tru64", 12: "OpenBSD",
    }
    e_type     = struct.unpack("<H" if ei_data == 1 else ">H", data[16:18])[0]
    e_machine  = struct.unpack("<H" if ei_data == 1 else ">H", data[18:20])[0]
    e_version  = struct.unpack("<I" if ei_data == 1 else ">I", data[20:24])[0]
    return {
        "Class":       ELF_CLASS.get(ei_class, f"Unknown({ei_class})"),
        "Endianness":  ELF_DATA.get(ei_data, f"Unknown({ei_data})"),
        "ELF Version": ei_version,
        "OS/ABI":      osabi_map.get(ei_osabi, f"0x{ei_osabi:02x}"),
        "Type":        ELF_TYPE.get(e_type, f"Unknown({e_type})"),
        "Architecture":ELF_MACHINE.get(e_machine, f"0x{e_machine:04x}"),
        "File Version":e_version,
    }


def parse_pe_header(data: bytes) -> dict:
    info = {}
    if len(data) < 64:
        return info
    pe_offset = struct.unpack("<I", data[60:64])[0]
    if pe_offset + 24 > len(data):
        return info
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return info
    machine     = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
    num_sec     = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
    timestamp   = struct.unpack("<I", data[pe_offset+8:pe_offset+12])[0]
    chars       = struct.unpack("<H", data[pe_offset+22:pe_offset+24])[0]
    ts_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "N/A"
    info["Machine"]          = PE_MACHINE.get(machine, f"0x{machine:04x}")
    info["Sections"]         = num_sec
    info["Compile Timestamp"]= ts_str
    info["Characteristics"]  = f"0x{chars:04x}"
    flags = []
    if chars & 0x0002: flags.append("Executable")
    if chars & 0x2000: flags.append("DLL")
    if chars & 0x0020: flags.append("Large Address Aware")
    if flags: info["Flags"] = ", ".join(flags)

    # Optional header
    opt_offset = pe_offset + 24
    if opt_offset + 2 <= len(data):
        magic = struct.unpack("<H", data[opt_offset:opt_offset+2])[0]
        info["PE Format"] = {0x10b: "PE32", 0x20b: "PE32+ (64-bit)", 0x107: "ROM"}.get(magic, f"0x{magic:04x}")
    if opt_offset + 68 <= len(data):
        subsystem = struct.unpack("<H", data[opt_offset+68:opt_offset+70])[0]
        info["Subsystem"] = PE_SUBSYSTEM.get(subsystem, f"0x{subsystem:04x}")
    return info


def parse_zip_header(data: bytes) -> dict:
    if len(data) < 30:
        return {}
    version_needed = struct.unpack("<H", data[4:6])[0]
    flags          = struct.unpack("<H", data[6:8])[0]
    compression    = struct.unpack("<H", data[8:10])[0]
    mod_time       = struct.unpack("<H", data[10:12])[0]
    mod_date       = struct.unpack("<H", data[12:14])[0]
    fname_len      = struct.unpack("<H", data[26:28])[0]
    extra_len      = struct.unpack("<H", data[28:30])[0]
    comp_map = {0:"Stored", 8:"Deflated", 9:"Enhanced Deflated",
                12:"bzip2", 14:"LZMA", 98:"PPMd"}
    first_file = data[30:30+fname_len].decode("utf-8", errors="replace") if fname_len else "(empty)"
    # DOS date decode
    try:
        day   = mod_date & 0x1F
        month = (mod_date >> 5) & 0x0F
        year  = ((mod_date >> 9) & 0x7F) + 1980
        hour  = (mod_time >> 11) & 0x1F
        minute= (mod_time >> 5) & 0x3F
        date_str = f"{year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}"
    except Exception:
        date_str = "N/A"
    return {
        "Version Needed": f"{version_needed/10:.1f}",
        "Compression":    comp_map.get(compression, compression),
        "Flags":          f"0x{flags:04x}",
        "First Entry":    first_file,
        "Modified":       date_str,
    }


def parse_gzip_header(data: bytes) -> dict:
    if len(data) < 10:
        return {}
    cm      = data[2]
    flags   = data[3]
    mtime   = struct.unpack("<I", data[4:8])[0]
    xfl     = data[8]
    os_byte = data[9]
    os_map  = {0:"MS-DOS",3:"Unix",7:"Macintosh",10:"NTFS/Windows",11:"NTFS",255:"Unknown"}
    ts_str  = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S") if mtime else "N/A"
    flag_list = []
    if flags & 0x01: flag_list.append("Text")
    if flags & 0x02: flag_list.append("Has CRC16")
    if flags & 0x04: flag_list.append("Has Extra")
    if flags & 0x08: flag_list.append("Has Filename")
    if flags & 0x10: flag_list.append("Has Comment")
    fname = ""
    if flags & 0x08:
        start = 10 if not (flags & 0x04) else ...
        try:
            end = data.index(0, 10)
            fname = data[10:end].decode("latin-1", errors="replace")
        except ValueError:
            fname = ""
    return {
        "Compression Method": cm,
        "Flags":     ", ".join(flag_list) if flag_list else "None",
        "Timestamp": ts_str,
        "Extra Flags": "Maximum compression" if xfl == 2 else ("Fastest" if xfl == 4 else str(xfl)),
        "OS":        os_map.get(os_byte, f"0x{os_byte:02x}"),
        **({"Original Filename": fname} if fname else {}),
    }


def parse_mp3_id3(data: bytes) -> dict:
    if data[:3] != b'ID3':
        return {}
    ver   = f"2.{data[3]}.{data[4]}"
    flags = data[5]
    size  = ((data[6] & 0x7F) << 21 | (data[7] & 0x7F) << 14 |
             (data[8] & 0x7F) << 7  | (data[9] & 0x7F))
    flag_list = []
    if flags & 0x80: flag_list.append("Unsync")
    if flags & 0x40: flag_list.append("Extended Header")
    if flags & 0x20: flag_list.append("Experimental")
    if flags & 0x10: flag_list.append("Footer Present")
    return {
        "ID3 Version": ver,
        "Tag Size":    f"{size:,} bytes",
        "Flags":       ", ".join(flag_list) if flag_list else "None",
    }


def parse_sqlite_header(data: bytes) -> dict:
    if len(data) < 100:
        return {}
    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:
        page_size = 65536
    write_ver  = data[18]
    read_ver   = data[19]
    change_counter = struct.unpack(">I", data[24:28])[0]
    page_count = struct.unpack(">I", data[28:32])[0]
    text_enc   = struct.unpack(">I", data[56:60])[0]
    enc_map    = {1:"UTF-8", 2:"UTF-16 LE", 3:"UTF-16 BE"}
    user_version = struct.unpack(">I", data[60:64])[0]
    return {
        "Page Size":       f"{page_size:,} bytes",
        "Write Version":   "WAL" if write_ver == 2 else "Journal",
        "Read Version":    "WAL" if read_ver == 2 else "Journal",
        "Page Count":      f"{page_count:,}",
        "Change Counter":  change_counter,
        "Text Encoding":   enc_map.get(text_enc, text_enc),
        "User Version":    user_version,
        "Approx Size":     f"{page_size * page_count / (1024**2):.2f} MB" if page_count else "?",
    }


FORMAT_PARSERS = {
    "PNG Image":          parse_png_header,
    "JPEG Image":         parse_jpeg_header,
    "GIF Image (87a)":    parse_gif_header,
    "GIF Image (89a)":    parse_gif_header,
    "BMP Image":          parse_bmp_header,
    "PDF Document":       parse_pdf_header,
    "ELF Binary (Linux)": parse_elf_header,
    "Windows PE Executable": parse_pe_header,
    "ZIP / Office Open XML": parse_zip_header,
    "Word Document":      parse_zip_header,
    "Excel Workbook":     parse_zip_header,
    "PowerPoint Presentation": parse_zip_header,
    "Android APK":        parse_zip_header,
    "GZIP Archive":       parse_gzip_header,
    "MP3 Audio (ID3 tag)":parse_mp3_id3,
    "SQLite Database":    parse_sqlite_header,
}


# ─────────────────────────────────────────────────────────────
# ENTROPY CALCULATION (detects encryption / compression)
# ─────────────────────────────────────────────────────────────

def byte_entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def entropy_label(e: float) -> str:
    if e < 1.0:  return "Very Low  (mostly zeros / padding)"
    if e < 3.5:  return "Low       (text / sparse data)"
    if e < 6.0:  return "Medium    (structured binary data)"
    if e < 7.2:  return "High      (compressed or encrypted)"
    return              "Very High (likely encrypted or random)"


# ─────────────────────────────────────────────────────────────
# HEX DUMP
# ─────────────────────────────────────────────────────────────

def hex_dump(data: bytes, rows: int = 8) -> str:
    lines = []
    for i in range(0, min(len(data), rows * 16), 16):
        chunk = data[i:i+16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:08x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# HASHES
# ─────────────────────────────────────────────────────────────

def file_hashes(path: str) -> dict:
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "MD5":    md5.hexdigest(),
        "SHA-1":  sha1.hexdigest(),
        "SHA-256":sha256.hexdigest(),
    }


# ─────────────────────────────────────────────────────────────
# EXTENSION MISMATCH CHECK
# ─────────────────────────────────────────────────────────────

def check_extension(path: str, detected_ext: str) -> str | None:
    file_ext = Path(path).suffix.lower()
    if not detected_ext:
        return None
    if file_ext and file_ext != detected_ext.lower():
        return f"⚠  Extension mismatch! File is '{file_ext}' but content is '{detected_ext}'"
    return None


# ─────────────────────────────────────────────────────────────
# MAIN ANALYSIS
# ─────────────────────────────────────────────────────────────

def analyze(path: str, show_hex: bool = False, as_json: bool = False) -> None:
    if not os.path.isfile(path):
        print(f"Error: '{path}' not found.")
        sys.exit(1)

    stat   = os.stat(path)
    data   = read_bytes(path, 1024)
    magic  = detect_magic(data)
    hashes = file_hashes(path)
    entropy_val   = byte_entropy(data[:512])
    mismatch      = check_extension(path, magic["ext"])
    specific_info = FORMAT_PARSERS.get(magic["type"], lambda _: {})(data)
    mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    result = {
        "file":     os.path.abspath(path),
        "filename": os.path.basename(path),
        "size":     stat.st_size,
        "modified": mtime,
        "detected": {
            "type":        magic["type"],
            "mime":        magic["mime"],
            "extension":   magic["ext"],
            "magic_bytes": magic["sig"].hex() if magic["sig"] else "",
            "magic_offset":magic["offset"],
        },
        "format_details": specific_info,
        "entropy":  round(entropy_val, 4),
        "entropy_label": entropy_label(entropy_val),
        "hashes":   hashes,
        "mismatch": mismatch,
    }

    if as_json:
        print(json.dumps(result, indent=2, default=str))
        return

    W = 60
    def sep(c="─"): print(c * W)
    def hdr(t): sep("═"); print(f"  {t}"); sep("═")
    def row(k, v): print(f"  {k:<22} {v}")

    hdr("🔍 FILE MAGIC NUMBER ANALYZER")

    sep()
    print("  FILE INFO")
    sep()
    row("Path:",     result["file"])
    row("Name:",     result["filename"])
    row("Size:",     f"{stat.st_size:,} bytes ({stat.st_size / 1024:.1f} KB)")
    row("Modified:", mtime)

    sep()
    print("  DETECTED FILE TYPE")
    sep()
    row("Type:",      magic["type"])
    row("MIME:",      magic["mime"])
    row("Extension:", magic["ext"] or "(binary / no extension)")
    row("Magic Hex:", " ".join(f"{b:02x}" for b in magic["sig"]) if magic["sig"] else "(none)")
    row("At Offset:", f"{magic['offset']} bytes")

    if mismatch:
        sep()
        print(f"  {mismatch}")

    if specific_info:
        sep()
        print("  FORMAT-SPECIFIC HEADER DETAILS")
        sep()
        for k, v in specific_info.items():
            row(f"{k}:", str(v))

    sep()
    print("  ENTROPY (first 512 bytes)")
    sep()
    row("Shannon Entropy:", f"{entropy_val:.4f} / 8.0")
    row("Assessment:",      entropy_label(entropy_val))

    sep()
    print("  CRYPTOGRAPHIC HASHES")
    sep()
    for algo, digest in hashes.items():
        row(f"{algo}:", digest)

    sep()
    print("  RAW HEX DUMP (first 128 bytes)")
    sep()
    print(hex_dump(data, rows=8 if not show_hex else 32))
    sep("═")
    print()


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Magic Number & File Header Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file",      help="Path to the file to analyze")
    parser.add_argument("--hex-dump",action="store_true", help="Show extended hex dump (256 bytes)")
    parser.add_argument("--json",    action="store_true", help="Output results as JSON")
    args = parser.parse_args()
    analyze(args.file, show_hex=args.hex_dump, as_json=args.json)


if __name__ == "__main__":
    main()
