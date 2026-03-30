<div align="center">

```
███╗   ███╗ █████╗  ██████╗ ██╗ ██████╗
████╗ ████║██╔══██╗██╔════╝ ██║██╔════╝
██╔████╔██║███████║██║  ███╗██║██║
██║╚██╔╝██║██╔══██║██║   ██║██║██║
██║ ╚═╝ ██║██║  ██║╚██████╔╝██║╚██████╗
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝ ╚═════╝
```

**Magic Number & File Header Analyzer**

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-f97316?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-8b5cf6?style=flat-square)
![Made by](https://img.shields.io/badge/Made%20by-Rikixz-ec4899?style=flat-square)

*Identify any file's true type from its raw bytes — no extensions, no guessing.*

</div>

---

## What it does

Drop any file in. Get back its **true format**, **header details**, **entropy**, and **cryptographic hashes** — all from the raw bytes, no file extension needed.

```
════════════════════════════════════════════════════════════
  🔍 FILE MAGIC NUMBER ANALYZER
════════════════════════════════════════════════════════════
  FILE INFO
────────────────────────────────────────────────────────────
  Path:                  /home/user/suspicious.pdf
  Size:                  259 bytes (0.3 KB)
────────────────────────────────────────────────────────────
  DETECTED FILE TYPE
────────────────────────────────────────────────────────────
  Type:                  Word Document
  MIME:                  application/vnd.openxmlformats...
  Extension:             .docx
  Magic Hex:             50 4b 03 04
────────────────────────────────────────────────────────────
  ⚠  Extension mismatch! File is '.pdf' but content is '.docx'
════════════════════════════════════════════════════════════
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/blaxkmiradev/-magic_analyzer.git
cd -magic_analyzer

# Run — no pip install needed
python magic_analyzer.py <file>
```

---

## Usage

```bash
# Basic analysis
python magic_analyzer.py photo.jpg

# Extended hex dump (256 bytes)
python magic_analyzer.py archive.zip --hex-dump

# JSON output (pipe-friendly)
python magic_analyzer.py binary.bin --json
```

### JSON output example

```json
{
  "detected": {
    "type": "PNG Image",
    "mime": "image/png",
    "extension": ".png",
    "magic_bytes": "89504e470d0a1a0a"
  },
  "format_details": {
    "Width": "1920 px",
    "Height": "1080 px",
    "Color Type": "RGBA",
    "Bit Depth": 8
  },
  "entropy": 7.91,
  "entropy_label": "Very High (likely encrypted or random)",
  "hashes": {
    "MD5": "d41d8cd98f00b204e9800998ecf8427e",
    "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "SHA-256": "e3b0c44298fc1c149afbf4c8996fb924..."
  }
}
```

---

## Supported Formats

| Category | Formats |
|---|---|
| 🖼 **Images** | PNG, JPEG, GIF, BMP, TIFF, WebP, JPEG2000, PSD, ICO |
| 🎵 **Audio** | MP3 (ID3), FLAC, OGG, WAV, AIFF, WMA |
| 🎬 **Video** | MP4/MOV, MKV/WebM, AVI, MPEG, FLV, WMV |
| 📄 **Documents** | PDF, DOCX, XLSX, PPTX, XLS/DOC (OLE2), RTF |
| 📦 **Archives** | ZIP, GZIP, BZIP2, XZ, 7z, RAR, LZ4, ZStd, TAR |
| ⚙️ **Executables** | ELF (Linux), PE/EXE/DLL (Windows), Mach-O (macOS), APK |
| 🔤 **Fonts** | TTF, OTF, WOFF, WOFF2 |
| 🗄 **Other** | SQLite, PEM/Keys, Shell Scripts, PostScript |

---

## What each section tells you

**File Type Detection** — Matches 70+ magic byte signatures at their correct offsets. Drills into ZIP containers to distinguish `.docx` / `.xlsx` / `.pptx` / APK. Breaks down RIFF containers into WAV, AVI, or WebP.

**Format-specific Headers** — Goes beyond just the type. For example:
- **PNG** → width, height, color type, bit depth, interlace mode
- **ELF** → architecture (x86-64, ARM, RISC-V…), endianness, OS ABI, binary type
- **PE/EXE** → target machine, compile timestamp, DLL vs executable, subsystem
- **SQLite** → page size, WAL mode, encoding, page count
- **GZIP** → original filename, OS, timestamp, compression level
- **ZIP** → compression method, first entry name, version needed
- **JPEG** → dimensions, DPI/density, EXIF presence
- **PDF** → version, encryption, XFA forms

**Entropy** — Shannon entropy of the first 512 bytes. Useful for spotting encrypted payloads, compressed blobs, or suspiciously random data hiding inside innocent-looking files.

**Extension Mismatch** — Warns when the file's actual content doesn't match its extension. Catches renamed files, obfuscated malware, or just accidental mis-saves.

**Hashes** — MD5, SHA-1, SHA-256 of the full file for integrity checks and VirusTotal lookups.

---

## Requirements

- Python **3.8+**
- **Zero** third-party packages — stdlib only

---

## License

MIT © [Rikixz](https://github.com/blaxkmiradev)

---

<div align="center">
<sub>Made with ♥ by Rikixz</sub>
</div>
