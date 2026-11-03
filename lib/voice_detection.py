"""Read Borderlands 3/4 voice pack indexes without changing game files.

The public entry point is :func:`scan_voice_packs`.  It returns immutable
results suitable for a CLI or a future Tkinter interface; this module never
deletes or modifies files.

Borderlands 3 encrypts its PAK indexes.  Scanning it requires the optional
``cryptography`` package and the game's own executable (the key is extracted
from that executable and is not included here).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import struct
from typing import Iterable


VOICE_LANGUAGES = (
    "Chinese(Simplified)",
    "English(US)",
    "French(France)",
    "German",
    "Italian",
    "Japanese",
    "Korean",
    "Spanish(Spain)",
)

_BL4_FILE = re.compile(r"^pakchunk(\d+)-Windows_(\d+)_P\.(pak|ucas|utoc)$", re.I)
_BL3_FILE = re.compile(
    r"^pakchunk(\d+)(?:optional)?-WindowsNoEditor(?:_(\d+)_P)?\.pak$", re.I
)
_TOC_MAGIC = b"-==--==--==--==-"
_PAK_MAGIC = 0x5A6F12E1


class VoiceScanError(Exception):
    """A recognized game file is malformed or unsupported."""


@dataclass(frozen=True)
class VoicePack:
    """A detected language pack and the game files belonging to it."""

    language: str
    chunk_id: int
    files: tuple[Path, ...]
    size_bytes: int


@dataclass(frozen=True)
class ScanResult:
    """Voice packs found in a game's ``OakGame/Content/Paks`` directory."""

    game: str
    paks_directory: Path
    packs: tuple[VoicePack, ...]
    skipped_files: tuple[Path, ...]

    @property
    def languages(self) -> tuple[str, ...]:
        return tuple(sorted({pack.language for pack in self.packs}))


def scan_voice_packs(
    paks_directory: str | Path,
    *,
    game: str,
    executable: str | Path | None = None,
) -> ScanResult:
    """Identify voice-language chunks in a Borderlands Paks directory.

    ``game`` must be ``"bl3"`` or ``"bl4"``.  For Borderlands 3, pass the
    path to ``Borderlands3.exe``; its local key is needed to read encrypted
    indexes.  Detection is read-only.
    """

    root = Path(paks_directory).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Paks directory does not exist: {root}")
    game_key = game.lower().replace("borderlands", "").replace(" ", "")
    if game_key not in {"3", "4", "bl3", "bl4"}:
        raise ValueError("game must be 'bl3' or 'bl4'")
    is_bl3 = game_key in {"3", "bl3"}
    if is_bl3 and executable is None:
        raise ValueError("Borderlands 3 scanning requires the game's executable")

    matcher = _BL3_FILE if is_bl3 else _BL4_FILE
    chunks: dict[int, list[Path]] = {}
    for path in root.iterdir():
        match = matcher.match(path.name)
        if match and path.is_file():
            chunks.setdefault(int(match.group(1)), []).append(path)

    key = _find_bl3_key(root, Path(executable)) if is_bl3 and chunks else None
    packs: list[VoicePack] = []
    skipped: list[Path] = []
    for chunk_id, files in sorted(chunks.items()):
        try:
            language = _chunk_language(files, is_bl3=is_bl3, key=key)
        except (VoiceScanError, ValueError, IndexError, struct.error):
            skipped.extend(files)
            continue
        if language is None:
            continue
        ordered = tuple(sorted(files, key=lambda p: (p.suffix.lower() == ".pak", p.name.lower())))
        packs.append(VoicePack(language, chunk_id, ordered, sum(p.stat().st_size for p in ordered)))
    return ScanResult("Borderlands 3" if is_bl3 else "Borderlands 4", root,
                      tuple(packs), tuple(sorted(set(skipped))))


def _chunk_language(files: Iterable[Path], *, is_bl3: bool, key: bytes | None) -> str | None:
    languages: set[str] = set()
    for path in files:
        suffix = path.suffix.lower()
        if suffix == ".pak":
            pak = _read_pak(path, is_bl3=is_bl3, key=key)
            if pak is None:
                return None
            mount, entries = pak
            if is_bl3:
                # BL3 paths are relative to the mount point. Only entries
                # beneath WwiseAudio identify voice language chunks.
                paths = []
                for name in entries:
                    parts = (mount + name).strip("/").split("/")
                    try:
                        index = parts.index("WwiseAudio")
                    except ValueError:
                        continue
                    paths.append(parts[index + 1 :])
            else:
                if entries and not mount.rstrip("/").endswith("WwiseAudio"):
                    return None
                paths = [name.strip("/").split("/") for name in entries]
            for parts in paths:
                if parts and parts[0] == "Media":
                    parts = parts[1:]
                if len(parts) > 1 and parts[0] in VOICE_LANGUAGES:
                    languages.add(parts[0])
        elif suffix == ".utoc":
            if any(not header for header in _read_toc_headers(path)):
                return None
    return next(iter(languages)) if len(languages) == 1 else None


def _read_toc_headers(path: Path) -> tuple[bool, ...]:
    data = path.read_bytes()
    if len(data) < 104 or data[:16] != _TOC_MAGIC or data[16] != 8:
        raise VoiceScanError(f"{path.name}: unsupported IoStore TOC")
    if _u32(data, 32) != 12 or data[80] & 6 or _u32(data, 52) != 1:
        raise VoiceScanError(f"{path.name}: unsupported encrypted, signed, or split TOC")
    count = _u32(data, 24)
    ids_offset = _u32(data, 20)
    spans_offset = ids_offset + count * 12
    blocks_offset = spans_offset + count * 10 + _u32(data, 84) * 4 + _u32(data, 96) * 4
    block_count = _u32(data, 28)
    expected_end = (blocks_offset + block_count * 12 + _u32(data, 36) * _u32(data, 40)
                    + _u32(data, 48))
    if expected_end > len(data) or len(data) - expected_end != count * 24:
        raise VoiceScanError(f"{path.name}: inconsistent TOC sections")
    return tuple(data[ids_offset + i * 12 + 11] == 6 for i in range(count))


def _read_pak(path: Path, *, is_bl3: bool, key: bytes | None):
    return _read_pak_v6(path, key) if is_bl3 else _read_pak_v11(path)


def _read_pak_v11(path: Path):
    data = path.read_bytes()
    if len(data) < 221:
        raise VoiceScanError(f"{path.name}: too small to be a PAK")
    footer = data[-221:]
    if _u32(footer, 17) != _PAK_MAGIC or _i32(footer, 21) != 11:
        raise VoiceScanError(f"{path.name}: unsupported PAK footer/version")
    if footer[16] != 0:
        return None  # Encrypted BL4 indexes are not readable by this scanner.
    index_offset, index_size = _i64(footer, 25), _i64(footer, 33)
    index = _slice(data, index_offset, index_size, path)
    p = 0
    mount, p = _fstring(index, p)
    if _u32(index, p + 12) != 0:
        p += 36
    if _u32(index, p + 16) == 0:
        return None
    directory_offset, directory_size = _i64(index, p + 20), _i64(index, p + 28)
    encoded_entries = p + 60
    q = encoded_entries + _i32(index, p + 56) + 4
    if q > len(index):
        raise VoiceScanError(f"{path.name}: invalid PAK index")
    plain_count = _u32(index, q - 4)
    for _ in range(plain_count):
        _bounds(index, q, 53, path)
        compressed = _u32(index, q + 24) != 0
        q += 57 + 16 * _u32(index, q + 48) if compressed else 53
    if q != len(index):
        raise VoiceScanError(f"{path.name}: PAK index layout mismatch")
    directories = _slice(data, directory_offset, directory_size, path)
    folders, r = _i32(directories, 0), 4
    names: list[str] = []
    for _ in range(folders):
        folder, r = _fstring(directories, r)
        count, r = _i32(directories, r), r + 4
        for _ in range(count):
            name, r = _fstring(directories, r)
            location, r = _i32(directories, r), r + 4
            if location != -(1 << 31):
                names.append(folder + name)
    return mount, names


def _find_bl3_key(paks: Path, executable: Path) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("Borderlands 3 scanning needs 'cryptography' (python -m pip install cryptography)") from exc
    if not executable.is_file():
        raise FileNotFoundError(f"Borderlands3.exe not found: {executable}")
    probes = sorted(paks.glob("*.pak"), key=lambda item: item.stat().st_size, reverse=True)
    if not probes:
        raise VoiceScanError("No PAK files found to validate the Borderlands 3 key")
    exe = executable.read_bytes()
    for offset in range(max(0, len(exe) - 56)):
        if exe[offset:offset + 2] != b"\xC7\x01":
            continue
        if not all(exe[offset + 7 * j - 1:offset + 7 * j + 2] == bytes((0xC7, 0x41, 4 * j))
                   for j in range(1, 8)):
            continue
        key = bytearray(32)
        key[:4] = exe[offset + 2:offset + 6]
        for j in range(1, 8):
            key[j * 4:j * 4 + 4] = exe[offset + 7 * j + 2:offset + 7 * j + 6]
        try:
            _read_pak_v6(probes[0], bytes(key), validate_key=True)
            return bytes(key)
        except (VoiceScanError, ValueError):
            continue
    raise VoiceScanError(f"Could not find a key in {executable.name} that opens {probes[0].name}")


def _read_pak_v6(path: Path, key: bytes | None, validate_key: bool = False):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("Borderlands 3 scanning needs the 'cryptography' package") from exc
    data = path.read_bytes()
    if len(data) < 45:
        raise VoiceScanError(f"{path.name}: too small to be a PAK")
    footer = data[-45:]
    if _u32(footer, 1) != _PAK_MAGIC or _i32(footer, 5) != 6:
        raise VoiceScanError(f"{path.name}: unsupported PAK footer/version")
    encrypted = footer[0] != 0
    if validate_key and not encrypted:
        raise VoiceScanError("PAK index is not encrypted; cannot validate key")
    index_offset, index_size = _i64(footer, 9), _i64(footer, 17)
    index = _slice(data, index_offset, index_size, path)
    if encrypted:
        if key is None or len(index) % 16:
            raise VoiceScanError(f"{path.name}: missing key or invalid encrypted index")
        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        index = decryptor.update(index) + decryptor.finalize()
    import hashlib
    if hashlib.sha1(index).digest() != footer[25:45]:
        raise VoiceScanError(f"{path.name}: index fingerprint mismatch")
    mount, p = _fstring(index, 0)
    count, p = _i32(index, p), p + 4
    names: list[str] = []
    for _ in range(count):
        name, p = _fstring(index, p)
        _bounds(index, p, 53, path)
        method = _i32(index, p + 24)
        p += 48
        if method != 0:
            blocks, p = _i32(index, p), p + 4
            if blocks <= 0:
                raise VoiceScanError(f"{path.name}: compressed entry has no blocks")
            p += blocks * 16
        _bounds(index, p, 5, path)
        flags = index[p]
        p += 5
        if flags & 2 == 0:
            names.append(name)
    if p > len(index) or len(index) - p >= 16:
        raise VoiceScanError(f"{path.name}: PAK index layout mismatch")
    return mount, names


def _slice(data: bytes, offset: int, size: int, path: Path) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise VoiceScanError(f"{path.name}: file section is out of bounds")
    return data[offset:offset + size]


def _bounds(data: bytes, offset: int, size: int, path: Path) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise VoiceScanError(f"{path.name}: unexpected end of file")


def _fstring(data: bytes, offset: int) -> tuple[str, int]:
    count = _i32(data, offset)
    offset += 4
    if count == 0:
        return "", offset
    size = -count * 2 if count < 0 else count
    raw = data[offset:offset + size]
    if len(raw) != size:
        raise VoiceScanError("Invalid Unreal string in PAK index")
    encoding = "utf-16-le" if count < 0 else "latin-1"
    return raw.decode(encoding).rstrip("\0"), offset + size


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _i64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<q", data, offset)[0]
