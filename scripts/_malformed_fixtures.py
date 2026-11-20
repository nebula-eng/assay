"""Generate malformed inputs to check the parser never panics or hangs.

These are the shapes a fuzzer finds first: a header that points past the end of
the file, a count field larger than the file could hold, and container formats
whose internal offsets disagree with each other.
"""

import os
import random
import struct

OUT = os.path.join(os.environ.get("TEMP", "/tmp"), "bad")
os.makedirs(OUT, exist_ok=True)


def write(name: str, data: bytes) -> None:
    with open(os.path.join(OUT, name), "wb") as handle:
        handle.write(data)


# 1. Valid MZ, e_lfanew points past EOF.
pe = bytearray(b"MZ" + b"\x00" * 0x3E)
struct.pack_into("<I", pe, 0x3C, 0x1000)
write("trunc_pe.exe", bytes(pe))

# 2. e_lfanew lands inside the DOS header.
pe2 = bytearray(b"MZ" + b"\x00" * 0x3E)
struct.pack_into("<I", pe2, 0x3C, 0x10)
write("lfanew_inside.exe", bytes(pe2))

# 3. Section count 0xFFFF on a file that could never hold them.
pe3 = bytearray(b"MZ" + b"\x00" * 0x3E)
struct.pack_into("<I", pe3, 0x3C, 0x40)
pe3 += b"\x00" * (0x40 - len(pe3))
pe3 += b"PE\x00\x00"
pe3 += struct.pack("<HHIIIHH", 0x8664, 0xFFFF, 0, 0, 0, 0, 0)
pe3 += b"\x00" * 0x200
write("sections_ffff.exe", bytes(pe3))

# 4. ELF64 whose section table starts exactly at EOF.
elf = bytearray(64)
elf[0:4] = b"\x7fELF"
elf[4] = 2  # ELFCLASS64
elf[5] = 1  # little endian
elf[6] = 1  # EV_CURRENT
struct.pack_into("<H", elf, 16, 3)  # ET_DYN
struct.pack_into("<H", elf, 18, 62)  # EM_X86_64
struct.pack_into("<Q", elf, 40, 64)  # e_shoff == EOF
struct.pack_into("<H", elf, 58, 64)  # e_shentsize
struct.pack_into("<H", elf, 60, 64)  # e_shnum
write("trunc_elf.so", bytes(elf))

# 5. Mach-O64 claiming a thousand load commands beyond the file.
macho = bytearray(32)
struct.pack_into("<I", macho, 0, 0xFEEDFACF)
struct.pack_into("<I", macho, 4, 0x01000007)
struct.pack_into("<I", macho, 16, 1000)  # ncmds
struct.pack_into("<I", macho, 20, 100000)  # sizeofcmds
write("trunc_macho.dylib", bytes(macho))

# 6. Zip whose end-of-central-directory offset points backwards.
zip_data = bytearray()
zip_data += b"PK\x03\x04" + b"\x00" * 26
zip_data += b"PK\x01\x02" + b"\x00" * 42
write("bad_zip.zip", bytes(zip_data))

# 7. A gzip header that promises more than the file holds.
write("trunc_gzip.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"\x01\x02")

# 8. Degenerate sizes.
write("zeros.bin", b"\x00" * 4096)
write("one_byte.bin", b"A")

# 9. Random noise, seeded so the result is reproducible.
random.seed(7)
write("noise.bin", bytes(random.randrange(256) for _ in range(8192)))

# 10. Deeply nested-looking script markers, to exercise the script path.
write("obfuscated.sh", ("eval (" * 200 + ")" * 200).encode())

print(f"wrote {len(os.listdir(OUT))} malformed inputs to {OUT}")
