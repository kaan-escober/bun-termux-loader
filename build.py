#!/usr/bin/env python3
"""
Bun Termux Builder
Creates self-contained Termux-compatible binaries from Bun bundled executables.
Automatically detects and embeds native libs (.so/.node) for bunfs shim support.
"""

import struct
import sys
import os
import re
import subprocess
from pathlib import Path

GLIBC_PATH = "/data/data/com.termux/files/usr/glibc"

# ═══════════════════════════════════════════════════════════════════════════════
# UTILS
# ═══════════════════════════════════════════════════════════════════════════════

def log(msg):
    print(f"[+] {msg}")

def error(msg):
    print(f"[!] Error: {msg}", file=sys.stderr)

def format_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

# ═══════════════════════════════════════════════════════════════════════════════
# COMPILATION
# ═══════════════════════════════════════════════════════════════════════════════

def build_shim(shim_path: str):
    log("Building bunfs_shim.so...")
    glibc = Path(GLIBC_PATH)
    if not glibc.exists():
        error(f"Glibc not found at {GLIBC_PATH}. Cannot build shim.")
        sys.exit(1)

    cmd = [
        "clang",
        "--target=aarch64-linux-gnu",
        "-shared", "-fPIC", "-O2", "-nostdlib",
        f"-I{glibc}/include",
        f"-Wl,--dynamic-linker={glibc}/lib/ld-linux-aarch64.so.1",
        f"-Wl,-rpath,{glibc}/lib",
        "-o", shim_path,
        "bunfs_shim.c",
        f"{glibc}/lib/libc.so.6",
        f"{glibc}/lib/libc_nonshared.a",
        f"{glibc}/lib/ld-linux-aarch64.so.1",
        f"{glibc}/lib/libdl.so.2"
    ]
    
    try:
        subprocess.run(cmd, check=True)
        log("Shim built successfully.")
    except subprocess.CalledProcessError:
        error("Failed to build bunfs_shim.so")
        sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
# ELF PARSING
# ═══════════════════════════════════════════════════════════════════════════════

ELF_MAGIC = b'\x7fELF'

def find_elf_end(data: bytes) -> int:
    if len(data) < 64 or data[:4] != ELF_MAGIC:
        raise ValueError("Not a valid ELF file")
    if data[4] != 2:
        raise ValueError("Only 64-bit ELF supported")

    e_phoff = struct.unpack('<Q', data[32:40])[0]
    e_phentsize = struct.unpack('<H', data[54:56])[0]
    e_phnum = struct.unpack('<H', data[56:58])[0]

    e_shoff = struct.unpack('<Q', data[40:48])[0]
    e_shentsize = struct.unpack('<H', data[58:60])[0]
    e_shnum = struct.unpack('<H', data[60:62])[0]

    end = 0

    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', data[ph:ph+4])[0]
        if p_type == 1:  # PT_LOAD
            p_offset = struct.unpack('<Q', data[ph+8:ph+16])[0]
            p_filesz = struct.unpack('<Q', data[ph+32:ph+40])[0]
            seg_end = p_offset + p_filesz
            if seg_end > end:
                end = seg_end

    if e_shoff > 0 and e_shnum > 0:
        sh_end = e_shoff + e_shentsize * e_shnum
        if sh_end > end:
            end = sh_end

    return end

def elf64_size(data: bytes) -> int:
    if len(data) < 64 or data[:4] != ELF_MAGIC:
        return 0
    ei_class = data[4]
    if ei_class != 2:
        return 0
    try:
        return find_elf_end(data)
    except (ValueError, struct.error):
        return 0

# Supported Bun bundled binary markers
# Old format: "---- Bun! ----" (legacy)
# New format: "packages by bun" (recent Bun versions)
# Must search larger range as Bun embeds source map/assets
BUN_MARKERS = [b'---- Bun! ----', b'packages by bun']

def check_bun_marker(data: bytes) -> bool:
    # Check both old and new markers anywhere in binary
    # Marker position varies by version (end, near-start, or anywhere in between)
    for marker in BUN_MARKERS:
        if marker in data:
            return True
    return False

# ═══════════════════════════════════════════════════════════════════════════════
# NATIVE LIB DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def find_bunfs_native_libs(data: bytes, elf_end: int):
    """
    Scan the embedded data region for native lib filenames referenced via
    /$bunfs/root/ paths, then locate their ELF data in the binary.
    Returns list of (name, data_bytes) tuples.
    """
    embedded = data[elf_end:]

    native_names = set()
    for m in re.finditer(rb'/\$bunfs/root/([^\x00\"\'\n]+\.(?:so|node))', embedded):
        name = m.group(1).decode('utf-8', errors='replace')
        slash = name.rfind('/')
        if slash >= 0:
            name = name[slash + 1:]
        native_names.add(name)

    if not native_names:
        return []

    log(f"Found {len(native_names)} native lib reference(s): {', '.join(sorted(native_names))}")

    elf_blobs = []
    pos = 0
    while pos < len(embedded):
        idx = embedded.find(ELF_MAGIC, pos)
        if idx < 0:
            break
        blob = embedded[idx:]
        sz = elf64_size(blob)
        if sz > 1024:
            elf_blobs.append((elf_end + idx, sz, blob[:sz]))
        pos = idx + 4

    SIGNATURES = {
        'libopentui':  [b'setLogCallback', b'renderToStr', b'OpenTUI'],
        'librust_pty': [b'openpty', b'libpthread', b'forkpty', b'rust_pty'],
        'watcher':     [b'napi_register_module', b'napi_create_reference'],
    }

    def identify_blob(blob):
        for lib_key, sigs in SIGNATURES.items():
            if any(sig in blob for sig in sigs):
                return lib_key
        return None

    claimed = set()
    libs = []
    for name in sorted(native_names):
        matched = False
        stem = name.split('.')[0].split('-')[0]
        for i, (off, sz, blob) in enumerate(elf_blobs):
            if i in claimed:
                continue
            if name.encode() in blob[:65536]:
                log(f"  {name}: {format_size(sz)} (offset {off})")
                libs.append((name, blob))
                claimed.add(i)
                matched = True
                break
        if not matched:
            for i, (off, sz, blob) in enumerate(elf_blobs):
                if i in claimed:
                    continue
                blob_id = identify_blob(blob)
                if blob_id and any(k in name for k in [blob_id]):
                    log(f"  {name}: {format_size(sz)} (offset {off}, matched by signature)")
                    libs.append((name, blob))
                    claimed.add(i)
                    matched = True
                    break
        if not matched:
            for i, (off, sz, blob) in enumerate(elf_blobs):
                if i in claimed:
                    continue
                e_type = struct.unpack_from('<H', blob, 16)[0]
                if e_type == 3:
                    log(f"  {name}: {format_size(sz)} (offset {off}, matched by elimination)")
                    libs.append((name, blob))
                    claimed.add(i)
                    matched = True
                    break
        if not matched:
            log(f"  {name}: WARNING - could not locate in binary")

    return libs

# ═══════════════════════════════════════════════════════════════════════════════
# BUNLIBS PACKING
# ═══════════════════════════════════════════════════════════════════════════════

BUNLIBS_MAGIC = b'BUNLIBS1'

def pack_native_libs(libs, shim_path=None):
    """
    Pack native libs (and optionally shim) into BUNLIBS1 format.
    Format:
      "BUNLIBS1" (8 bytes)
      num_libs   (4 bytes LE)
      For each lib:
        name_len (2 bytes LE)
        name     (name_len bytes)
        data_len (8 bytes LE)
        data     (data_len bytes)
    """
    all_libs = list(libs)

    if shim_path and os.path.exists(shim_path):
        with open(shim_path, 'rb') as f:
            shim_data = f.read()
        all_libs.append(('bunfs_shim.so', shim_data))
        log(f"  bunfs_shim.so: {format_size(len(shim_data))}")

    if not all_libs:
        return b''

    buf = bytearray()
    buf += BUNLIBS_MAGIC
    buf += struct.pack('<I', len(all_libs))

    for name, data in all_libs:
        name_bytes = name.encode('utf-8')
        buf += struct.pack('<H', len(name_bytes))
        buf += name_bytes
        buf += struct.pack('<Q', len(data))
        buf += data

    return bytes(buf)

# ═══════════════════════════════════════════════════════════════════════════════
# CORE BUILD
# ═══════════════════════════════════════════════════════════════════════════════

METADATA_MAGIC = b'BUNWRAP1'

def build(input_path: str, output_path: str, wrapper_path: str, shim_path: str):
    input_file = Path(input_path).resolve()
    output_file = Path(output_path).resolve()
    wrapper_file = Path(wrapper_path).resolve()
    shim_file = Path(shim_path).resolve()

    is_default_wrapper = (str(wrapper_file) == str(Path("./wrapper").resolve()))
    wrapper_built = False
    
    is_default_shim = (str(shim_file) == str(Path("./bunfs_shim.so").resolve()))

    if not input_file.exists():
        error(f"Input file not found: {input_file}")
        sys.exit(1)

    if not wrapper_file.exists():
        if is_default_wrapper:
             log("Wrapper not found. Building...")
             try:
                 subprocess.run(["make"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                 wrapper_built = True
             except subprocess.CalledProcessError:
                 error("Failed to build wrapper with make")
                 sys.exit(1)
        else:
             error(f"Wrapper not found: {wrapper_file}")
             sys.exit(1)

    if not shim_file.exists():
        if is_default_shim:
             build_shim(str(shim_file))
        else:
             log(f"Warning: Shim not found at {shim_file}. Native libs may fail to load.")

    log(f"Processing: {input_file.name} -> {output_file.name}")

    with open(input_file, 'rb') as f:
        input_data = f.read()

    if not check_bun_marker(input_data):
        error("Input doesn't appear to be a Bun bundled binary (missing '---- Bun! ----' marker)")
        sys.exit(1)

    try:
        elf_end = find_elf_end(input_data)
    except ValueError as e:
        error(f"ELF parsing failed: {e}")
        sys.exit(1)

    bun_elf = input_data[:elf_end]
    embedded_data = input_data[elf_end:]

    with open(wrapper_file, 'rb') as f:
        wrapper_data = f.read()

    native_libs = find_bunfs_native_libs(input_data, elf_end)
    bunlibs_block = pack_native_libs(native_libs, shim_path)

    # Layout:
    #   [Wrapper ELF]
    #   [BUNWRAP1 (8) | bun_elf_size (8)]
    #   [Bun ELF binary]
    #   [BUNLIBS1 block (if native libs found)]
    #   [Embedded JS + Bun trailer at EOF]

    metadata = METADATA_MAGIC + struct.pack('<Q', len(bun_elf))

    output_data = bytearray()
    output_data += wrapper_data
    output_data += metadata
    output_data += bun_elf
    output_data += bunlibs_block
    output_data += embedded_data

    try:
        with open(output_file, 'wb') as f:
            f.write(output_data)
    except OSError as e:
        if e.errno == 26:
            error(f"Output file is busy (probably running)")
            sys.exit(1)
        raise

    final_size = len(output_data)
    with open(output_file, 'r+b') as f:
        f.seek(-8, 2)
        f.write(struct.pack('<Q', final_size))

    os.chmod(output_file, 0o755)

    log(f"Success! Output size: {format_size(final_size)}")
    if bunlibs_block:
        log(f"  Embedded {len(native_libs)} native lib(s) + shim")

    if is_default_wrapper and wrapper_built:
        log("Cleaning up wrapper")
        try:
             os.remove(wrapper_file)
        except OSError:
             pass

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    args = sys.argv[1:]

    if '-h' in args or '--help' in args:
        print("Usage: python3 build.py [input] [output] [--wrapper <path>] [--shim <path>]")
        print()
        print("Options:")
        print("  --wrapper <path>  Path to wrapper binary (default: ./wrapper)")
        print("  --shim <path>     Path to bunfs_shim.so (default: ./bunfs_shim.so)")
        print()
        print("Native .so/.node libs are auto-detected and embedded.")
        sys.exit(0)

    wrapper_path = "./wrapper"
    shim_path = "./bunfs_shim.so"
    positional = []
    i = 0
    while i < len(args):
        if args[i] == '--wrapper' and i + 1 < len(args):
            wrapper_path = args[i + 1]
            i += 2
        elif args[i] == '--shim' and i + 1 < len(args):
            shim_path = args[i + 1]
            i += 2
        else:
            positional.append(args[i])
            i += 1

    input_path = positional[0] if len(positional) > 0 else "./droid"
    if len(positional) > 1:
        output_path = positional[1]
    else:
        inp = Path(input_path)
        output_path = str(inp.parent / f"{inp.stem}-termux")

    build(input_path, output_path, wrapper_path, shim_path)

if __name__ == '__main__':
    main()
