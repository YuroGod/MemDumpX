from pathlib import Path
from typing import Optional
import struct

import ida_kernwin
import ida_idaapi
import ida_bytes

PLUGIN_VERSION = "0.1"


def _read_memory(ea: int, size: int) -> Optional[bytes]:
    if size <= 0:
        return b""
    try:
        data = ida_bytes.get_bytes(ea, size)
    except Exception as e:
        ida_kernwin.msg(f"_read_memory exception @0x{ea:X}: {e}\n")
        data = None
    if data:
        return data

    parts = []
    remain = size
    cur = ea
    chunk = 0x1000
    while remain > 0:
        toread = min(chunk, remain)
        try:
            p = ida_bytes.get_bytes(cur, toread)
        except Exception:
            p = None
        if not p:
            break
        parts.append(p)
        readlen = len(p)
        cur += readlen
        remain -= readlen
        if readlen < toread:
            break
    if not parts:
        return None
    return b"".join(parts)


def _dump_file(data: bytes, suggested_name: str):
    fp = ida_kernwin.ask_file(True, suggested_name, "Save dump as")
    if not fp:
        return
    try:
        Path(fp).write_bytes(data)
        ida_kernwin.msg(f"Dumped {len(data)} bytes -> {fp}\n")
    except OSError as exc:
        ida_kernwin.warning(f"Write failed: {exc}")


def _dump_pe(base: int):
    dos = _read_memory(base, 0x40)
    if not dos or len(dos) < 0x40 or dos[:2] != b"MZ":
        ida_kernwin.warning(f"Invalid DOS header @0x{base:X}")
        return

    try:
        e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    except struct.error:
        ida_kernwin.warning("Cannot parse e_lfanew")
        return

    nt = _read_memory(base + e_lfanew, 4 + 20)
    if not nt or len(nt) < 4 or nt[:4] != b"PE\x00\x00":
        ida_kernwin.warning(f"Invalid PE signature @0x{base + e_lfanew:X}")
        return

    try:
        (_, num_sections, _, _, _, size_of_opt_header, _) = struct.unpack_from(
            "<HHIIIHH", nt, 4
        )
    except struct.error:
        ida_kernwin.warning("Failed to unpack FileHeader")
        return

    opt = _read_memory(base + e_lfanew + 4 + 20, size_of_opt_header)
    if not opt:
        ida_kernwin.warning("Failed to read OptionalHeader")
        return

    size_of_headers = 0
    if len(opt) >= 0x3C + 4:
        try:
            size_of_headers = struct.unpack_from("<I", opt, 0x3C)[0]
        except struct.error:
            size_of_headers = 0

    section_table_off = e_lfanew + 4 + 20 + size_of_opt_header
    section_size = 40
    sections = []

    for i in range(num_sections):
        sh = _read_memory(base + section_table_off + i * section_size, section_size)
        if not sh or len(sh) < 16:
            ida_kernwin.msg(f"Warning: cannot read section header #{i}\n")
            continue
        name = sh[:8].rstrip(b"\x00").decode(errors="ignore")
        try:
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", sh, 8)
        except struct.error:
            ida_kernwin.msg(f"Warning: malformed section header #{i}\n")
            continue
        sections.append((name, raw_ptr, raw_size))

    if not sections:
        ida_kernwin.warning("No section headers found")
        return

    max_end = size_of_headers if size_of_headers > 0 else 0
    for _, ptr, sz in sections:
        if ptr and sz:
            end = ptr + sz
            if end > max_end:
                max_end = end

    if max_end == 0:
        ida_kernwin.warning("Cannot compute output size")
        return

    out = bytearray(max_end)

    # headers
    hdr = _read_memory(base, max_end if size_of_headers == 0 else size_of_headers)
    if hdr:
        out[0 : len(hdr)] = hdr
    else:
        ida_kernwin.msg("Warning: header area not readable; header may be incomplete\n")

    # sections (file offsets)
    for name, raw_ptr, raw_size in sections:
        if not raw_ptr or not raw_size:
            ida_kernwin.msg(
                f"Skip section {name!r} (raw_ptr={raw_ptr} raw_size={raw_size})\n"
            )
            continue
        src = base + raw_ptr
        data = _read_memory(src, raw_size)
        if not data:
            ida_kernwin.msg(f"Warning: section {name!r} unreadable @0x{src:X}\n")
            continue
        ln = min(len(data), raw_size)
        out[raw_ptr : raw_ptr + ln] = data[:ln]
        if ln < raw_size:
            ida_kernwin.msg(f"Partial read for {name!r}: {ln}/{raw_size}\n")

    _dump_file(bytes(out), f"{base:X}_PE_raw.bin")


def _dump_elf(base: int):
    hdr = _read_memory(base, 0x100)
    if not hdr or len(hdr) < 16 or hdr[:4] != b"\x7fELF":
        ida_kernwin.warning(f"Invalid ELF header @0x{base:X}")
        return

    is64 = hdr[4] == 2
    endian = "<" if hdr[5] == 1 else ">"

    try:
        if is64:
            e_phoff = struct.unpack_from(endian + "Q", hdr, 0x20)[0]
            e_phentsize = struct.unpack_from(endian + "H", hdr, 0x36)[0]
            e_phnum = struct.unpack_from(endian + "H", hdr, 0x38)[0]
        else:
            e_phoff = struct.unpack_from(endian + "I", hdr, 0x1C)[0]
            e_phentsize = struct.unpack_from(endian + "H", hdr, 0x2A)[0]
            e_phnum = struct.unpack_from(endian + "H", hdr, 0x2C)[0]
    except struct.error:
        ida_kernwin.warning("Failed to parse ELF headers")
        return

    max_end = 0
    for i in range(e_phnum):
        ph = _read_memory(base + e_phoff + i * e_phentsize, e_phentsize)
        if not ph or len(ph) < e_phentsize:
            continue
        try:
            if is64:
                p_type = struct.unpack_from(endian + "I", ph, 0)[0]
                p_vaddr = struct.unpack_from(endian + "Q", ph, 0x10)[0]
                p_memsz = struct.unpack_from(endian + "Q", ph, 0x28)[0]
            else:
                p_type = struct.unpack_from(endian + "I", ph, 0)[0]
                p_vaddr = struct.unpack_from(endian + "I", ph, 0x08)[0]
                p_memsz = struct.unpack_from(endian + "I", ph, 0x14)[0]
        except struct.error:
            continue
        if p_type == 1 and p_memsz:
            end = p_vaddr + p_memsz
            if end > max_end:
                max_end = end

    if max_end == 0:
        ida_kernwin.warning("No PT_LOAD segments found")
        return

    data = _read_memory(base, max_end)
    if not data:
        ida_kernwin.warning("Failed to read ELF image")
        return
    _dump_file(data, f"{base:X}_ELF.bin")


def _dump_raw(base: int):
    s = ida_kernwin.ask_str("0x1000", 0, "Size (hex)")
    if s is None:
        return
    try:
        size = int(s, 16)
    except Exception:
        ida_kernwin.warning("Invalid hex size")
        return
    if size <= 0:
        ida_kernwin.warning("Size must be positive")
        return
    data = _read_memory(base, size)
    if not data:
        ida_kernwin.warning("Failed to read raw bytes")
        return
    _dump_file(data, f"{base:X}_{size:X}_RAW.bin")


class MemDumpX_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Dump memory to file (PE raw image supported)"
    wanted_name = "MemDumpX"
    wanted_hotkey = "Ctrl-Alt-D"

    def init(self):
        print(f"MemDumpX({PLUGIN_VERSION}) loaded.")
        return ida_idaapi.PLUGIN_OK

    def term(self):
        pass

    def run(self, _arg):
        ea_default = ida_kernwin.get_screen_ea()
        addr = ida_kernwin.ask_str(f"0x{ea_default:X}", 0, "Start address (hex)")
        if addr is None:
            return
        try:
            start = int(addr, 16)
        except Exception:
            ida_kernwin.warning("Invalid address")
            return

        mode = ida_kernwin.ask_buttons("PE", "ELF", "RAW", 0, "Choose dump mode")
        if mode == 1:
            _dump_pe(start)
        elif mode == 0:
            _dump_elf(start)
        elif mode == -1:
            _dump_raw(start)


def PLUGIN_ENTRY():
    return MemDumpX_t()
