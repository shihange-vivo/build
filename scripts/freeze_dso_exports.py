#!/usr/bin/env python3
# Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Freeze a DSO's dynamic symbol table to an export manifest (, ).

rustc always generates its own version script for cdylibs, and rust-lld
unions multiple version scripts, so a user-supplied script cannot hide the
symbols rustc lists at link time. The freeze is therefore applied after the
link by rewriting `.dynsym` directly: every dynamic symbol with GLOBAL/WEAK
binding whose name is not in the manifest gets STB_LOCAL. The patch touches
only the `st_info` bind bits — names, indices, hash tables and relocations
all stay byte-identical, so the loader's name-based resolution (internal
PLT/GOT relocations included) keeps working, while the dynamic symbol table
equals the manifest exactly (`check_blueos_elf.py --exports` verifies this)
and app links against the DSO can no longer resolve off-manifest names.

Usage: freeze_dso_exports.py --elf <path> --exports <path> [--out <path>]

The frozen output is written to `--out` (default: `<elf>.frozen`). The
original artifact is left untouched: app links consume the unfrozen DSO,
while the kernel embeds the frozen one — strictly validating consumers
(rust-lld) reject a `.dynsym` whose hash tables still cover names that
were localized in place, so re-freezing the shared artifact must not
rewrite what other links read.
"""

import argparse
import struct
import sys

# ELF little-endian constants.
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
SHT_DYNSYM = 11
SHT_STRTAB = 3
STB_GLOBAL = 1
STB_WEAK = 2
STB_LOCAL = 0


def parse_manifest(path):
    """Extract the symbol names from the `global:` block of the script."""
    names = set()
    in_global = False
    for raw in open(path, encoding="utf-8"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "{":
            continue
        if line == "global:":
            in_global = True
            continue
        if line == "local:":
            in_global = False
            continue
        if in_global:
            name = line.rstrip(";").strip()
            if name and name != "*":
                names.add(name)
    return names


def elf_layout(data):
    """Return class-specific section/symbol layouts for a little-endian ELF."""
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[5] != ELFDATA2LSB:
        raise ValueError("only little-endian ELF is supported")
    if data[4] == ELFCLASS32:
        return {
            "shoff": struct.unpack_from("<I", data, 0x20)[0],
            "shentsize": struct.unpack_from("<H", data, 0x2E)[0],
            "shnum": struct.unpack_from("<H", data, 0x30)[0],
            "shstrndx": struct.unpack_from("<H", data, 0x32)[0],
            "section_format": "<IIIIIIIIII",
            "sh_info_offset": 28,
            "symbol_info_offset": 12,
        }
    if data[4] == ELFCLASS64:
        return {
            "shoff": struct.unpack_from("<Q", data, 0x28)[0],
            "shentsize": struct.unpack_from("<H", data, 0x3A)[0],
            "shnum": struct.unpack_from("<H", data, 0x3C)[0],
            "shstrndx": struct.unpack_from("<H", data, 0x3E)[0],
            "section_format": "<IIQQQQIIQQ",
            "sh_info_offset": 44,
            "symbol_info_offset": 4,
        }
    raise ValueError("unsupported ELF class")


def section_table(data):
    """Parse the section header table; return (sections, shstrndx, layout)."""
    layout = elf_layout(data)
    e_shoff = layout["shoff"]
    e_shentsize = layout["shentsize"]
    e_shnum = layout["shnum"]
    e_shstrndx = layout["shstrndx"]
    expected_size = struct.calcsize(layout["section_format"])
    if e_shentsize < expected_size or e_shstrndx >= e_shnum:
        raise ValueError("invalid ELF section table geometry")
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link,
         _sh_info, _sh_addralign, sh_entsize) = struct.unpack_from(
            layout["section_format"], data, off)
        sections.append({
            "name_off": sh_name,
            "type": sh_type,
            "header_off": off,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "entsize": sh_entsize,
        })
    return sections, e_shstrndx, layout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", required=True)
    parser.add_argument("--exports", required=True)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    manifest = parse_manifest(args.exports)
    if not manifest:
        print("freeze_dso_exports: empty manifest, refusing to localize all",
              file=sys.stderr)
        return 1

    with open(args.elf, "rb") as handle:
        data = bytearray(handle.read())

    try:
        sections, shstrndx, layout = section_table(data)
    except (IndexError, struct.error, ValueError) as error:
        print(f"freeze_dso_exports: {error}", file=sys.stderr)
        return 1
    strtab_section = sections[shstrndx]
    shstr = bytes(data[strtab_section["offset"]:
                       strtab_section["offset"] + strtab_section["size"]])

    def section_name(section):
        end = shstr.find(b"\x00", section["name_off"])
        return shstr[section["name_off"]:end].decode("ascii", "replace")

    dynsym = None
    linked_strtab = None
    for section in sections:
        if section["type"] == SHT_DYNSYM:
            dynsym = section
            linked_strtab = section["link"]
    if dynsym is None or linked_strtab is None:
        print("freeze_dso_exports: no .dynsym section", file=sys.stderr)
        return 1
    strtab = sections[linked_strtab]
    strtab_bytes = bytes(data[strtab["offset"]:strtab["offset"] + strtab["size"]])

    def symbol_name(st_name):
        if st_name == 0 or st_name >= len(strtab_bytes):
            return ""
        end = strtab_bytes.find(b"\x00", st_name)
        return strtab_bytes[st_name:end].decode("ascii", "replace")

    # Two-way sync: manifest names become GLOBAL, everything else LOCAL.
    # Re-freezing an already frozen DSO must therefore restore bindings for
    # manifest symbols that a later ABI diff added back.
    changed = 0
    first_global = 0
    for off in range(dynsym["offset"],
                     dynsym["offset"] + dynsym["size"], dynsym["entsize"]):
        st_name = struct.unpack_from("<I", data, off)[0]
        st_info_offset = off + layout["symbol_info_offset"]
        st_info = data[st_info_offset]
        name = symbol_name(st_name)
        if not name or "@" in name:
            continue
        if name in manifest:
            binding = STB_GLOBAL
        else:
            binding = STB_LOCAL
        if (st_info >> 4) != binding:
            data[st_info_offset] = (st_info & 0x0F) | (binding << 4)
            changed += 1
        if binding != STB_LOCAL and first_global == 0:
            first_global = (off - dynsym["offset"]) // dynsym["entsize"]

    # Keep sh_info consistent: it records the index of the first non-local
    # symbol. (The GNU hash table keeps covering the localized names — the
    # loader's name-based lookups rely on that for the DSO's internal PLT/GOT
    # relocations; only the binding changed.)
    if first_global:
        struct.pack_into("<I", data,
                         dynsym["header_off"] + layout["sh_info_offset"],
                         first_global)

    # Write via a sibling temp file and rename so parallel consumers of the
    # output (e.g. the kernel seed) never observe a partially written ELF.
    import os
    import tempfile
    target = args.out if args.out else args.elf + ".frozen"
    dirname = os.path.dirname(target)
    fd, tmp = tempfile.mkstemp(dir=dirname, prefix=".freeze-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print("freeze_dso_exports: updated {} bindings".format(changed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
