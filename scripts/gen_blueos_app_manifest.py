#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

"""Generate an application-package manifest from the final ELF artifacts.

The manifest freezes the build-time verified dependency closure of a dynamic
application package (Phase 2, C30 §6): for the root and each private DSO it
records the SONAME, build-id, ELF identity fields and the exact DT_NEEDED
list, resolving every needed SONAME either to a package-private image or to a
declared system dependency. It reads only the final linked ELFs — never GN
arguments — via llvm-readelf (override with LLVM_READELF).

Usage:
  gen_blueos_app_manifest.py --package-id multi --profile <id> \
      --root <elf> [--private <soname>,<vfs-path>,<elf> ...] \
      [--system-soname libc.so.1] --out manifest.json
"""

import argparse
import json
import os
import re
import subprocess
import sys


class ManifestError(Exception):
    pass


def _run(readelf, *args):
    try:
        proc = subprocess.run([readelf, *args], capture_output=True, text=True,
                              check=False)
    except FileNotFoundError:
        raise ManifestError(f"llvm-readelf not found: {readelf!r}") from None
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise ManifestError(f"`{' '.join([readelf, *args])}` failed: {detail}")
    return proc.stdout


def _parse_header(text):
    class_ = re.search(r"Class:\s+(\S+)", text)
    machine = re.search(r"Machine:\s+(\S+)", text)
    elftype = re.search(r"Type:\s+(\S+)", text)
    flags = re.search(r"Flags:\s+(0x[0-9A-Fa-f]+)", text)
    if not (class_ and machine and elftype and flags):
        raise ManifestError("unable to parse ELF header")
    return {
        "class": class_.group(1),
        "machine": machine.group(1),
        "type": elftype.group(1),
        "flags": flags.group(1),
    }


def _dynamic_tags(text):
    """Map tag name -> list of values from `llvm-readelf -d`.

    `llvm-readelf` prints a description column, e.g.
    `0x00000001 (NEEDED) Shared library: [libc.so.1]`; the bracketed name is
    the value, with a fallback to the raw tail for flags like TEXTREL.
    """
    tags = {}
    for match in re.finditer(r"\((NEEDED|SONAME|RPATH|RUNPATH|TEXTREL)\)\s+(.*)",
                             text):
        name, tail = match.group(1), match.group(2).strip()
        bracketed = re.search(r"\[([^\]]+)\]", tail)
        tags.setdefault(name, []).append(bracketed.group(1) if bracketed
                                         else tail)
    # TEXTREL prints as `(TEXTREL) 0x...` or a flag line; normalize either.
    if re.search(r"\(TEXTREL\)", text):
        tags.setdefault("TEXTREL", ["present"])
    return tags


def _build_id(readelf, elf):
    text = _run(readelf, "-n", elf)
    match = re.search(r"Build ID:\s+([0-9A-Fa-f]+)", text)
    if not match:
        raise ManifestError(f"{elf}: no build-id (the artifact link profile "
                            f"must pass --build-id)")
    return match.group(1)


def _program_header_types(readelf, elf):
    text = _run(readelf, "-l", elf)
    return set(re.findall(r"^\s{2}(\S+)\s+0x[0-9A-Fa-f]+", text, re.M))


def _relocations(readelf, elf):
    text = _run(readelf, "-r", elf)
    return sorted(set(re.findall(r"\b(R_[A-Z0-9_]+)\b", text)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-id", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--root", required=True, help="path,elf pair")
    parser.add_argument("--private", action="append", default=[],
                        help="soname,vfs_path,elf triple")
    parser.add_argument("--system-soname", action="append", default=[],
                        help="a system-provided SONAME (repeatable)")
    parser.add_argument("--out", required=True)
    parser.add_argument("--layout", default=None,
                        help="optional output: artifact->vfs-path layout JSON")
    parser.add_argument("--llvm-readelf",
                        default=os.environ.get("LLVM_READELF", "llvm-readelf"))
    args = parser.parse_args()

    root_path, root_elf = args.root.split(",", 1)
    if not os.path.isfile(root_elf):
        raise ManifestError(f"root artifact missing: {root_elf}")

    privates = []
    for spec in args.private:
        soname, vfs_path, elf = spec.split(",", 2)
        if not os.path.isfile(elf):
            raise ManifestError(f"private artifact missing: {elf}")
        privates.append({"soname": soname, "path": vfs_path, "elf": elf})

    # Private SONAMEs must be unique in the package and must not collide with
    # the reserved system SONAMEs (C30 §6.2, rejected at generation time).
    seen = set()
    for entry in privates:
        if entry["soname"] in seen:
            raise ManifestError(f"duplicate private SONAME {entry['soname']}")
        if entry["soname"] in args.system_soname:
            raise ManifestError(
                f"private SONAME {entry['soname']} collides with a reserved "
                f"system SONAME")
        seen.add(entry["soname"])
    private_sonames = {entry["soname"] for entry in privates}

    def image_entry(path, soname, elf, role):
        header = _parse_header(_run(args.llvm_readelf, "-h", elf))
        tags = _dynamic_tags(_run(args.llvm_readelf, "-d", elf))
        phdrs = _program_header_types(args.llvm_readelf, elf)
        needed = []
        for needed_soname in tags.get("NEEDED", []):
            source = ("package" if needed_soname in private_sonames
                      else "system")
            if source == "system" and needed_soname not in args.system_soname:
                raise ManifestError(
                    f"{elf}: DT_NEEDED {needed_soname} is neither a package "
                    f"private image nor a declared system dependency")
            needed.append({"soname": needed_soname, "source": source})
        return {
            "role": role,
            "path": path,
            "soname": soname,
            "build_id": _build_id(args.llvm_readelf, elf),
            "identity": header,
            "needed": needed,
            "phdr_types": sorted(phdrs),
            "relocations": _relocations(args.llvm_readelf, elf),
        }

    if root_path in [entry["path"] for entry in privates] + []:
        raise ManifestError(f"root path {root_path} is not unique")

    root_tags = _dynamic_tags(_run(args.llvm_readelf, "-d", root_elf))
    if root_tags.get("SONAME"):
        raise ManifestError(f"{root_elf}: root must not carry a SONAME")
    root_entry = image_entry(root_path, None, root_elf, "root")
    private_entries = [
        image_entry(entry["path"], entry["soname"], entry["elf"], "private_dso")
        for entry in privates
    ]
    for entry in private_entries:
        if entry["soname"] is None:
            raise ManifestError(f"{entry['path']}: private DSO must carry a "
                                f"SONAME")

    manifest = {
        "package_id": args.package_id,
        "profile": args.profile,
        "root": root_entry,
        "private_images": private_entries,
        "system_sonames": args.system_soname,
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"gen_blueos_app_manifest: wrote {args.out}")

    if args.layout:
        layout = [
            {"vfs_path": root_path, "artifact": root_elf},
        ]
        for entry, image in zip(privates, private_entries):
            layout.append({"vfs_path": image["path"], "artifact": entry["elf"]})
        with open(args.layout, "w", encoding="utf-8") as handle:
            json.dump(layout, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"gen_blueos_app_manifest: wrote {args.layout}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ManifestError as error:
        print(f"FAIL manifest: {error}", file=sys.stderr)
        sys.exit(1)
