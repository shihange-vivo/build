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

"""Bidirectional validation between an app-package manifest and the ELFs
(Phase 2, C30 §6.2).

The manifest must describe exactly what the final ELFs declare:
  - every manifest image exists and its build-id matches the artifact;
  - every ELF DT_NEEDED has exactly one manifest binding and no ghost
    dependency remains;
  - private SONAMEs are unique and do not collide with reserved system names;
  - the root carries no SONAME, private DSOs must;
  - every system edge names a declared system SONAME;
  - RPATH/RUNPATH/TEXTREL/PT_TLS/PT_INTERP are absent everywhere.

Usage: check_blueos_app_package.py --manifest <json> \
          --root <elf> [--private <soname>,<elf> ...] \
          [--llvm-readelf <path>]
"""

import argparse
import json
import os
import re
import subprocess
import sys


class CheckError(Exception):
    pass


def _run(readelf, *args):
    try:
        proc = subprocess.run([readelf, *args], capture_output=True, text=True,
                              check=False)
    except FileNotFoundError:
        raise CheckError(f"llvm-readelf not found: {readelf!r}") from None
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise CheckError(f"`{' '.join([readelf, *args])}` failed: {detail}")
    return proc.stdout


def _dynamic_tags(readelf, elf):
    text = _run(readelf, "-d", elf)
    tags = {}
    for match in re.finditer(r"\((NEEDED|SONAME|RPATH|RUNPATH|TEXTREL)\)\s+(.*)",
                             text):
        name, tail = match.group(1), match.group(2).strip()
        bracketed = re.search(r"\[([^\]]+)\]", tail)
        tags.setdefault(name, []).append(bracketed.group(1) if bracketed
                                         else tail)
    if re.search(r"\(TEXTREL\)", text):
        tags.setdefault("TEXTREL", ["present"])
    return tags


def _build_id(readelf, elf):
    text = _run(readelf, "-n", elf)
    match = re.search(r"Build ID:\s+([0-9A-Fa-f]+)", text)
    return match.group(1) if match else None


def _program_header_types(readelf, elf):
    text = _run(readelf, "-l", elf)
    return set(re.findall(r"^\s{2}(\S+)\s+0x[0-9A-Fa-f]+", text, re.M))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--private", action="append", default=[],
                        help="soname,elf pair")
    parser.add_argument("--llvm-readelf",
                        default=os.environ.get("LLVM_READELF", "llvm-readelf"))
    args = parser.parse_args()

    with open(args.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)

    system_sonames = set(manifest.get("system_sonames", []))
    private_entries = manifest["private_images"]
    private_sonames = [entry["soname"] for entry in private_entries]
    if len(private_sonames) != len(set(private_sonames)):
        raise CheckError("manifest: duplicate private SONAME")
    for soname in private_sonames:
        if soname in system_sonames:
            raise CheckError(f"manifest: private SONAME {soname} collides "
                             f"with a reserved system SONAME")

    # Pair manifest entries with their real ELFs.
    elf_by_soname = {}
    for spec in args.private:
        soname, elf = spec.split(",", 1)
        elf_by_soname[soname] = elf
    if not os.path.isfile(args.root):
        raise CheckError(f"root artifact missing: {args.root}")

    def check_image(entry, elf, role):
        actual_tags = _dynamic_tags(args.llvm_readelf, elf)
        actual_build_id = _build_id(args.llvm_readelf, elf)
        if actual_build_id != entry["build_id"]:
            raise CheckError(
                f"{entry['path']}: build-id mismatch (manifest "
                f"{entry['build_id']}, ELF {actual_build_id})")
        actual_needed = actual_tags.get("NEEDED", [])
        declared = [edge["soname"] for edge in entry["needed"]]
        if sorted(actual_needed) != sorted(declared):
            raise CheckError(
                f"{entry['path']}: DT_NEEDED mismatch (ELF {actual_needed}, "
                f"manifest {declared})")
        for name in ("RPATH", "RUNPATH", "TEXTREL"):
            if actual_tags.get(name):
                raise CheckError(f"{entry['path']}: {name} present")
        phdrs = _program_header_types(args.llvm_readelf, elf)
        for bad in ("TLS", "INTERP"):
            if bad in phdrs:
                raise CheckError(f"{entry['path']}: PT_{bad} present")
        actual_soname = actual_tags.get("SONAME", [])
        if role == "root" and actual_soname:
            raise CheckError(f"{entry['path']}: root must not carry a SONAME")
        if role == "private_dso" and sorted(actual_soname) != [entry["soname"]]:
            raise CheckError(
                f"{entry['path']}: SONAME mismatch (ELF {actual_soname}, "
                f"manifest {entry['soname']})")
        # Every edge resolves to a private image or a declared system SONAME.
        for edge in entry["needed"]:
            if edge["source"] == "package" and edge["soname"] not in elf_by_soname:
                raise CheckError(
                    f"{entry['path']}: package edge {edge['soname']} has no "
                    f"private image")
            if edge["source"] == "system" and edge["soname"] not in system_sonames:
                raise CheckError(
                    f"{entry['path']}: system edge {edge['soname']} is not a "
                    f"declared system dependency")

    check_image(manifest["root"], args.root, "root")
    for entry in private_entries:
        if entry["soname"] not in elf_by_soname:
            raise CheckError(f"manifest: {entry['soname']} has no ELF on the "
                             f"command line")
        check_image(entry, elf_by_soname[entry["soname"]], "private_dso")

    print(f"PASS package: {manifest['package_id']} "
          f"({len(private_entries) + 1} images)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CheckError, json.JSONDecodeError, OSError) as error:
        print(f"FAIL package: {error}", file=sys.stderr)
        sys.exit(1)
