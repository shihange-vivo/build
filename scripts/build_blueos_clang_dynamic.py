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

"""Build a BlueOS C/C++ PIE or DSO with Clang and LLD.

The ordinary GN C/C++ linker tool is also used for static kernel artifacts and
is intentionally board-owned.  Dynamic applications have a different link
contract, so this small driver keeps their Clang/LLD flags local and explicit.
It compiles every source independently (``clang`` for C, ``clang++`` for C++)
and performs one final ``clang++ -fuse-ld=lld`` link without a hosted runtime.
"""

import argparse
import os
import subprocess
import tempfile


def _compiler(source):
    extension = os.path.splitext(source)[1].lower()
    return "clang" if extension == ".c" else "clang++"


def _target_flags(target):
    if not target.startswith("thumb"):
        return []
    float_abi = "hard" if target.endswith("eabihf") else "soft"
    return ["-mthumb", f"-mfloat-abi={float_abi}"]


def _compile(source, output, target, pic_flag):
    command = [
        _compiler(source),
        f"--target={target}",
        pic_flag,
        "-Oz",
        "-ffreestanding",
        "-ffunction-sections",
        "-fdata-sections",
        "-fshort-enums",
        "-fsigned-char",
        "-fvisibility=hidden",
        "-Wall",
        "-Wextra",
        "-Werror",
    ]
    command += _target_flags(target)
    if target.startswith("thumb"):
        # LLD's Thumbv7 PIC tail-call thunk enters a local PLT entry through
        # an even address. Cortex-M has no ARM state, so keep imported calls
        # as BL-to-local-PLT sequences until that linker behavior is corrected.
        command += ["-fno-optimize-sibling-calls"]
    if _compiler(source) == "clang++":
        command += [
            "-std=c++17",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-threadsafe-statics",
            "-fno-use-cxa-atexit",
        ]
    command += ["-c", source, "-o", output]
    subprocess.run(command, check=True)


def _link(args, objects):
    command = [
        "clang++",
        f"--target={args.target}",
        "-fuse-ld=lld",
        "-nostdlib",
        "-nostartfiles",
        "-nodefaultlibs",
        "-Wl,--gc-sections",
        "-Wl,--no-undefined",
        "-Wl,--no-as-needed",
        "-Wl,-Bdynamic",
        "-Wl,--hash-style=both",
        "-Wl,--build-id=sha1",
        "-Wl,-z,now",
        "-Wl,-z,relro",
        "-Wl,-z,noexecstack",
        "-Wl,-z,text",
        "-Wl,-z,max-page-size=4096",
    ]
    command += _target_flags(args.target)
    if args.target.startswith("thumb"):
        # Keep any linker-generated Thumb thunk position-independent.
        command += ["-Wl,--pic-veneer"]
    if args.kind == "pie":
        command += [
            "-Wl,-pie",
            "-Wl,--no-dynamic-linker",
            "-Wl,-e,_start",
            "-Wl,--export-dynamic-symbol=main",
        ]
    else:
        command += ["-Wl,-shared", f"-Wl,-soname,{args.soname}"]
    command += objects
    if args.start_object:
        command += [
            "-Wl,--whole-archive",
            args.start_object,
            "-Wl,--no-whole-archive",
        ]
    command += args.library
    command += ["-o", args.output]
    subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("pie", "dso"), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--library", action="append", default=[])
    parser.add_argument("--start-object")
    parser.add_argument("--soname")
    args = parser.parse_args()

    if args.kind == "pie" and not args.start_object:
        parser.error("PIE requires --start-object")
    if args.kind == "dso" and not args.soname:
        parser.error("DSO requires --soname")

    output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    pic_flag = "-fPIE" if args.kind == "pie" else "-fPIC"
    args.output = output
    if args.start_object:
        args.start_object = os.path.abspath(args.start_object)
    args.library = [os.path.abspath(path) for path in args.library]
    with tempfile.TemporaryDirectory(prefix="blueos-clang-",
                                     dir=os.path.dirname(output)) as object_dir:
        objects = []
        for index, source in enumerate(args.source):
            object_path = os.path.join(object_dir, f"{index}.o")
            _compile(os.path.abspath(source), object_path, args.target,
                     pic_flag)
            objects.append(object_path)
        _link(args, objects)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
