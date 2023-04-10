#!/usr/bin/env python3

# get GoReSym from https://github.com/mandiant/GoReSym/releases
GoReSym_PATH = "./GoReSym_lin"

import hashlib
import json
import subprocess
import sys

import capstone
import lief


def get_json(filename):
    try:
        output = subprocess.run(
            [GoReSym_PATH, "-d", filename], check=True, stdout=subprocess.PIPE
        ).stdout
        jsondata = json.loads(output)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        jsondata = None
    return jsondata


def sha256_data(data: bytes) -> str:
    m = hashlib.sha256()
    m.update(data)
    return m.hexdigest()


def hash_func(data: bytes) -> (str, int):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    first_bytes = b""
    for i in md.disasm(data, 0):
        first_bytes += bytes([data[i.address]])
    first_bytes = bytes([data[x.address] for x in md.disasm(data, 0)])
    #    print(first_bytes)
    return (sha256_data(first_bytes)[:32], len(first_bytes))


def process(filename: str) -> None:
    #    print(f"Checking {filename}...")
    with open(filename, mode="rb") as f:
        filedata = f.read()
    filehash = sha256_data(filedata)
    jsondata = get_json(filename)
    if jsondata:
        binary = lief.parse(filedata)
        if binary:
            # check arch, hash_func assumes x86_64
            assert binary.header.machine_type == lief.ELF.ARCH.x86_64
            for listname in ("UserFunctions", "StdFunctions"):
                for gofunction in jsondata[listname]:
                    funcname = gofunction["FullName"]
                    start = gofunction["Start"]
                    start_offset = binary.virtual_address_to_offset(start)
                    end = gofunction["End"]
                    end_offset = binary.virtual_address_to_offset(end)
                    funchash, processed_len = hash_func(
                        filedata[start_offset:end_offset]
                    )
                    #                    funclen = end_offset - start_offset
                    print(f"{funchash} {filehash} {processed_len} {funcname}")
        else:
            print(f"ERROR parsing {filename}!", file=sys.stderr)
    else:
        print(f"ERROR getting Go symbols from {filename}!", file=sys.stderr)


if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} filename...")
else:
    for filename in sys.argv[1:]:
        process(filename)
