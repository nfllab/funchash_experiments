#!/usr/bin/env python3

import re
import sys

big_dict = {}


def add_to_dict(filename):
    with open(filename) as f:
        for line in f:
            line = line.rstrip()
            mo = re.fullmatch(r"([0-9a-f]{32}) ([0-9a-f]{64}) (\d+) (.+)", line)
            if mo:
                funchash = mo.group(1)
                filehash = mo.group(2)
                funclen = int(mo.group(3))
                funcname = mo.group(4)
                d = dict(
                    funchash=funchash,
                    filehash=filehash,
                    funclen=funclen,
                    funcname=funcname,
                )
                dlist = big_dict.get(funchash, [])
                dlist.append(d)
                big_dict[funchash] = dlist
            else:
                print(f"ERROR parsing line: {line}", file=sys.stderr)
                exit(1)


def check_dict():
    for key, value in big_dict.items():
        if len(value) > 1:
            print(f"{key} was found multiple times:")
            for d in value:
                print(f'{d["filehash"]} {d["funclen"]} {d["funcname"]}')


if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} gofunchash_output.txt...")
else:
    for filename in sys.argv[1:]:
        add_to_dict(filename)
    check_dict()
