#!/usr/bin/env python3
"""Compare the native ABI symbol with each BPF read-only marker at build time."""

import argparse
import struct
import subprocess
from pathlib import Path


class Elf:
    def __init__(self, data):
        if data[:6] != b"\x7fELF\x02\x01":
            raise ValueError("expected a little-endian ELF64 object")
        self.data = data
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        offset, size, count, names_index = header[6], header[11], header[12], header[13]
        self.sections = [
            struct.unpack_from("<IIQQQQIIQQ", data, offset + index * size)
            for index in range(count)
        ]
        names = self.contents(self.sections[names_index])
        self.named = {self.string(names, section[0]): section for section in self.sections}

    @staticmethod
    def string(data, offset):
        return data[offset:data.index(b"\0", offset)].decode("ascii")

    def contents(self, section):
        return self.data[section[4]:section[4] + section[5]]

    def native_identity(self):
        symbols = self.named[".symtab"]
        names = self.contents(self.sections[symbols[6]])
        for offset in range(0, symbols[5], symbols[9]):
            name, _, _, section_index, value, size = struct.unpack_from(
                "<IBBHQQ", self.data, symbols[4] + offset
            )
            if self.string(names, name) == "llb_expected_abi":
                return self.contents(self.sections[section_index])[value:value + size]
        raise ValueError("missing llb_expected_abi symbol")


def validate_identity(data):
    if not data.endswith(b"\0") or b"\0" in data[:-1]:
        raise ValueError("malformed ABI identity")
    return data.decode("ascii").rstrip("\0")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--bpf", nargs="+", required=True)
    args = parser.parse_args()
    native_path = Path(args.native)
    expected = Elf(native_path.read_bytes()).native_identity()
    print("NATIVE", validate_identity(expected))
    member = subprocess.check_output(["ar", "p", args.archive, native_path.name])
    if Elf(member).native_identity() != expected:
        raise SystemExit("ABI identity mismatch: native archive member")
    for name in args.bpf:
        elf = Elf(Path(name).read_bytes())
        actual = elf.contents(elf.named[".rodata.llbabi"])
        print("BPF", name, validate_identity(actual))
        if actual != expected:
            raise SystemExit("ABI identity mismatch: " + name)
    print("PASS: native object/archive and every built BPF ABI identity agree")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, struct.error) as error:
        raise SystemExit("ABI identity inspection failed: " + str(error)) from error
