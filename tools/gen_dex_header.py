#!/usr/bin/env python3
"""
gen_dex_header.py — đọc 1 file .dex đã compile sẵn, sinh ra file .h chứa
mảng byte C++ tương ứng (kHookStubDex[] + kHookStubDexLen), để nhúng
thẳng vào main.cpp lúc build, không cần ghi/đọc file .dex ra đĩa lúc app
chạy thật (InMemoryDexClassLoader nạp thẳng từ bytes trong bộ nhớ).

Cách dùng: python3 gen_dex_header.py <input.dex> <output.h>
"""
import sys


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input.dex> <output.h>", file=sys.stderr)
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    with open(input_path, "rb") as f:
        data = f.read()

    with open(output_path, "w") as f:
        f.write("// AUTO-GENERATED — không sửa tay, sinh ra từ HookStub.dex\n")
        f.write("// bởi tools/gen_dex_header.py lúc build.\n")
        f.write("#pragma once\n\n")
        f.write(f"static const unsigned char kHookStubDex[] = {{\n")

        # Viết theo dòng 16 byte/dòng cho dễ đọc, dù không bắt buộc.
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_values = ", ".join(f"0x{b:02x}" for b in chunk)
            f.write(f"    {hex_values},\n")

        f.write("};\n\n")
        f.write(f"static const unsigned int kHookStubDexLen = {len(data)};\n")

    print(f"Generated {output_path}: {len(data)} bytes embedded")


if __name__ == "__main__":
    main()
