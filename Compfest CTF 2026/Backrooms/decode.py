#!/usr/bin/env python3
"""Recover the flag rendered by rev_backrooms.exe."""

SOURCE = bytes.fromhex(
    "4abfe017ba9a051b4acaabdc34ffa430e0838bd472750b0f60"
    "babb7b13d13e00e82be199a9cba3aa95b5df39d4e31b74ad409"
    "bf66e1effe1645a856f00"
)

SEED = 0xA3F1924D
ADD = 0xDB

GLYPHS = {
    ".##/#../#../.##": "C",
    "###/#.#/#.#/###": "O",
    "##./###/#.#/#.#": "M",
    "###/#.#/###/#..": "P",
    "###/#../##./#..": "F",
    "###/##./#../###": "E",
    ".##/##./..#/##.": "S",
    "###/.#./.#./.#.": "T",
    "##./.#./.#./###": "1",
    ".##/###/#.#/###": "8",
    "..#/##./.#./..#": "{",
    "#.#/###/#.#/#.#": "H",
    ".../.../.../###": "_",
    "###/.#./.#./###": "I",
    "##./.##/#../###": "2",
    ".#./#.#/#.#/.#.": "0",
    "#.#/#.#/.#./.#.": "Y",
    "###/#.#/###/#.#": "A",
    "###/#.#/##./#.#": "R",
    "###/#.#/#.#/###": "O",
    "#../#../#../###": "L",
    "##./#.#/#.#/##.": "D",
    "#../.##/.#./#..": "}",
}


def ror8(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (8 - shift))) & 0xFF


def transform(source: bytes) -> bytes:
    seed = SEED
    add = ADD
    output = []

    for index, byte in enumerate(source[:60]):
        seed = (seed * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        value = (byte + add) & 0xFF
        value = ror8(value, index % 7 + 1)
        value ^= (seed >> 16) & 0xFF
        output.append(value)
        add = (add + 0xF3) & 0xFF

    return bytes(output)


def glyph_pattern(rows: list[list[int]], glyph: int) -> str:
    return "/".join(
        "".join("#" if rows[row][glyph * 4 + column] else "." for column in range(3))
        for row in range(4)
    )


def main() -> None:
    transformed = transform(SOURCE)
    bits = [(byte >> bit) & 1 for byte in transformed for bit in range(7, -1, -1)]
    rows = [bits[row * 120 : (row + 1) * 120] for row in range(4)]

    print(f"transformed: {transformed.hex()}")
    print("canvas:")
    for row in rows:
        print("".join("#" if bit else "." for bit in row))

    decoded = []
    for glyph in range(30):
        pattern = glyph_pattern(rows, glyph)
        character = GLYPHS.get(pattern, "?")
        decoded.append(character)
        print(f"glyph {glyph:02}: {pattern}")

    print("decoded token: <omitted>")


if __name__ == "__main__":
    main()
