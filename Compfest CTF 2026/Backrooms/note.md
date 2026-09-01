# Backrooms — Compfest CTF 2026

**Category:** Reverse engineering

**Flag:** `COMPFEST18{HE_IS_20_YEARS_OLD}`

## Files

The original challenge executable and its runtime assets are included beside this writeup:

- `rev_backrooms.exe`
- `assets/backrooms/audio.mp3`
- `assets/backrooms/BackRoomsCarpet.png`
- `assets/backrooms/Backroosm.bin`
- `assets/backrooms/Backroosm.gltf`
- `assets/backrooms/the_backrooms_wallpaper__seamless__by_dalay_lamma_df1ci3n-fullview.jpg`
- `decode.py` — a small Python reproducer for the decoding steps below

The spelling `Backroosm.bin` is preserved from the supplied archive.

## Idea

This is a graphical challenge rather than a normal flag checker. The executable starts a Backrooms scene and draws a pattern of cubes. The flag is encoded in that pattern, so searching the executable for `COMPFEST` does not reveal the answer directly.

The useful path is:

1. Find the initialization routine that prepares the cube pattern.
2. Recover the 60-byte transformation loop.
3. Apply the transformed bytes as a 4×120 bitmap.
4. Treat every four columns as a 3-column glyph followed by a blank separator.
5. Read the resulting 30 glyphs as the flag.

The music and the other files are scene assets; they are not needed to recover the flag.

## Static analysis

The file is a 64-bit Windows PE executable. Its image base is `0x140000000`. The relevant routine is in the large code section around RVA `0x5290` (VA `0x140005290`). Near the start of the routine, the program initializes three values and a pointer to the embedded data:

```asm
mov edx, 0xa3f1924d       ; 32-bit PRNG state
mov r8d, 1                ; loop counter, used as index + 1
mov r9b, 0xdb             ; byte-wise additive state
lea r10, [rip + ...]      ; embedded byte array
```

The `lea` resolves to VA `0x142f3f978`, which corresponds to file offset `0x2f3e978` in this PE. The bytes there begin with:

```text
4abfe017ba9a051b4acaabdc34ffa430e0838bd472750b0f60
babb7b13d13e00e82be199a9cba3aa95b5df39d4e31b74ad409
bf66e1effe1645a856f00
```

The loop runs 60 times. The final `00` byte is padding and is not consumed by the loop.

## Recovering the byte transformation

The assembly updates the state before processing each source byte. It then adds the current `add` value, rotates right by a position-dependent amount, XORs one PRNG byte, and advances the additive state:

```python
seed = (seed * 0x41C64E6D + 0x3039) & 0xffffffff
value = (source[i] + add) & 0xff
value = ror8(value, i % 7 + 1)
value ^= (seed >> 16) & 0xff
add = (add + 0xF3) & 0xff
```

In pseudocode, the complete loop is:

```python
seed = 0xA3F1924D
add = 0xDB
decoded = []

for i, byte in enumerate(source[:60]):
    seed = (seed * 0x41C64E6D + 0x3039) & 0xffffffff
    x = (byte + add) & 0xff
    shift = i % 7 + 1
    x = ((x >> shift) | (x << (8 - shift))) & 0xff
    x ^= (seed >> 16) & 0xff
    decoded.append(x)
    add = (add + 0xF3) & 0xff
```

The resulting 60 bytes are:

```text
6eceee6ec62ae0e60c40aeee60e8c88aea8cc44ecec04c06a0acaac0a8a68aaec8244a4a804208a048ec20a8a46ea88ec4ee2aeeecee4e4eaaceeec8
```

## Reconstructing the bitmap

After transforming a byte, the executable stores its bits separately, most-significant bit first. Sixty bytes therefore become 480 one-byte bit values. The next part of the routine treats them as four rows of 120 columns:

```python
bits = [(byte >> bit) & 1 for byte in decoded for bit in range(7, -1, -1)]
rows = [bits[row * 120 : (row + 1) * 120] for row in range(4)]
```

The rendered rows are:

```text
.##.###.##..###.###.###..##.###.##...##...#.#.#.###.....###..##.....##...#......#.#.###.###.###..##.....###.#...##..#...
#...#.#.###.#.#.#...##..##...#...#..###.##..###.##.......#..##.......##.#.#.....#.#.##..#.#.#.#.##......#.#.#...#.#..##.
#...#.#.#.#.###.##..#.....#..#...#..#.#..#..#.#.#........#....#.....#...#.#......#..#...###.##....#.....#.#.#...#.#..#..
.##.###.#.#.#...#...###.##...#..###.###...#.#.#.###.###.###.##..###.###..#..###..#..###.#.#.#.#.##..###.###.###.##..#...
```

Every group of four columns contains three columns of glyph data and one all-zero separator. Consequently, the 120-column rows contain 30 glyphs, each 3×4:

```python
for glyph in range(30):
    columns = range(glyph * 4, glyph * 4 + 3)
    # read rows[row][column] for row = 0..3
```

The first glyphs decode as `C`, `O`, `M`, `P`, `F`, `E`, `S`, `T`, `1`, `8`, and `{`. The remaining glyphs read:

```text
H E _ I S _ 2 0 _ Y E A R S _ O L D }
```

Joining them gives the flag:

```text
COMPFEST18{HE_IS_20_YEARS_OLD}
```

## Reproduction

From this directory, run:

```bash
python3 decode.py
```

The script prints the transformed bytes, the 4×120 canvas, each 3×4 glyph, and the final decoded flag.
