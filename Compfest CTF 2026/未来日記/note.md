# 未来日記 — Compfest CTF 2026

**Category:** Binary exploitation (heap)

**Challenge author:** yrNeh22

**Description:** `who knew Aang could bend bits too?`

## Flag

```text
COMPFEST18{さぁ_E1n5_zW31_Dr3i_重なり合う_fdf0b744ee277fcc}
```

## Files in this folder

- `chall`: the challenge executable.
- `chall.c`: the supplied source code.
- `libc.so.6` and `ld-linux-x86-64.so.2`: the matching Ubuntu glibc and loader.
- `exploit.py`: the working local/remote exploit.
- `Dockerfile` and `docker-compose.yml`: the supplied container configuration.

`flag.txt` is intentionally not included: the local copy contained a dummy flag,
not the flag from the live challenge service.

## 1. What the program does

The program is a tiny note manager. It stores up to seven pointers in the global
array `nikkis[]` and remembers each requested size in `sizes[]`.

The menu has three documented actions and one hidden information leak:

```text
[1] add
[2] delete
[3] edit
>>
```

Option 4 calls `predict()`, even though it is not printed in the menu.

### Adding a note

```c
char *nikki = malloc(size);
nikkis[idx] = nikki;
sizes[idx] = size;
```

The index must be between 0 and 6, and the requested size must be at most
`0x500`.

### Deleting a note

```c
free(nikkis[idx]);
```

This is the important mistake: the pointer is freed, but `nikkis[idx]` is not
changed to `NULL`.

### Editing a note

```c
read(0, nikkis[idx], sizes[idx]);
```

The program trusts the old pointer and old size. If the note was already freed,
this writes into freed heap memory.

### The hidden prediction leak

```c
unsigned short secret = ((unsigned short)nikkis[0]) >> 12;
```

The program prints `secret` as `TAKE THIS: <hex>`. This reveals four bits of the
pointer in slot zero: heap address bits 12–15. It is not a complete address
leak, but it is enough to make the final one-byte safe-linking guess manageable.

## 2. Vulnerabilities

### Use-after-free

The sequence below is accepted:

```text
add(0, 0x88)
delete(0)
edit(0, attacker_data)
```

`edit(0, ...)` writes to memory after `free()` has returned it to the allocator.
That memory contains glibc's tcache metadata, so the attacker can change the
allocator's linked-list pointers.

### Double-free check bypass

Modern glibc stores a tcache key in the second eight bytes of a freed chunk. It
uses that key to detect a direct double free. The same UAF lets us overwrite the
first 16 bytes of the freed chunk with zeroes before freeing it again. Clearing
the key bypasses the check:

```text
delete(1)
edit(1, 16 zero bytes)
delete(1)
```

Repeating this fills one tcache bin with aliases of the same physical chunk.

### Replacing occupied slots

`add()` does not check whether a slot is already occupied and does not free its
old value before replacing it. This creates useful stale aliases during heap
layout preparation.

These bugs are more important than a traditional stack overflow: they let us
corrupt allocator metadata and make `malloc()` return a pointer into libc.

## 3. Heap concepts needed for the exploit

### Chunk size versus requested size

`malloc()` adds allocator bookkeeping and rounds up for alignment. For example,
a request of `0x88` becomes a chunk of size `0x90`, and a request of `0x3e8`
becomes a chunk of size `0x3f0`.

### Tcache

Tcache is a set of per-thread singly linked lists of recently freed chunks. Each
size class has a head pointer. A subsequent `malloc()` of that size normally
returns the head of the corresponding list.

### Safe-linking

Recent glibc versions do not store a tcache `next` pointer directly. They store:

```text
stored_next = real_next XOR (address_of_next_field >> 12)
```

Consequently, poisoning a tcache list usually requires knowing an address. Here
we use a partial overwrite and try the unknown high nibble on a fresh connection.

## 4. Heap layout used

The first allocation is deliberately large:

```text
add(0, 0x4d0)  -> D, user pointer = heap + 0x10
```

It is larger than the normal tcache range, so it causes glibc to initialize the
tcache structure after it. The important offsets observed with the supplied
Ubuntu glibc `2.42-0ubuntu3.1` are:

```text
heap + 0x4f0  tcache_perthread_struct user area
heap + 0x760  an overlapping entry pointer used for edits
heap + 0x770  tcache entry[61]
heap + 0x780  tcache entry[63]
heap + 0x7f0  F, the first 0x90-sized note
heap + 0x880  A, a 0x3f0-sized note
heap + 0xc70  B, a 0x410-sized note
```

The exact absolute heap address is randomized, but these offsets remain stable.

## 5. Turning the UAF into a tcache metadata pointer

### Step 1: prepare two tcache bins

The exploit allocates:

```text
slot 0: D = add(0, 0x4d0)
slot 1: F = add(1, 0x88)
slot 2: A = add(2, 0x3e8)
slot 5: B = add(5, 0x408)
```

It frees `B` and `A`, placing them in tcache bins for chunk sizes `0x410` and
`0x3f0`.

### Step 2: make a self-linked tcache entry

The exploit frees `F` seven times. Between frees it uses the UAF to clear the
first 16 bytes of `F`, which removes the tcache key and allows the next free.
After the last free, the tcache head points to `F`, and `F->next` is a valid
safe-linked pointer back to `F` itself.

### Step 3: overwrite one byte

The self-link is edited by changing only its low byte. The desired decoded
address is `heap + 0x780`, the `0x410` tcache entry field. Option 4 reveals the
low nibble of the safe-linking key; the other nibble is unknown.

For each possible high nibble `g`, the script computes:

```python
key_low = (g << 4) | leaked_heap_nibble
encoded_low = 0x80 ^ key_low
```

The correct guess makes the next allocation return the tcache entry at
`heap + 0x780`. Since the heap is freshly randomized for every connection, the
script retries guesses on new connections.

Two allocations then give:

```text
add(3, 0x88) -> the original F chunk
add(4, 0x88) -> P = heap + 0x780
```

`P` is now an edit pointer into the allocator's metadata.

## 6. Getting full tcache control

Using `P`, the exploit partially changes tcache entry 63 first to
`heap + 0x4f0`:

```text
add(6, 0x408) -> M = heap + 0x4f0
```

`M` overlaps the entire `tcache_perthread_struct`, giving a full-size metadata
write primitive.

The script then changes entry 63 to `heap + 0x760` and allocates:

```text
add(2, 0x408) -> Q = heap + 0x760
```

`Q` can edit entry 61 without destroying the separate pointer `P`, which is
still able to edit entry 63.

## 7. Recovering a libc pointer with safe-linking double protection

The large chunk `D` is freed to the unsorted bin. Its freed contents contain a
raw pointer into glibc's `main_arena`.

The exploit uses `Q` to redirect tcache entry 61 to `D` and allocates a
`0x3f0`-class chunk. When glibc removes `D` from tcache, it applies safe-linking
to the raw arena pointer and stores the protected value back in entry 61.

Next, `P` redirects entry 63 to the entry-61 field itself. Because both fields
are on the same heap page, the safe-linking keys cancel when glibc performs the
second tcache allocation:

```text
protected = arena_pointer XOR heap_page_key
decoded   = protected XOR heap_page_key
          = arena_pointer
```

The next allocation therefore returns a raw libc address. Option 4 now leaks
four bits from that libc pointer as well.

## 8. Leaking libc and the heap through stdout

In this libc:

```text
main_arena + 0x60  = libc + 0x234b20
_IO_2_1_stdout_    = libc + 0x2355c0
```

These addresses are close enough that the exploit can partially redirect the
raw arena pointer to stdout by overwriting only its low 16 bits.

The script allocates a pointer to `_IO_2_1_stdout_` and edits its `FILE` fields:

```text
flags       = 0xfbad1800
read fields = 0
write_base  = stdout
write_ptr   = the existing stdout buffer pointer
```

The next normal menu print flushes the bytes between `write_base` and
`write_ptr`, disclosing the full stdout address. Subtracting `0x2355c0` gives
the complete libc base.

The exploit then performs a second stdout overwrite whose write window points
at `main_arena`. The arena's top pointer is a known offset from the initial heap
layout, so this reveals the complete heap base as well.

## 9. Final control flow: House of Apple FSOP

FSOP means **File Stream Oriented Programming**: instead of overwriting a return
address, we corrupt a glibc `FILE` object and make a later `printf()` call a
function pointer from that object.

The exploit writes a fake wide-character structure in the heap:

```text
fake_wide_data + 0xe0       -> fake wide vtable
fake_wide_vtable + 0x68     -> system
```

It replaces stdout's vtable with the legitimate `_IO_wfile_jumps` table and
sets stdout's `_wide_data` pointer to the fake structure. The fake `FILE` starts
with:

```text
  cat flag.txt
```

When the next menu output takes the wide-file path, glibc reaches the fake
`doallocate` function pointer. That pointer is `system`, and its argument is the
stdout object itself, so the command at the start of the object is executed.

The service runs with `flag.txt` in its working directory, producing the flag.

## 10. Running the exploit

On Kali, from this directory:

```bash
python3 exploit.py --remote --brute
```

The `--brute` mode opens fresh connections and tries the unknown nibble. The
default is 64 attempts. If all attempts happen to miss, run it again:

```bash
python3 exploit.py --remote --brute --attempts 128
```

To test locally with the supplied loader and libc:

```bash
python3 exploit.py
```

The local run uses `flag.txt` only as a smoke-test file; it is not the remote
challenge flag.

## 11. Lessons for a first heap-exploitation challenge

1. Always inspect what happens to a pointer after `free()`. A dangling pointer
   is often more useful than the original allocation.
2. Learn the allocator's data structures before trying random inputs. Tcache
   bins, chunk sizes, and safe-linking explain why each request size matters.
3. A partial leak can still be valuable. Four leaked bits were enough to reduce
   a pointer-byte uncertainty to 16 attempts.
4. When a direct return-address overwrite is unavailable, libc data structures
   such as `FILE` objects may provide another control-flow path.
5. Always use the exact challenge libc when debugging heap behavior. Small glibc
   version differences can change tcache limits, metadata layout, and FILE
   internals.
