---
title: "EHAXCTF 2026: Reverse Engineering Write-up"
published: 2026-03-04
description: "Reverse engineering notes from EHAXCTF 2026, including crackmes, path validation, and numerical analysis."
tags:
  - CTF
  - Reverse Engineering
category: CTF
author: "Duc Nguyen"
sourceLink: "https://github.com/4r12u/EhaxCTF2026_WU"
draft: false
---

This is my reverse engineering write-up for **EHAXCTF 2026**. The solutions below show the parts of each binary that mattered, together with the small scripts used to recover the flags.

## IGuessbro

The binary eventually calls `flagPrinter`, which reads a 35-character candidate and checks it with three functions: `DecodeAndCompareString`, `CheckMathProperties`, and `CheckHash`.

`DecodeAndCompareString` decodes a 35-byte constant using an index-dependent XOR:

```c
decoded[i] = encoded[i] ^ (i * 7) ^ 0xA5;
```

The encoded bytes recovered from `.rodata` are:

```python
encoded = [
    0xE0, 0xEA, 0x9F, 0xE8, 0xC2, 0xFF, 0xBF, 0xE1, 0xC2, 0xFD,
    0x96, 0xDB, 0x82, 0x8D, 0xF4, 0xA8, 0x8A, 0xA6, 0xB3, 0x14,
    0x5D, 0x69, 0x4D, 0x35, 0x7E, 0x69, 0x4C, 0x7B, 0x13, 0x5A,
    0x14, 0x17, 0x28, 0x71, 0x36,
]

flag = "".join(chr(value ^ ((index * 7) ^ 0xA5))
               for index, value in enumerate(encoded))
print(flag)
```

The result is:

```text
EH4X{y0u_gu3ss3d_th4t_r1sc_cr4ckm3}
```

The other checks confirm the `EH4X{...}` format, validate a set of character positions modulo `10^9 + 7`, and compare a custom hash against `0x81CF06F4A08CB5EF`.

## PathFinder

The program asks for a path. Each input character is looked up in a 12-byte table containing a two-dimensional movement and a bitmask. The candidate must move from `(0, 0)` to `(9, 9)` without leaving the grid, satisfy the mask check at every step, and pass a final custom hash.

When valid, `MakeFlag` run-length encodes repeated characters into the final flag format:

```c
while (*input) {
    character = *input;
    count = 0;
    while (character == *input) {
        ++count;
        ++input;
    }
    if (count <= 1) *out++ = character;
    else out += sprintf(out, "%d%c", count, character);
}
```

The movement table and hash are documented in the original repository alongside the solver.

## Compute It

This challenge validates complex numbers with Newton's method. The decompiled equations are the real and imaginary components of:

```text
f(z) = z^3 - 1
```

The validator accepts a point only when it converges to `(1, 0)` in exactly 12 iterations. I evaluated every coordinate from `signal_data.txt`, converted valid points to bits, and reshaped the result into a 20×130 image:

```python
def check_coordinate(real, image):
    count = 0
    for _ in range(50):
        f_real = real * (real * real) - image * (real * 3.0 * image) - 1.0
        f_image = image * (real * 3.0 * real) - image * (image * image)
        d_real = 3.0 * (real * real - image * image)
        d_image = image * (real * 6.0)
        denominator = d_image * d_image + d_real * d_real
        if denominator < 1e-9:
            break
        real -= (f_image * d_image + f_real * d_real) / denominator
        image -= (f_image * d_real - f_real * d_image) / denominator
        count += 1
        if abs(real - 1.0) < 1e-6 and abs(image) < 1e-6:
            break
    return count == 12
```

Rendering the bit grid reveals:

```text
EH4X{N3WTON_W45_R1GHT}
```

## Kaje

`main` generates entropy, derives a keystream, and XORs it with two 16-byte constants before printing the result. The important reversing step is reconstructing `gen_entropy` and `gen_keystream`, then reproducing the XOR with the constants loaded from `.rodata`. The provided `kaje` binary and IDA database are kept in the source repository for the remaining constant values and solver.

## Summary

The complete challenge files, binaries, scripts, and the original Vietnamese notes are available in the [EhaxCTF2026_WU repository](https://github.com/4r12u/EhaxCTF2026_WU).
