#!/usr/bin/env python3
"""Keygen for Ragnarok.exe crackme based on bytecode analysis."""

import argparse

FNV_INIT = 0x811c9dc5
FNV_PRIME = 0x1000193
LCG_MULT = 0x41c64e6d
LCG_ADD = 0x3039
TARGET = 0x13371337cafebabe
MASK_64 = 0xFFFFFFFFFFFFFFFF
MASK_32 = 0xFFFFFFFF


def fnv1a_hash(username: str) -> int:
    """Compute FNV-1a hash of username.

    Binary does: hash = (byte ^ hash) * prime
    Note the XOR happens BEFORE multiply.
    """
    hash_value = FNV_INIT
    for char in username:
        hash_value = ((ord(char) ^ hash_value) * FNV_PRIME) & MASK_32
    return hash_value


def lcg_next(state: int) -> int:
    """Perform one LCG step."""
    return (state * LCG_MULT + LCG_ADD) & MASK_32


def extract_coefficients(username: str) -> tuple:
    """Generate C1-C4 and PRNG offsets from username hash.

    From FUN_140001bf0 decompilation:
    - Two LCG steps per coefficient
    - Coefficient = (state1 >> 16 & 0x7fff) | (state2 & 0x7fff0000)
    - This creates a 30-bit value with bit 15 always 0
    """
    state = fnv1a_hash(username)

    # C1: two LCG steps, combine bits
    state1 = lcg_next(state)
    state2 = lcg_next(state1)
    c1 = ((state1 >> 16) & 0x7fff) | (state2 & 0x7fff0000)
    state = state2

    # C2
    state1 = lcg_next(state)
    state2 = lcg_next(state1)
    c2 = ((state1 >> 16) & 0x7fff) | (state2 & 0x7fff0000)
    state = state2

    # C3
    state1 = lcg_next(state)
    state2 = lcg_next(state1)
    c3 = ((state1 >> 16) & 0x7fff) | (state2 & 0x7fff0000)
    state = state2

    # C4
    state1 = lcg_next(state)
    state2 = lcg_next(state1)
    c4 = ((state1 >> 16) & 0x7fff) | (state2 & 0x7fff0000)
    state = state2

    # Additional PRNG values used as offsets in bytecode (p1-p4)
    state = lcg_next(state)
    p1 = (state >> 16) & 0x7fff

    state = lcg_next(state)
    p2 = (state >> 16) & 0x7fff

    state = lcg_next(state)
    p3 = (state >> 16) & 0x7fff

    state = lcg_next(state)
    p4 = (state >> 16) & 0x7fff

    return (c1, c2, c3, c4, p1, p2, p3, p4)


def solve_serial(coeffs: tuple, s1: int, s2: int, s3: int) -> int:
    """Solve for S4 given coefficients and S1, S2, S3.

    From VM trace, the actual equation is:
    R0 = (C1 ^ S1 + p1) + ((C2 + S2) ^ p2) + (C3 - S3 + p3) + ((C4 ^ S4) ^ p4)

    Each serial part is processed differently:
    - S1: XOR with C1, then ADD p1
    - S2: ADD to C2, then XOR with p2
    - S3: SUB from C3, then ADD p3
    - S4: XOR with C4, then XOR with p4

    Solving for S4:
    TARGET = partial + ((C4 ^ S4) ^ p4)
    (C4 ^ S4) ^ p4 = TARGET - partial
    C4 ^ S4 = (TARGET - partial) ^ p4
    S4 = C4 ^ ((TARGET - partial) ^ p4)
    """
    c1, c2, c3, c4, p1, p2, p3, p4 = coeffs

    # Compute known contributions from S1, S2, S3
    r1 = (c1 ^ s1) + p1
    r2 = (c2 + s2) ^ p2
    r3 = (c3 - s3 + p3)

    partial = (r1 + r2 + r3) & MASK_64

    # Solve for S4
    needed = (TARGET - partial) & MASK_64
    s4 = c4 ^ (needed ^ p4)

    return s4


def verify_serial(username: str, s1: int, s2: int, s3: int, s4: int) -> tuple:
    """Verify serial produces target value. Returns (result, matches)."""
    coeffs = extract_coefficients(username)
    c1, c2, c3, c4, p1, p2, p3, p4 = coeffs

    # Emulate actual VM computation
    r1 = (c1 ^ s1) + p1
    r2 = (c2 + s2) ^ p2
    r3 = (c3 - s3 + p3)
    r4 = (c4 ^ s4) ^ p4

    r0 = (r1 + r2 + r3 + r4) & MASK_64

    return r0, r0 == TARGET


def generate_serial(username: str) -> str:
    """Generate complete serial for given username."""
    coeffs = extract_coefficients(username)
    s1 = s2 = s3 = 0x1337
    s4 = solve_serial(coeffs, s1, s2, s3)
    return f"{s1:X}-{s2:X}-{s3:X}-{s4:X}"


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description='Ragnarok.exe Keygen')
    parser.add_argument('username', nargs='?', help='Username to generate serial for')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show debug info')
    args = parser.parse_args()

    if args.username:
        username = args.username
    else:
        username = input("Enter username: ").strip()

    if not username:
        print("Error: Username cannot be empty")
        return 1

    serial = generate_serial(username)
    print(f"\n{'='*50}")
    print(f"  Username: {username}")
    print(f"  Serial:   {serial}")
    print(f"{'='*50}")

    # Verify the generated serial
    s1 = s2 = s3 = 0x1337
    coeffs = extract_coefficients(username)
    s4 = solve_serial(coeffs, s1, s2, s3)
    result, matches = verify_serial(username, s1, s2, s3, s4)

    if args.verbose:
        c1, c2, c3, c4, p1, p2, p3, p4 = coeffs
        print(f"\n[Debug] FNV-1a hash: 0x{fnv1a_hash(username):08X}")
        print(f"[Debug] C1=0x{c1:08X} C2=0x{c2:08X} C3=0x{c3:08X} C4=0x{c4:08X}")
        print(f"[Debug] p1=0x{p1:04X} p2=0x{p2:04X} p3=0x{p3:04X} p4=0x{p4:04X}")
        print(f"[Debug] S4=0x{s4:016X}")
        print(f"[Debug] Result: 0x{result:016X}")
        print(f"[Debug] Target: 0x{TARGET:016X}")

    if matches:
        print("\n[OK] Serial verified!")
    else:
        print(f"\n[FAIL] Serial verification failed!")
        print(f"       Expected: 0x{TARGET:016X}")
        print(f"       Got:      0x{result:016X}")
        return 1

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main() or 0)
