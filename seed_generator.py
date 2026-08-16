#!/usr/bin/env python3
"""
seed_generator.py

Offline BIP39 mnemonic generator using ONLY user-supplied Dice/Card entropy.

Security design:
- No network access.
- No OS randomness / secrets / random module.
- Dice mode: D6 outcomes 1..6, with exact base-6 rejection sampling.
- Card mode: outcomes 1..13 (A=1..10,J=11,Q=12,K=13), with exact
  base-13 rejection sampling.
- BIP39 checksum is implemented directly from SHA-256.
- The BIP39 English wordlist must be supplied as a local file.
- Seed/mnemonic is never written to disk by this program.
- Verify mode validates checksum only; it does NOT prove the original
  entropy source was random.

IMPORTANT:
The program accepts entropy transcripts as input. For real wallet creation,
run it on an offline machine and do not paste real entropy/mnemonics into
chat, shells with persistent history, IDEs, or logs.

Input format:
  Dice: space-separated values 1..6
  Cards: space-separated values 1..13; alternatively A/J/Q/K may be used,
         where A=1, J=11, Q=12, K=13. The value 10 is one token.

The extraction algorithm:
  A sequence of radix-n symbols is interpreted as an integer X in [0,n^k).
  We reject the top remainder so that the accepted range is an exact multiple
  of 2^ENT. Then X mod 2^ENT is the output entropy. This is exact
  rejection sampling and introduces no modulo bias.

For 128 bits:
  Dice: 50 rolls minimum; Card: 35 outcomes minimum.
For 256 bits:
  Dice: 100 rolls minimum; Card: 70 outcomes minimum.

The CLI requires exactly the minimum count; extra outcomes are rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Iterable

ENT_BITS = (128, 256)
RADIX = {"dice": 6, "cards": 13}

# BIP39 checksum length in bits: ENT/32 (4 bits for 128-bit, 8 bits for 256-bit).


def _checksum_bits(entropy: bytes) -> int:
    return len(entropy) * 8 // 32


# Convert integer to fixed-width binary string (e.g., 5, 8 → "00000101").
def _int_to_bits(value: int, width: int) -> str:
    return f"{value:0{width}b}"


def parse_rolls(text: str, mode: str) -> list[int]:
    """
    Parse whitespace/comma-separated outcomes.
    Cards accept 1..13, A=1, J=11, Q=12, K=13.
    '10' is a single token (not two separate digits).
    """
    tokens = text.replace(",", " ").split()
    out = []
    aliases = {"A": 1, "J": 11, "Q": 12, "K": 13}
    maxv = RADIX[mode]

    for tok in tokens:
        u = tok.upper()
        if mode == "cards" and u in aliases:
            v = aliases[u]
        else:
            try:
                v = int(tok)
            except ValueError as exc:
                raise ValueError(f"Invalid {mode} outcome: {tok!r}") from exc
        if not 1 <= v <= maxv:
            raise ValueError(f"{mode} outcome {v} outside 1..{maxv}")
        out.append(v)
    return out


def _min_count(radix: int, ent_bits: int) -> int:
    # Smallest k with radix**k >= 2**ENT.
    # (For 256-bit cards this is 70; for 256-bit dice it is 100.)
    k = 0
    capacity = 1
    target = 1 << ent_bits
    while capacity < target:
        capacity *= radix
        k += 1
    return k


def extract_entropy(outcomes: Iterable[int], mode: str, required: int, ent_bits: int) -> bytes:
    """
    Exact rejection-sampling extractor.

    For k outcomes, encode each symbol as digit (outcome-1) in radix n.
    X is in [0, n^k).
    Let M = floor(n^k / 2^ENT) * 2^ENT.
    If X >= M, reject. Otherwise output X mod 2^ENT.

    This is unbiased even though n (6 or 13) is not a power of two.
    """
    if ent_bits not in ENT_BITS:
        raise ValueError("Entropy must be 128 or 256 bits.")

    vals = list(outcomes)
    radix = RADIX[mode]
    k = len(vals)
    # required = _min_count(radix, ent_bits)
    if k < required:
        raise ValueError(
            f"{mode}: need at least {required} outcomes for {ent_bits} bits; "
            f"got {k}."
        )

    # For reproducibility and simple auditing, use exactly the minimum count.
    # The CLI enforces exact count, so this truncation is a defensive safety net.
    vals = vals[:required]

    x = 0
    for v in vals:
        if not 1 <= v <= radix:
            raise ValueError(f"Outcome {v} outside 1..{radix}")
        x = x * radix + (v - 1)

    capacity = radix ** required
    target = 1 << ent_bits
    accepted_limit = (capacity // target) * target

    if x >= accepted_limit:
        raise ValueError(
            "REJECTED by exact rejection sampling. "
            "Supply a new independent set of outcomes; do not edit/reorder "
            "the rejected transcript to try to make it pass."
        )

    entropy_int = x % target
    return entropy_int.to_bytes(ent_bits // 8, "big")


# BIP39: entropy + SHA256 checksum → 11-bit groups → wordlist lookup.
def entropy_to_mnemonic(entropy: bytes, wordlist: list[str]) -> str:
    ent_bits = len(entropy) * 8
    if ent_bits not in ENT_BITS:
        raise ValueError("Entropy must be 128 or 256 bits.")
    if len(wordlist) != 2048:
        raise ValueError("BIP39 wordlist must contain exactly 2048 words.")

    checksum_len = _checksum_bits(entropy)
    digest = hashlib.sha256(entropy).digest()
    cs = _int_to_bits(digest[0], 8)[:checksum_len]
    data = "".join(f"{b:08b}" for b in entropy) + cs

    words = []
    for i in range(0, len(data), 11):
        idx = int(data[i:i+11], 2)
        words.append(wordlist[idx])
    return " ".join(words)


# BIP39: words → 11-bit indices → split into entropy + checksum → verify SHA256.
def mnemonic_to_entropy(mnemonic: str, wordlist: list[str]) -> bytes:
    words = mnemonic.strip().split()
    if len(words) not in (12, 24):
        raise ValueError("Mnemonic must contain exactly 12 or 24 words.")
    if len(wordlist) != 2048:
        raise ValueError("BIP39 wordlist must contain exactly 2048 words.")

    index = {w: i for i, w in enumerate(wordlist)}
    if len(index) != 2048:
        raise ValueError("Wordlist contains duplicate words.")

    try:
        data = "".join(f"{index[w]:011b}" for w in words)
    except KeyError as exc:
        raise ValueError(
            f"Word not found in wordlist: {exc.args[0]!r}") from exc

    # Note: hashlib.sha256 uses OpenSSL on most platforms. For air-gapped
    # production use, consider auditing the OpenSSL build or substituting
    # a pure-Python constant-time SHA-256 implementation.

    ent_bits = 128 if len(words) == 12 else 256
    cs_len = ent_bits // 32
    entropy_bits = data[:ent_bits]
    supplied_cs = data[ent_bits:ent_bits + cs_len]

    entropy = int(entropy_bits, 2).to_bytes(ent_bits // 8, "big")
    actual_cs = _int_to_bits(hashlib.sha256(entropy).digest()[0], 8)[:cs_len]

    if supplied_cs != actual_cs:
        raise ValueError(
            f"Invalid BIP39 checksum: supplied={supplied_cs}, "
            f"actual={actual_cs}"
        )
    return entropy


# Read and validate BIP39 wordlist file (must be 2048 unique words).
def load_wordlist(path: Path) -> list[str]:
    words = [line.strip() for line in path.read_text("utf-8").splitlines()
             if line.strip()]
    if len(words) != 2048:
        raise ValueError(f"{path} contains {len(words)} words; expected 2048.")
    if len(set(words)) != 2048:
        raise ValueError("Wordlist contains duplicate words.")
    return words


# Run built-in BIP39 test vectors to verify implementation correctness.
def self_test(wordlist: list[str]) -> None:
    # BIP39 official test vector #1 (mnemonic only).
    # ENT = 000...000 (128 bits), checksum = 0011.
    expected_12 = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    entropy = bytes(16)
    got = entropy_to_mnemonic(entropy, wordlist)
    assert got == expected_12, (got, expected_12)
    assert mnemonic_to_entropy(expected_12, wordlist) == entropy

    # BIP39 official 256-bit all-zero vector.
    expected_24 = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon art"
    )
    entropy256 = bytes(32)
    got256 = entropy_to_mnemonic(entropy256, wordlist)
    assert got256 == expected_24, (got256, expected_24)
    assert mnemonic_to_entropy(expected_24, wordlist) == entropy256

    # Non-zero entropy test: verify round-trip with known bytes.
    non_zero = bytes(range(16))
    mnemo_nz = entropy_to_mnemonic(non_zero, wordlist)
    recovered = mnemonic_to_entropy(mnemo_nz, wordlist)
    assert recovered == non_zero, (recovered, non_zero)

    # Invalid checksum detection test: use a valid word with wrong checksum.
    # The original mnemonic ends with "about" (checksum 0011 for all-zero entropy).
    # Swapping to "abandon" (index 0, bits 00000000000) changes the checksum bits
    # to 0000, which doesn't match the expected 0011.
    try:
        mnemonic_to_entropy(
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon", wordlist
        )
        assert False, "Should have raised ValueError for invalid checksum"
    except ValueError as exc:
        assert "Invalid BIP39 checksum" in str(exc), \
            f"Expected checksum error, got: {exc}"

    # Rejection sampling test: all-max outcomes produce X near n^k - 1,
    # which falls in the rejection region at the top of the range.
    # For 50 dice rolls (base-6), max X = 6^50 - 1, which exceeds
    # the accepted_limit = floor(6^50 / 2^128) * 2^128.
    dice_max = [6] * 50
    try:
        extract_entropy(dice_max, "dice", 128)
        assert False, "Should have been rejected by exact sampling"
    except ValueError as exc:
        assert "REJECTED" in str(exc)

    print("SELF-TEST: PASS")


# CLI entry point: parse args, dispatch to generate/verify/self-test.
def main() -> int:
    p = argparse.ArgumentParser(
        description="Offline Dice/Card BIP39 mnemonic generator and verifier."
    )
    p.add_argument("--wordlist", default="BIP39_wordlist.txt",
                   help="local BIP39 English wordlist (default: BIP39_wordlist.txt)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser(
        "generate", help="generate mnemonic from supplied entropy transcript")
    g.add_argument("--mode", choices=["dice", "cards"], required=True)
    g.add_argument("--bits", type=int, choices=[128, 256], required=True)
    g.add_argument(
        "--rolls",
        required=True,
        help="space/comma separated outcomes; Cards accept A,J,Q,K."
    )
    g.add_argument(
        "--show-entropy", action="store_true",
        help="show entropy hex (avoid on production wallet creation)"
    )

    v = sub.add_parser("verify", help="verify BIP39 checksum of a mnemonic")
    v.add_argument("--mnemonic", required=True)

    t = sub.add_parser("self-test", help="run built-in BIP39 test vectors")

    args = p.parse_args()
    wordlist = load_wordlist(Path(args.wordlist))

    if args.cmd == "self-test":
        self_test(wordlist)
        return 0

    if args.cmd == "verify":
        entropy = mnemonic_to_entropy(args.mnemonic, wordlist)
        print("VALID BIP39 CHECKSUM")
        print(f"Entropy size: {len(entropy) * 8} bits")
        print("Entropy is NOT printed.")
        return 0

    if args.cmd == "generate":
        outcomes = parse_rolls(args.rolls, args.mode)
        required = _min_count(RADIX[args.mode], args.bits)
        if len(outcomes) != required:
            raise ValueError(
                f"For reproducibility, provide exactly {required} outcomes "
                f"for {args.mode}/{args.bits}."
            )
        entropy = extract_entropy(outcomes, args.mode, required, args.bits)
        mnemonic = entropy_to_mnemonic(entropy, wordlist)
        print("WARNING: this output contains wallet secrets.")
        print("Do not save terminal output, screenshots, shell history, or logs.")
        print()
        print("Mnemonic:")
        print(mnemonic)
        if args.show_entropy:
            print()
            print("Entropy (hex):")
            print(entropy.hex())
        return 0

    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
