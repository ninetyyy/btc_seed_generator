# seed_generator.py

Offline Dice/Card BIP39 generator.

## Files

Keep these two files together:

- `seed_generator.py`
- your `BIP39_wordlist.txt` (2048-word BIP39 English list)

The program does not download anything, does not use `random`, and does not
write the mnemonic or entropy to disk.

## Minimum input counts

- Dice (D6): 50 outcomes for 128-bit, 100 for 256-bit.
- Cards (13 outcomes): 35 outcomes for 128-bit, 70 for 256-bit.

Card values:
- A = 1
- 2..10 = themselves
- J = 11
- Q = 12
- K = 13

Use replacement: each card outcome must be an independent uniform draw from
1..13. If physically using 13 cards, draw one, record it, replace it, shuffle,
then draw again.

## Test first

```text
python seed_generator.py --wordlist BIP39_wordlist.txt self-test
```

Expected:

```text
SELF-TEST: PASS
```

## Generate from a transcript

Dice:

```text
python seed_generator.py --wordlist BIP39_wordlist.txt generate --mode dice --bits 128 --rolls "1 6 3 ... 50 values"
```

Cards:

```text
python seed_generator.py --wordlist BIP39_wordlist.txt generate --mode cards --bits 128 --rolls "1 8 3 9 J 2 K ... 35 values"
```

The generator uses exact radix rejection sampling. It interprets the outcomes
as a base-6 or base-13 integer, rejects the small top range that would create
modulo bias, and maps the accepted value uniformly to 2^ENT possibilities.

If the transcript is rejected, collect a new independent transcript. Do not
modify the rejected values.

## Verify

```text
python seed_generator.py --wordlist BIP39_wordlist.txt verify --mnemonic "..."
```

The program reports whether the BIP39 checksum is valid but deliberately does
not print the recovered entropy.

## Important production precautions

For real funds:

1. Use an offline machine / live OS.
2. Verify the Python source before running it.
3. Verify the wordlist has exactly 2048 unique words.
4. Disconnect networking.
5. Avoid shells/IDEs that save command history or logs.
6. Write the mnemonic by hand; do not save it as a file.
7. Independently restore/verify the resulting wallet before funding it.
8. Remember: BIP39 passphrase is a separate secret and is not generated here.

This tool's checksum test proves implementation consistency; it does not prove
that your physical dice/card process was unbiased.
