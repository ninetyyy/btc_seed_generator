# seed_generator.py

Offline Dice/Card BIP39 generator.

## Files

Keep these two files together:

- `seed_generator.py`
- `BIP39_wordlist.txt` (2048-word BIP39 English list)

The program does not download anything, does not use `random`, and does not
write the mnemonic or entropy to disk. It *does* validate the wordlist
byte-for-byte against the official BIP39 English list (order + content),
which is safer than trusting any wordlist at face value.

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
SELF-TEST: PASS (16 official vectors, wordlist hash OK)
```

`self-test` now runs the official BIP39 test vectors (128/256-bit entropy →
12/24-word mnemonics) and refuses to proceed if the wordlist is
not the exact official list (SHA-256 checked).

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

The CLI requires exactly the minimum count; extra or missing outcomes are
rejected.

If the transcript is rejected, collect a new independent transcript. Do not
modify the rejected values.

## Verify

```text
python seed_generator.py --wordlist BIP39_wordlist.txt verify --mnemonic "..."
```

The program reports whether the BIP39 checksum is valid but deliberately does
not print the recovered entropy.

## Web UI (local only)

An optional local-only web UI wraps the same `seed_generator.py` logic —
no cryptographic code is duplicated in JavaScript. It adds:

- `seed_server.py`
- `templates/index.html`
- `static/app.js`, `static/style.css`

Properties:

- Binds to `127.0.0.1` only; never `0.0.0.0`. No external services,
  APIs, or CDNs: page, styles, and script are served from this directory.
- Flask debug mode and the interactive debugger are disabled.
- API requests must come from the local page (`Origin`/`Host` guard);
  cross-origin requests are rejected with 403.
- Nothing is persisted: no files, no database, no cookies, no browser
  storage, no request-body logging. Secrets travel only in the JSON
  bodies of `POST /api/generate` and `POST /api/verify` (loopback only,
  never in URLs or command-line arguments).
- No automatic clipboard copying; words are displayed for manual
  transcription.
- `Clear Session` wipes all UI state, clears the in-page copy of the
  last generated mnemonic, and calls `POST /api/reset`.
- After a successful generate, the result section shows a
  "Verify this mnemonic" button. It hands the fresh mnemonic to the
  Verify tab in-page (JavaScript memory to the textarea: no clipboard,
  no storage, no network) and runs the checksum check immediately.
- The Verify tab shows a live word count and, once the text holds
  exactly 12 or 24 words, re-runs the checksum check about 0.6 s after
  the last keystroke.
- At startup the server re-validates the wordlist SHA-256 and runs the
  16 official BIP39 test vectors; it refuses to start if either fails.

Run it (from the project directory, using the venv):

```text
python seed_server.py
# → http://127.0.0.1:8420

python seed_server.py --port 9000 --wordlist BIP39_wordlist.txt
```

API (JSON, loopback only):

```text
POST /api/generate  {"mode":"dice","bits":128,"transcript":"3 3 4 ..."}
    → {"words":[...], "word_count":12, "checksum_valid":true, ...}
      (the BIP39 checksum is auto-verified before the response is sent;
       entropy is never returned)

POST /api/verify    {"mnemonic":"word ... word"}
    → {"valid":true, "word_count":12, "entropy_size_bits":128}
      or {"valid":false, "reason":"Invalid BIP39 checksum: ..."}
      (a verdict is HTTP 200; only malformed requests return 400;
       the recovered entropy is never returned)

POST /api/reset     → {"ok":true}   (clears server-side temporary state)
```

### Residual-data limits (web UI and CLI alike)

This tool does not store secrets, but it cannot make them invisible to
the machine they run on:

- Values can remain in **RAM** until the machine is powered off (or the
  memory is overwritten).
- The **OS pagefile / swap** may capture pages that contained secrets.
- **Crash dumps** (minidumps, kernel memory dumps) may contain them.
- **Browser extensions** (and any installed add-ons) can read a page in
  the browser serving this tool.
- **Pre-existing malware** on the machine can exfiltrate whatever the
  processes hold in memory.

For real funds: use a dedicated, clean, offline machine; verify the
source; and power off the machine when done. The BIP39 checksum proves
implementation consistency — it does not prove that the physical
dice/card process was unbiased.

## Important production precautions

For real funds:

1. Use an offline machine / Disconnect internet, wifi and bluetooth.
2. Verify the Python source before running it.
3. Verify the wordlist has exactly 2048 unique words (this program does),
   and that it matches the official BIP39 English list (it also does).
4. Avoid shells/IDEs that save command history or logs.
5. Write the mnemonic by hand; do not save it as a file.
6. Independently restore/verify the resulting wallet before funding it.
7. Shut down your machine to avoid data store unintentionally in RAM/memory.

* Remember: BIP39 passphrase is a separate secret and is not generated here.

This tool's checksum test proves implementation consistency; it does not prove
that your physical dice/card process was unbiased.
