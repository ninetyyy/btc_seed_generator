#!/usr/bin/env python3
"""
seed_server.py

Local-only Flask web UI for the offline BIP39 mnemonic tool.

Security design:
- Binds to 127.0.0.1 only (never 0.0.0.0). No external services, APIs,
  or CDNs: the page, styles, and script are served from this directory.
- Reuses seed_generator.py for ALL entropy extraction, rejection
  sampling, BIP39 generation, and validation. No cryptographic logic is
  reimplemented here or in JavaScript.
- Secrets (transcripts / entropy / mnemonics) travel only in the JSON
  bodies of the two API calls. They are never placed in URLs,
  command-line arguments, logs, cookies, files, or browser storage.
- The server is stateless: nothing about a session is retained after a
  request. POST /api/reset is an explicit cleanup hook for the UI.
- Flask debug mode and the interactive debugger are disabled; the
  reloader is off and the server runs single-threaded.
- API requests are restricted to this local application: a request
  carrying an Origin header must come from http://127.0.0.1:<port>;
  a request without Origin (e.g. curl) must carry the exact Host
  header 127.0.0.1:<port>. Anything else is rejected with 403.
- Every response (page and static assets included) is served with
  no-store cache control, nosniff, a strict same-origin CSP, and
  framing blocked.

Residual-data limits (documented in the README and the UI footer):
values can persist in RAM, the OS pagefile/swap, crash dumps, browser
extensions, or via pre-existing malware until the machine is powered
off. The server process holding them in memory is the best guarantee.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

import seed_generator as sg

DEFAULT_PORT = 8420
HOST = "127.0.0.1"

# Runtime configuration (set by main() before the server starts).
PORT = DEFAULT_PORT
WORDLIST: list[str] = []

# Strict same-origin CSP: the page may only load resources from itself.
# No inline scripts/styles, no external origins, no frames, no fonts.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)

app = Flask(__name__, static_folder="static", template_folder="templates")
# A transcript is at most ~100 short tokens; 16 KB is far above that.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# ---------------------------------------------------------------------------
# Security middleware
# ---------------------------------------------------------------------------

@app.after_request
def _security_headers(resp):
    """Apply security headers to every response (page, static, API)."""
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = CSP
    return resp


@app.before_request
def _loopback_origin_guard():
    """Reject API requests that do not come from this local application.

    - Browsers always send Origin on cross-origin (and, in practice,
      same-origin) POSTs: it must be exactly http://127.0.0.1:<port>.
    - Origin-less clients (e.g. curl) must still address the exact
      loopback Host header 127.0.0.1:<port>.
    This stops other web pages from issuing requests to the API.
    """
    if not request.path.startswith("/api/"):
        return None
    if request.headers.get("Origin", ""):
        if request.headers["Origin"] != f"http://{HOST}:{PORT}":
            return jsonify(error="Cross-origin request rejected."), 403
        return None
    if request.headers.get("Host", "") != f"{HOST}:{PORT}":
        return jsonify(error="Request must target 127.0.0.1."), 403
    return None


def _make_api_error_handler():
    def handler(e: HTTPException):
        if request.path.startswith("/api/"):
            return jsonify(error=e.description or e.name), e.code
        return e
    return handler


app.register_error_handler(404, _make_api_error_handler())
app.register_error_handler(405, _make_api_error_handler())
app.register_error_handler(413, _make_api_error_handler())


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/generate")
def api_generate():
    """Generate a mnemonic from a user-supplied entropy transcript.

    Body: {"mode": "dice"|"cards", "bits": 128|256,
           "transcript": "space-separated outcomes"}
    The transcript is a JSON body value: it never appears in a URL,
    in the command line, or in the logs.

    The response contains the mnemonic words only. Entropy is never
    returned, and the BIP39 checksum is auto-verified server-side
    before the response is sent.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Request body must be a JSON object."), 400
    mode = data.get("mode")
    bits = data.get("bits")
    transcript = data.get("transcript")
    if mode not in ("dice", "cards"):
        return jsonify(error="mode must be 'dice' or 'cards'."), 400
    if bits not in (128, 256):
        return jsonify(error="bits must be 128 or 256."), 400
    if not isinstance(transcript, str) or not transcript.strip():
        return jsonify(error="transcript must be a non-empty string."), 400

    try:
        # Authoritative parsing/validation (server-side reuse of the
        # CLI implementation).
        outcomes = sg.parse_rolls(transcript, mode)
        required = sg._min_count(sg.RADIX[mode], bits)
        if len(outcomes) != required:
            raise ValueError(
                f"Expected exactly {required} outcomes for "
                f"{mode}/{bits}-bit, got {len(outcomes)}."
            )
        entropy = sg.extract_entropy(outcomes, mode, required, bits)
        mnemonic = sg.entropy_to_mnemonic(entropy, WORDLIST)

        # Automatic BIP39 checksum self-verification (round-trip).
        # The recovered entropy is compared and discarded, never sent.
        if sg.mnemonic_to_entropy(mnemonic, WORDLIST) != entropy:
            raise ValueError("Internal error: checksum re-verification failed.")

        words = mnemonic.split(" ")
        return jsonify(
            words=words,
            word_count=len(words),
            checksum_valid=True,
            mode=mode,
            bits=bits,
        )
    except ValueError as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/verify")
def api_verify():
    """Verify the BIP39 checksum of a supplied mnemonic.

    Body: {"mnemonic": "word word ... word"} (12 or 24 words).
    A valid or invalid verdict is a successful query (HTTP 200); only
    malformed requests return 400. The recovered entropy is never
    returned - only the verdict, word count, and entropy bit size.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Request body must be a JSON object."), 400
    mnemonic = data.get("mnemonic")
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        return jsonify(error="mnemonic must be a non-empty string."), 400

    try:
        entropy = sg.mnemonic_to_entropy(mnemonic, WORDLIST)
        return jsonify(
            valid=True,
            word_count=len(mnemonic.strip().split()),
            entropy_size_bits=len(entropy) * 8,
        )
    except ValueError as exc:
        return jsonify(valid=False, reason=str(exc)), 200


@app.post("/api/reset")
def api_reset():
    """Clear temporary server-side data.

    The server is intentionally stateless (no sessions, no cookies,
    no stored request data), so this is an explicit cleanup hook that
    keeps the UI contract simple. Process shutdown frees everything
    else that was held in memory.
    """
    return jsonify(ok=True)



# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def load_state(wordlist_path: Path) -> list[str]:
    """Load and validate the wordlist, then run the BIP39 self-test.

    The server refuses to start if the wordlist is not the official
    list or if any test vector fails.
    """
    global WORDLIST
    WORDLIST = sg.load_wordlist(wordlist_path)
    sg.self_test(WORDLIST)
    return WORDLIST


def main() -> int:
    global PORT
    parser = argparse.ArgumentParser(
        description="Local-only web UI for seed_generator.py "
                    "(binds 127.0.0.1 only; no external resources)."
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"loopback port (default {DEFAULT_PORT})")
    parser.add_argument("--wordlist", default="BIP39_wordlist.txt",
                        help="local BIP39 English wordlist "
                             "(default: BIP39_wordlist.txt)")
    args = parser.parse_args()
    PORT = args.port

    wordlist_path = Path(args.wordlist)
    if not wordlist_path.is_absolute():
        wordlist_path = Path(__file__).resolve().parent / wordlist_path
    try:
        load_state(wordlist_path)
    except (ValueError, AssertionError, OSError) as exc:
        print(f"FATAL: refusing to start: {exc}", file=sys.stderr)
        return 1

    print("=" * 66)
    print("  Offline BIP39 web UI - local only")
    print(f"  URL       : http://{HOST}:{PORT}")
    print("  Binds to  : 127.0.0.1 only (not reachable from the network)")
    print("  Stores    : nothing (no files, cookies, or secret logs)")
    print("  For real wallet creation, keep this machine offline.")
    print("=" * 66)

    # No debug, no interactive debugger, no reloader, single-threaded.
    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False,
        use_debugger=False,
        threaded=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
