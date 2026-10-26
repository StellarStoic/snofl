from flask import Flask, request, jsonify, redirect, send_from_directory
import json
import html
import sqlite3
import os
import string
import secrets
import time
import urllib.parse
from datetime import datetime, timedelta

from nip05proof import validate_name, verify_proof
import logging
import logging.handlers

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "urls.db")
BLOCKLIST_FILE = os.path.join(os.path.dirname(__file__), "blockedUrls.json")

# Paths to .well-known directories
NOSTR_JSON_PATH = os.path.join(BASE_DIR, '.well-known', 'nostr.json')
LNURLP_DIR = os.path.join(BASE_DIR, '.well-known', 'lnurlp')

# The log used to live in the web root under a logger set to CRITICAL while every event in this file is
# written at INFO — so it recorded nothing the app said, and grew to 102 MB on whatever the server
# printed to stderr instead. Out of the web root, at a level that actually records, and self-rotating so
# it cannot fill a disk again.
LOG_DIR = os.environ.get("SNOFL_LOG_DIR", "/var/log/snofl")
LOG_FILE = os.path.join(LOG_DIR, "blocked_urls.log")
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 3

try:
    os.makedirs(LOG_DIR, exist_ok=True)
    _log_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS)
    _log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[_log_handler])
except OSError as exc:  # a log that cannot be opened must not stop the app from serving
    logging.basicConfig(level=logging.INFO)
    logging.warning("file logging unavailable (%s); events go to stderr", exc)

def log_event(message):
    """Log events to the log file."""
    logging.info(message)

# Initialize database
def init_db():
    db_dir = os.path.dirname(DB_FILE)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)  # Create the directory if it doesn't exist
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS urls (
            short      TEXT PRIMARY KEY,
            original   TEXT,
            timestamp  TEXT DEFAULT CURRENT_TIMESTAMP,
            visits     INTEGER DEFAULT 0,
            last_accessed TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # Ensure the new columns exist for existing databases
    cursor.execute("PRAGMA table_info(urls)")
    columns = [col[1] for col in cursor.fetchall()]
    if "visits" not in columns:
        cursor.execute("ALTER TABLE urls ADD COLUMN visits INTEGER DEFAULT 0")
    if "last_accessed" not in columns:
        cursor.execute("ALTER TABLE urls ADD COLUMN last_accessed TEXT DEFAULT CURRENT_TIMESTAMP")
        
    conn.commit()
    conn.close()

SHORT_CODE_ALPHABET = string.ascii_letters + string.digits
SHORT_CODE_LENGTH = 7


def generate_short_url(cursor, attempts=8):
    """A random code, checked against the table.

    This was `md5(url)[:6]`: derived from the URL, so anyone who knew or guessed the destination could
    work out the code, the whole space was small enough to walk, and two different URLs could land on
    the same six characters — the first insert wins and the second URL's visitors are sent to the first
    one's destination. Random codes from `secrets` are unguessable and unpredictable; the loop is the
    collision check, and seven characters of base62 is ~3.5e12 of them.
    """
    for _ in range(attempts):
        code = ''.join(secrets.choice(SHORT_CODE_ALPHABET) for _ in range(SHORT_CODE_LENGTH))
        if not cursor.execute("SELECT 1 FROM urls WHERE short = ?", (code,)).fetchone():
            return code
    raise RuntimeError("could not find a free short code after %d attempts" % attempts)

# The zap record every new name gets. Unchanged content: this is what a wallet shows a donor.
LNURLP_TEMPLATE = {
        "callback": "https://livingroomofsatoshi.com/api/v1/lnurl/payreq/2ef0b1ef-ec6e-43b0-ba78-90f7c59cc95f",
        "maxSendable": 100000000000,
        "minSendable": 1000,
        "metadata": [
            ["text/plain", "Thank you for supporting the snofl.com project with your Zaps. Your generosity helps drive this initiative forward!"],
            ["text/identifier", "latterswiss19@walletofsatoshi.com"]
        ],
        "commentAllowed": 32,
        "tag": "payRequest",
        "allowsNostr": True,
        "nostrPubkey": "be1d89794bf92de5dd64c1e60f6a2c70c140abac9932418fee30c5c637fe9479"
    }

@app.route('/shorten', methods=['POST'])
def shorten_url():
    data = request.json
    original_url = data.get("url")
    if not original_url:
        return jsonify({"error": "URL is required"}), 400

    # Check if the URL already exists in the database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT short FROM urls WHERE original = ?", (original_url,))
    existing_short = cursor.fetchone()

    if existing_short:
        conn.close()
        return jsonify({"short_url": f"https://snofl.com/{existing_short[0]}"}), 200

    # A short link nobody else holds: random, unique, and checked before it is written.
    code = generate_short_url(cursor)
    cursor.execute("INSERT INTO urls (short, original) VALUES (?, ?)", (code, original_url))
    conn.commit()
    conn.close()

    return jsonify({"short_url": f"https://snofl.com/{code}"}), 201

def load_blocked_urls():
    """Load blocked URLs from the external JSON file."""
    try:
        with open(BLOCKLIST_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []  # Return an empty list if file is missing

def get_warning_url(reason):
    """Format the new custom warning URL with the reason encoded."""
    base_url = "https://snofl.com/index.html"
    
    # Combine the reason with the additional message
    full_message = (
        f"You've been redirected because the original link was blocked for violating our terms of service. "
        f"Reason: {reason}"
        f"Forget about it, move on with your life, go outside, and touch grass!"
        f"https://media1.tenor.com/m/hBb-jRuH95gAAAAd/touch-grass-grass.gif"
    )
    
    params = {
        "f": "1",
        "b": "#c14949",
        "t": "Attention!",
        "s": "This is not the page you are looking for.",
        "p": full_message,  # Use the combined message here
        "h": "ohbummerbummerohoh"
    }
    
    return f"{base_url}?{urllib.parse.urlencode(params)}"

@app.route('/deleted-urls', methods=['GET'])
def get_deleted_urls():
    """One deleted link, asked for by its code — not the whole record of removals."""
    short = (request.args.get('short') or '').strip()
    if not short:
        return jsonify({"error": "a 'short' code is required"}), 400

    try:
        with open(os.path.join(BASE_DIR, "deletedURLs.json"), "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "URL not found"}), 404

    for entry in data:
        if entry.get("short") == short:
            return jsonify(entry)
    return jsonify({"error": "URL not found"}), 404

@app.route('/<short>', methods=['GET'])
def redirect_short_url(short):
    # **Step 1: Ignore WebSocket requests**
    if short.startswith("wss:") or short.endswith(".com") or short.endswith(".net") or short.endswith(".org"):
        log_event(f"🛑 Ignored WebSocket or external request: {short}")
        return jsonify({"error": "Invalid request"}), 400

    blocked_urls = load_blocked_urls()

    # **Step 2: Block shortened URLs before querying the database**
    for entry in blocked_urls:
        if entry.get("shortened") and entry["shortened"].lower() not in ["none", ""]:
            if f"https://snofl.com/{short}" == entry["shortened"]:
                log_event(f"🚫 Blocked shortened URL: {short}")
                return redirect(get_warning_url(entry["reason"]), code=302)

    # **Step 3: Query database for full URLs**
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT original, visits FROM urls WHERE short = ?", (short,))
    result = cursor.fetchone()

    if result:
        original_url = html.unescape(result[0])
        visits = result[1] if result[1] is not None else 0

        # **Normalize encoding properly**
        normalized_original = urllib.parse.unquote_plus(original_url).strip()

        log_event(f"🔍 Checking Original URL: {original_url}")
        log_event(f"🔍 Normalized Original URL: {normalized_original}")

        for entry in blocked_urls:
            blocked_url = urllib.parse.unquote_plus(entry["full_url"]).strip()

            log_event(f"🔍 Checking against blocklist (Normalized): {blocked_url}")

            # **Exact Full URL Match**
            if normalized_original == blocked_url:
                log_event(f"🚫 Blocked full URL match: {original_url}")
                conn.close()
                return redirect(get_warning_url(entry["reason"]), code=302)

            # **Step 4: Check if 'p=' parameter matches**
            parsed_original = urllib.parse.urlparse(original_url)
            original_params = dict(urllib.parse.parse_qsl(parsed_original.query))
            blocked_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(entry["full_url"]).query))

            # Normalize `p=` parameter encoding
            if "p" in blocked_params and urllib.parse.unquote_plus(blocked_params["p"]) == urllib.parse.unquote_plus(original_params.get("p", "")):
                log_event(f"🚫 Blocked due to 'p=' parameter match: {original_url}")
                conn.close()
                return redirect(get_warning_url(entry["reason"]), code=302)

        # **Step 5: If not blocked, update visit count and redirect**
        cursor.execute(
            "UPDATE urls SET visits = ?, last_accessed = CURRENT_TIMESTAMP WHERE short = ?",
            (visits + 1, short)
        )
        conn.commit()
        conn.close()

        log_event(f"✅ Allowed URL: {original_url}")
        return redirect(original_url, code=302)

    # **Step 6: Handle invalid short URLs**
    conn.close()
    log_event(f"❌ Invalid short URL: {short}")

    # A one-segment request that is not a known code lands here, and this used to try the docroot as a
    # file name — which handed out whatever sits beside the pages: the SQLite database the redirects
    # are read from, app.py itself, the log. nginx serves the real static files before Flask ever sees
    # them, so the only thing this fallback can still usefully do is nothing. Judge it by the same
    # allowlist as the catch-all route, and 404 everything else.
    name = os.path.basename(short)
    if (not name.startswith('.')
            and os.path.splitext(name)[1].lower() in PUBLIC_EXTENSIONS
            and os.path.isfile(os.path.join(BASE_DIR, name))):
        try:
            return send_from_directory(BASE_DIR, short)
        except FileNotFoundError:
            pass

    return jsonify({"error": "URL not found"}), 404

# get visitor counter and time of last visit
@app.route('/visits', methods=['GET'])
def get_visits():
    """The numbers for one short link, asked for by its code.

    This used to answer with the whole table, paginated only by whatever `per_page` the caller
    named, so anyone could walk every shortcut and the destination each one points at. The page that
    asks for this (urlchckr.html) looks a code up one at a time, so one code is what it answers.
    """
    short = (request.args.get('short') or '').strip()
    if not short:
        return jsonify({"error": "a 'short' code is required"}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT short, original, timestamp, visits, last_accessed FROM urls WHERE short = ?",
        (short,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "URL not found"}), 404

    short, original, timestamp, visits, last_accessed = row
    now = datetime.utcnow()
    deletion_time_limit = timedelta(days=2100)  # URLs expire after 2100 days

    # Parse robustly: a row whose timestamp does not match the format should not 500 the whole route.
    try:
        created_at = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        created_at = None

    if created_at:
        age = now - created_at
        url_age = (f"{age.days//365}Y:{(age.days%365)//30}M:{age.days%30}D:"
                   f"{age.seconds//3600}H:{(age.seconds%3600)//60}M")
        time_remaining = (created_at + deletion_time_limit) - now
        if time_remaining.total_seconds() > 0:
            time_till_deletion = (f"{time_remaining.days//365}Y:{(time_remaining.days%365)//30}M:"
                                  f"{time_remaining.days%30}D:{time_remaining.seconds//3600}H")
        else:
            time_till_deletion = "EXPIRED"
    else:
        url_age = "unknown"
        time_till_deletion = "unknown"

    return jsonify({
        "short": short,
        "original": original,
        "timestamp": timestamp,
        "visits": visits,
        "last_accessed": last_accessed,
        "url_age": url_age,
        "time_till_deletion": time_till_deletion
    })
    
# What the site may hand out from its own directory. Everything else in there — the SQLite database
# the redirects are read from, app.py itself, the log — was reachable only because those files live
# beside the pages and nginx's try_files serves whatever exists on disk. nginx denies the same names;
# this is the second lock, for anything that reaches the app around the proxy.
PUBLIC_EXTENSIONS = {'.html', '.css', '.js', '.json', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                     '.webp', '.ico', '.webmanifest', '.txt', '.xml', '.woff', '.woff2'}


@app.route('/<path:filename>', methods=['GET'])
def serve_static_file(filename):
    name = os.path.basename(filename)
    if name.startswith('.') or os.path.splitext(name)[1].lower() not in PUBLIC_EXTENSIONS:
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(BASE_DIR, filename)

@app.route('/', methods=['GET'])
def home():
    return send_from_directory('.', 'index.html')

# A registration writes files, so it is metered per address. In memory on purpose: a restart clearing the
# counter is better than a counter that needs a database of its own.
NIP05_MAX_PER_HOUR = 10
NIP05_HITS = {}


def _rate_limited(ip):
    now = time.time()
    hits = [t for t in NIP05_HITS.get(ip, []) if now - t < 3600]
    hits.append(now)
    NIP05_HITS[ip] = hits
    return len(hits) > NIP05_MAX_PER_HOUR


@app.route('/.well-known/nostr.json', methods=['POST'])
def update_nostr_json():
    """Register NIP-05 names — with proof that the caller holds each key.

    Two things were wrong with this route. It took `{"names": {name: pubkey}}` from anyone, so any
    stranger could claim a name on this domain; and the name went straight into
    `os.path.join(LNURLP_DIR, name)`, which made a body of `{"names": {"../../x": "..."}}` a write
    primitive anywhere the process could write.

    A NIP-05 name is a promise that a pubkey belongs to a name here, so the only honest authorisation is
    a signature by that pubkey: the client signs `snofl-nip05:<name>:<pubkey>:<created_at>` and the
    server verifies it (BIP-340, in nip05proof.py) before anything is written. Names are then restricted
    to a lowercase character class that cannot contain a separator, and the store is written atomically.
    """
    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "?").split(",")[0].strip()
    if _rate_limited(ip):
        return jsonify({"error": "too many registrations from this address, try again later"}), 429

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("names"), dict) or not data["names"]:
        return jsonify({"error": "expected {\"names\": {name: pubkey}, \"proofs\": {name: {sig, created_at}}}"}), 400

    proofs = data.get("proofs")
    if not isinstance(proofs, dict):
        return jsonify({"error": ("every name needs a proof: sign the string "
                                  "'snofl-nip05:<name>:<pubkey>:<created_at>' with the key being claimed, "
                                  "and send {sig, created_at} beside the name")}), 400

    now = int(time.time())
    claims = {}
    for raw_name, raw_pubkey in data["names"].items():
        name = raw_name.strip().lower() if isinstance(raw_name, str) else raw_name
        pubkey = raw_pubkey.strip().lower() if isinstance(raw_pubkey, str) else raw_pubkey
        problem = validate_name(name) or verify_proof(name, pubkey, proofs.get(name), now)
        if problem:
            return jsonify({"error": "%r: %s" % (name, problem)}), 403
        claims[name] = pubkey

    try:
        with open(NOSTR_JSON_PATH, "r") as handle:
            existing_data = json.load(handle)
    except FileNotFoundError:
        existing_data = {"names": {}, "relays": {}}
    existing_data.setdefault("names", {})

    for name in claims:
        if name in existing_data["names"]:
            return jsonify({"error": "Name '%s' already exists and cannot be overwritten." % name}), 409

    existing_data["names"].update(claims)

    # Written beside the real file and moved into place: a half-written store is unreadable to every
    # client asking who a name belongs to.
    tmp_path = NOSTR_JSON_PATH + ".tmp"
    with open(tmp_path, "w") as handle:
        json.dump(existing_data, handle, indent=2)
    os.replace(tmp_path, NOSTR_JSON_PATH)

    os.makedirs(LNURLP_DIR, exist_ok=True)
    for name in claims:
        lnurlp_path = os.path.join(LNURLP_DIR, name)
        if os.path.exists(lnurlp_path):
            continue
        with open(lnurlp_path, "w") as lnurlp_file:
            json.dump(LNURLP_TEMPLATE, lnurlp_file, indent=2)

    log_event("nip05 registered: " + ", ".join(sorted(claims)))
    return jsonify({"registered": sorted(claims)}), 201

# LNURL get data
@app.route('/.well-known/lnurlp/<name>', methods=['GET'])
def serve_lnurlp(name):
    try:
        lnurlp_path = os.path.join(LNURLP_DIR, name)
        
        if not os.path.exists(lnurlp_path):
            return jsonify({"error": "LNURLP file not found"}), 404
        
        # Read and return the contents of the LNURLP file
        with open(lnurlp_path, 'r') as f:
            lnurlp_content = f.read()

        # Return as application/json
        return lnurlp_content, 200, {'Content-Type': 'application/json'}

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# nostr.json GET for nip05
@app.route('/.well-known/nostr.json', methods=['GET'])
def serve_nostr_json():
    try:
        if not os.path.exists(NOSTR_JSON_PATH):
            return jsonify({"error": "nostr.json not found"}), 404

        with open(NOSTR_JSON_PATH, 'r') as f:
            nostr_content = f.read()

        # Return the nostr.json content as application/json
        return nostr_content, 200, {'Content-Type': 'application/json'}

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(port=3000)




# if __name__ == '__main__':
#     init_db() # Initialize the database
#     app.run(debug=True, host='127.0.0.1', port=5500)