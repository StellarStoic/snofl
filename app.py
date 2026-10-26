from flask import Flask, request, jsonify, redirect, send_from_directory
import json
import html
import sqlite3
import hashlib
import os
import sys
import random
import string
import urllib.parse
from datetime import datetime, timedelta
import logging

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "urls.db")
BLOCKLIST_FILE = os.path.join(os.path.dirname(__file__), "blockedUrls.json")

# Paths to .well-known directories
NOSTR_JSON_PATH = os.path.join(BASE_DIR, '.well-known', 'nostr.json')
LNURLP_DIR = os.path.join(BASE_DIR, '.well-known', 'lnurlp')

LOG_FILE = os.path.join(os.path.dirname(__file__), "blocked_urls.log")

# **Setup logging**
logging.basicConfig(filename=LOG_FILE, level=logging.CRITICAL, format="%(asctime)s - %(message)s")

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

def generate_short_url():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=6))

@app.route('/shorten', methods=['POST'])
def shorten_url():
    data = request.json
    original_url = data.get("url")
    if not original_url:
        return jsonify({"error": "URL is required"}), 400

    # Generate a consistent hash for the original URL
    url_hash = hashlib.md5(original_url.encode()).hexdigest()[:6]

    # Check if the URL already exists in the database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT short FROM urls WHERE original = ?", (original_url,))
    existing_short = cursor.fetchone()

    if existing_short:
        conn.close()
        return jsonify({"short_url": f"https://snofl.com/{existing_short[0]}"}), 200

    # If no existing short link, create a new one
    cursor.execute("INSERT INTO urls (short, original) VALUES (?, ?)", (url_hash, original_url))
    conn.commit()
    conn.close()

    return jsonify({"short_url": f"https://snofl.com/{url_hash}"}), 201

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

    try:
        return send_from_directory('.', short)
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

@app.route('/.well-known/nostr.json', methods=['POST'])
def update_nostr_json():
    try:
        data = request.json
        if 'names' not in data:
            return jsonify({"error": "Invalid data format"}), 400
        
        # Read existing nostr.json (if exists)
        try:
            with open(NOSTR_JSON_PATH, 'r') as f:
                existing_data = json.load(f)
        except FileNotFoundError:
            existing_data = {"names": {}}
            
        # Overwrite Protection - Check if name exists
        for name, pubkey in data['names'].items():
            if name in existing_data['names']:
                return jsonify({"error": f"Name '{name}' already exists and cannot be overwritten."}), 409

        # Update nostr.json with new names/pubkeys
        existing_data['names'].update(data['names'])

        # Write back to nostr.json
        with open(NOSTR_JSON_PATH, 'w') as f:
            json.dump(existing_data, f, indent=2)

        # Create LNURLP file for each new name
        for name, pubkey in data['names'].items():
            lnurlp_content = {
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
            # Ensure lnurlp directory exists
            os.makedirs(LNURLP_DIR, exist_ok=True)

            lnurlp_path = os.path.join(LNURLP_DIR, name)
            
            # Overwrite Protection - Check if LNURLP file exists
            if os.path.exists(lnurlp_path):
                return jsonify({"error": f"LNURLP for '{name}' already exists."}), 409
            
            with open(lnurlp_path, 'w') as lnurlp_file:
                json.dump(lnurlp_content, lnurlp_file, indent=2)

        return jsonify({"message": "nostr.json and lnurlp files updated successfully."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

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