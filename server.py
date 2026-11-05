import time
from flask import Flask, request, jsonify, send_from_directory

# static_url_path='' → /manifest.json, /fernet.js and icons resolve from web/
app = Flask(__name__, static_folder='web', static_url_path='')
# Median-size guard: huge uploads (uncompressed camera base64) saturate the tunnel
# and the in-memory buffer. 4 MB compressed-JPEG payloads are well under this.
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
relay_buffer = []


def purge_expired():
    """Section 3: server-side copy of the 30-minute retention window."""
    now = time.time()
    relay_buffer[:] = [m for m in relay_buffer if (now - m.get('server_ts', 0)) <= 1800]


@app.route('/')
def index():
    return send_from_directory('web', 'index.html')


@app.route('/send', methods=['POST'])
def handle_send():
    data = request.json
    if data:
        if len(data.get('payload', '')) > 4_500_000:
            return jsonify({"status": "too_large"}), 413
        data['server_ts'] = time.time()
        relay_buffer.append(data)
    return jsonify({"status": "delivered"})


@app.route('/get', methods=['GET'])
def handle_get():
    purge_expired()
    after = request.args.get('after', 0, type=int)
    # Cursor rewind safety: a stale cursor (relay restarted / purged) replays from index 0
    # so messages that arrived between restart and the client's resync are never lost.
    if after < 0 or after > len(relay_buffer):
        after = 0
    current = relay_buffer[after:]
    # Size-aware delivery window: hand out an in-order prefix under ~300 KB per poll
    # (oversized items go alone). The cursor advances only as far as actually
    # delivered, so nothing is skipped — heavy queues simply drain over few polls.
    delivered = []
    total = 0
    last_delivered_idx = after
    for offset, m in enumerate(current):
        sz = len(m.get('payload', ''))
        if delivered and total + sz > 300_000:
            break
        delivered.append(m)
        total += sz
        last_delivered_idx = after + offset + 1
    # last_index keeps the client dedup cursor working (no 2-second duplicates)
    return jsonify({"messages": delivered, "last_index": last_delivered_idx})


@app.after_request
def add_cors_headers(resp):
    # The APK's WebView is cross-origin (serves the app from its own https://localhost
    # and calls the tunnel origin) — without these headers Chrome rejects every
    # request with "TypeError: fetch failed" before it ever reaches the route.
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    resp.headers['Access-Control-Max-Age'] = '300'
    return resp


if __name__ == '__main__':
    # PM_TLS=1 → local HTTPS mode (LAN, self-signed cert.pem/key.pem)
    # no PM_TLS → plain HTTP mode meant to sit behind a public TLS tunnel
    # (cloudflared / ngrok / serveo) with HTTPS terminated at the tunnel entry.
    import os
    if os.environ.get('PM_TLS'):
        app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'), debug=False)
    else:
        app.run(host='0.0.0.0', port=5000, debug=False)
