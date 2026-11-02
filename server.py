import time
from flask import Flask, request, jsonify, send_from_directory

# static_url_path='' → /manifest.json, /fernet.js and icons resolve from web/
app = Flask(__name__, static_folder='web', static_url_path='')
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
    current_payloads = current[-20:] if len(current) > 0 else []
    # last_index keeps the client dedup cursor working (no 2-second duplicates)
    return jsonify({"messages": current_payloads, "last_index": len(relay_buffer)})


if __name__ == '__main__':
    # Runs the network handler in secure mode to unlock camera/microphone permissions
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'), debug=False)
