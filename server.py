import time
from flask import Flask, request, jsonify

app = Flask(__name__)
relay_buffer = []


def purge_expired():
    """Messages older than the 30-minute retention window are dropped."""
    now = time.time()
    relay_buffer[:] = [m for m in relay_buffer if (now - m.get("server_ts", 0)) <= 1800]


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
    after = request.args.get("after", 0, type=int)
    current = relay_buffer[after:]
    current_payloads = current[-10:] if len(current) > 0 else []
    return jsonify({
        "messages": current_payloads,
        "last_index": len(relay_buffer),
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
