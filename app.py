from flask import Flask, render_template, jsonify
import threading
from sniffer import start_sniffing, captured_packets, alerts

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/packets")
def get_packets():
    return jsonify(captured_packets)

@app.route("/alerts")
def get_alerts():
    return jsonify(alerts)

if __name__ == "__main__":
    t = threading.Thread(target=start_sniffing, daemon=True)
    t.start()

    app.run(host="0.0.0.0", port=5000, debug=True)
