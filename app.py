from flask import Flask, render_template, jsonify, request
from scanner.scan_manager import run_full_scan

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.json.get("target")
    tcp_start = int(request.json.get("tcp_start", 1))
    tcp_end = int(request.json.get("tcp_end", 1024))

    result = run_full_scan(
        target=target,
        tcp_start=tcp_start,
        tcp_end=tcp_end
    )
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
