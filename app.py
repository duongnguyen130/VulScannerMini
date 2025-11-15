from flask import Flask, render_template, request, jsonify, Response
from scanner.scan_manager import run_full_scan, run_full_scan_streamed

app = Flask(__name__)


# -------------------------------
# UI Home Page
# -------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# -------------------------------
# Normal Scan
# -------------------------------
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid request"}), 400

    target = data.get("target")
    profile = data.get("profile", "quick").lower()
    tcp_start = int(data.get("tcp_start", 1))
    tcp_end = int(data.get("tcp_end", 1024))

    if not target:
        return jsonify({"error": "Target is required"}), 400

    # Run full scan and return results
    result = run_full_scan(
        target=target,
        tcp_start=tcp_start,
        tcp_end=tcp_end,
        profile=profile
    )

    return jsonify(result)


# -------------------------------
# Progress Streaming (SSE)
# -------------------------------
@app.route("/progress")
def progress():
    target = request.args.get("target")
    profile = request.args.get("profile", "quick").lower()
    tcp_start = int(request.args.get("tcp_start", 1))
    tcp_end = int(request.args.get("tcp_end", 1024))

    if not target:
        return Response("data: ERROR\n\n", mimetype="text/event-stream")

    def event_stream():
        for event in run_full_scan_streamed(target, tcp_start, tcp_end, profile):
            yield f"data: {event}\n\n"

    # Response for SSE
    return Response(event_stream(), mimetype="text/event-stream")


# -------------------------------
# Run App
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True, threaded=True)
