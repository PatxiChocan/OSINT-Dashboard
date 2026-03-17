from flask import Blueprint, request, Response
from app.services.command_service import run_command, is_valid_command, stop_command
import json
import uuid

runner = Blueprint("runner", __name__)


@runner.route("/run", methods=["POST"])
def run():
    data = request.get_json(silent=True) or {}
    cmd = (data.get("cmd") or "").strip()
    request_id = data.get("request_id") or str(uuid.uuid4())

    is_valid, error = is_valid_command(cmd)
    if not is_valid:
        def error_stream():
            yield f"data: {json.dumps({'type': 'error', 'message': error, 'request_id': request_id})}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'request_id': request_id})}\n\n"

        return Response(error_stream(), mimetype="text/event-stream")

    def generate():
        for item in run_command(cmd, request_id=request_id):
            yield f"data: {json.dumps(item)}\n\n"

    return Response(generate(), mimetype="text/event-stream")


@runner.route("/stop", methods=["POST"])
def stop():
    data = request.get_json(silent=True) or {}
    request_id = (data.get("request_id") or "").strip()

    if not request_id:
        return {"ok": False, "error": "request_id requerido"}, 400

    stopped = stop_command(request_id)
    return {"ok": stopped}