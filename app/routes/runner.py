from flask import Blueprint, request, Response
from app.services.command_service import run_command, is_valid_command
import json

runner = Blueprint("runner", __name__)

@runner.route("/run", methods=["POST"])
def run():
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "").strip()

    is_valid, error = is_valid_command(cmd)
    if not is_valid:
        return Response(error, status=400)

    def generate():
        for item in run_command(cmd):
            yield f"data: {json.dumps(item)}\n\n"

    return Response(generate(), mimetype="text/event-stream")