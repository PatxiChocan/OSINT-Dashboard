from flask import Blueprint, request, Response, stream_with_context
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

        return Response(
            stream_with_context(error_stream()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    def generate():
        yield f"data: {json.dumps({'type': 'start', 'message': 'Ejecutando comando...', 'request_id': request_id})}\n\n"

        # Evento inicial extra para forzar arranque del stream en proxies/buffers
        yield f"data: {json.dumps({'type': 'heartbeat', 'message': 'stream-open', 'request_id': request_id})}\n\n"

        for item in run_command(cmd, request_id=request_id):
            yield f"data: {json.dumps(item)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@runner.route("/stop", methods=["POST"])
def stop():
    data = request.get_json(silent=True) or {}
    request_id = (data.get("request_id") or "").strip()

    if not request_id:
        return {"ok": False, "error": "request_id requerido"}, 400

    stopped = stop_command(request_id)
    return {"ok": stopped}