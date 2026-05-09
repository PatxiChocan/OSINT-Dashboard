from flask import Blueprint, jsonify, request
from app.routes.auth import role_required
from app.models import ROLE_ADMIN, ROLE_ANALYST
import json

stix_validate_bp = Blueprint("stix_validate", __name__)


@stix_validate_bp.route("/api/validate-stix", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def validate_stix():
    bundle = request.get_json(silent=True)
    if not bundle:
        return jsonify({"valid": False, "errors": ["No se recibió un bundle JSON válido"], "warnings": []}), 400

    try:
        from stix2validator import validate_string, ValidationOptions
        opts = ValidationOptions(strict=False)
        raw = json.dumps(bundle)
        results = validate_string(raw, opts)

        errors = []
        warnings = []
        for msg in results.errors:
            errors.append(str(msg))
        for msg in results.warnings:
            warnings.append(str(msg))

        return jsonify({
            "valid": results.is_valid,
            "errors": errors,
            "warnings": warnings,
            "object_count": len(bundle.get("objects", [])),
        })
    except Exception as e:
        return jsonify({"valid": False, "errors": [f"Error interno del validador: {e}"], "warnings": []}), 500
