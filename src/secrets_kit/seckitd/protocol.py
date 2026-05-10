"""Request handlers for ``seckitd`` (daemon-side command validation)."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from pydantic import ValidationError

from secrets_kit.schemas.envelope import validate_transport_message_wrapper
from secrets_kit.seckitd.bridge import default_seckit_argv, run_sync_import_stdin
from secrets_kit.seckitd.ipc_redact import relay_subprocess_tails_for_ipc, verbose_ipc_enabled


SECKITD_PROTOCOL_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DaemonState:
    """Minimal in-memory state (Phase 5A — no persistent queue)."""

    started_monotonic: float = field(default_factory=time.monotonic)
    started_iso: str = field(default_factory=_now_iso)
    outbound_log: List[Dict[str, Any]] = field(default_factory=list)


def handle_request(
    *,
    state: DaemonState,
    request: Mapping[str, Any],
    seckit_argv: Optional[List[str]] = None,
    child_env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Dispatch one validated JSON request; return response object (not yet framed)."""
    if not isinstance(request.get("op"), str):
        return _err("missing or invalid op")
    op = str(request["op"])
    if op == "ping":
        return _ok(
            {
                "protocol_version": SECKITD_PROTOCOL_VERSION,
                "pid": os.getpid(),
                "pong": True,
            }
        )
    if op == "status":
        uptime = time.monotonic() - state.started_monotonic
        return _ok(
            {
                "protocol_version": SECKITD_PROTOCOL_VERSION,
                "pid": os.getpid(),
                "started_at": state.started_iso,
                "uptime_seconds": round(uptime, 3),
                "outbound_artifacts_logged": len(state.outbound_log),
            }
        )
    if op == "submit_outbound":
        return _handle_submit_outbound(state=state, request=request)
    if op == "relay_inbound":
        return _handle_relay_inbound(
            request=request,
            seckit_argv=seckit_argv,
            child_env=child_env,
        )
    return _err(f"unknown op: {op!r}")


def _handle_submit_outbound(*, state: DaemonState, request: Mapping[str, Any]) -> Dict[str, Any]:
    allowed = {"op", "payload_b64", "payload_type", "client_ref"}
    extra = set(request.keys()) - allowed
    if extra:
        return _err(f"unexpected keys: {sorted(extra)}")
    payload_b64 = request.get("payload_b64")
    if not isinstance(payload_b64, str) or not payload_b64:
        return _err("submit_outbound requires non-empty payload_b64 string")
    client_ref = request.get("client_ref")
    if client_ref is not None and not isinstance(client_ref, str):
        return _err("client_ref must be a string when present")
    payload_type_m = request.get("payload_type")
    if payload_type_m is not None and not isinstance(payload_type_m, str):
        return _err("payload_type must be a string when present")
    rid = str(uuid.uuid4())
    rec = {
        "received_at": _now_iso(),
        "local_id": rid,
        "payload_type": payload_type_m,
        "size_b64": len(payload_b64),
        "client_ref": client_ref,
    }
    state.outbound_log.append(rec)
    return _ok(
        {
            "local_receipt": True,
            "local_id": rid,
            "received_at": rec["received_at"],
            "note": "daemon accepted locally; remote delivery not implied",
        }
    )


def _handle_relay_inbound(
    *,
    request: Mapping[str, Any],
    seckit_argv: Optional[List[str]],
    child_env: Optional[Dict[str, str]],
) -> Dict[str, Any]:
    allowed = {"op", "wrapper", "payload_text", "signer"}
    extra = set(request.keys()) - allowed
    if extra:
        return _err(f"unexpected keys: {sorted(extra)}")
    wrapper = request.get("wrapper")
    if not isinstance(wrapper, dict):
        return _err("relay_inbound requires wrapper object")
    try:
        validate_transport_message_wrapper(wrapper)
    except ValidationError as exc:
        return _err(f"wrapper validation failed: {exc}")
    signer = request.get("signer")
    if not isinstance(signer, str) or not signer.strip():
        return _err("relay_inbound requires signer (peer alias)")
    payload_text = request.get("payload_text")
    if not isinstance(payload_text, str) or not payload_text:
        return _err("relay_inbound requires non-empty payload_text")
    argv = seckit_argv if seckit_argv is not None else default_seckit_argv()
    result = run_sync_import_stdin(
        bundle_text=payload_text,
        signer_alias=signer.strip(),
        seckit_argv=argv,
        env=child_env,
    )
    ok = result.returncode == 0
    stdout_tail, stderr_tail = relay_subprocess_tails_for_ipc(
        ok=ok,
        stdout=result.stdout,
        stderr=result.stderr,
        verbose_ipc=verbose_ipc_enabled(),
    )
    return _ok(
        {
            "seckit_exit_code": result.returncode,
            "seckit_ok": ok,
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
        }
    )


def _ok(data: Dict[str, Any]) -> Dict[str, Any]:
    return {"ok": True, "data": data}


def _err(message: str) -> Dict[str, Any]:
    return {"ok": False, "error": message}
