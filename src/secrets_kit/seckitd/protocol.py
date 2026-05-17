"""
secrets_kit.seckitd.protocol

Request handlers for ``seckitd`` (daemon-side command validation).
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from pydantic import ValidationError
from secrets_kit.protocol.envelope import ProtocolVersionError, reject_unsupported_major
from secrets_kit.schemas.envelope import validate_transport_message_wrapper
from secrets_kit.seckitd.bridge import default_seckit_argv, run_sync_import_stdin
from secrets_kit.seckitd.ipc_redact import (
    relay_subprocess_tails_for_ipc,
    verbose_ipc_enabled,
)
from secrets_kit.seckitd.loopback_transport import LoopbackTransport
from secrets_kit.seckitd.runtime_log import runtime_log
from secrets_kit.seckitd.runtime_session import OutboundRuntimeCoordinator

SECKITD_PROTOCOL_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DaemonState:
    """In-memory state (Phase 5A receipt log; Phase 5D optional loopback runtime)."""

    agent_id: str = "seckitd"
    instance_id: str = "default"
    started_monotonic: float = field(default_factory=time.monotonic)
    started_iso: str = field(default_factory=_now_iso)
    outbound_log: List[Dict[str, Any]] = field(default_factory=list)
    runtime: OutboundRuntimeCoordinator = field(default_factory=OutboundRuntimeCoordinator)
    loopback: Optional[LoopbackTransport] = None

    def runtime_loopback_active(self) -> bool:
        return self.loopback is not None


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
    version_error = _check_request_protocol(request)
    if version_error is not None:
        return version_error
    op = str(request["op"])
    if op == "ping":
        return _ok(
            {
                "protocol_version": SECKITD_PROTOCOL_VERSION,
                "pid": os.getpid(),
                "agent_id": state.agent_id,
                "instance_id": state.instance_id,
                "pong": True,
            }
        )
    if op == "status":
        uptime = time.monotonic() - state.started_monotonic
        data: Dict[str, Any] = {
            "protocol_version": SECKITD_PROTOCOL_VERSION,
            "pid": os.getpid(),
            "agent_id": state.agent_id,
            "instance_id": state.instance_id,
            "started_at": state.started_iso,
            "uptime_seconds": round(uptime, 3),
            "outbound_artifacts_logged": len(state.outbound_log),
            "runtime_loopback_enabled": state.runtime_loopback_active(),
        }
        if state.loopback is not None:
            data["runtime"] = state.runtime.snapshot_status()
        else:
            data["runtime"] = None
        return _ok(data)
    if op == "sync_status":
        return _handle_sync_status(state=state)
    if op == "peer_outbound":
        return _handle_peer_outbound(state=state, request=request)
    if op == "peer_inbound_import":
        return _handle_peer_inbound_import(
            request=request,
            seckit_argv=seckit_argv,
            child_env=child_env,
        )
    return _err(f"unknown op: {op!r}")


def _handle_sync_status(*, state: DaemonState) -> Dict[str, Any]:
    """Return daemon status snapshot (uptime, loopback, coordinator)."""
    uptime = time.monotonic() - state.started_monotonic
    body: Dict[str, Any] = {
        "protocol_version": SECKITD_PROTOCOL_VERSION,
        "pid": os.getpid(),
        "agent_id": state.agent_id,
        "instance_id": state.instance_id,
        "started_at": state.started_iso,
        "uptime_seconds": round(uptime, 3),
        "outbound_artifacts_logged": len(state.outbound_log),
        "runtime_loopback_enabled": state.runtime_loopback_active(),
        "coordinator": state.runtime.snapshot_status() if state.loopback is not None else None,
    }
    if state.loopback is not None:
        body["loopback"] = {
            "connected": state.loopback.connected,
            "bytes_sent": state.loopback.bytes_sent,
            "chunks_delivered": len(state.loopback.chunks),
            "connect_calls": state.loopback.connect_calls,
            "disconnect_calls": state.loopback.disconnect_calls,
        }
    else:
        body["loopback"] = None
    return _ok(body)


def _handle_peer_outbound(*, state: DaemonState, request: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and enqueue an outbound peer payload into the runtime loopback."""
    allowed = {"op", "protocol_version", "payload_b64", "payload_type", "client_ref", "route_hint", "destination_peer"}
    extra = set(request.keys()) - allowed
    if extra:
        return _err(f"unexpected keys: {sorted(extra)}")
    payload_b64 = request.get("payload_b64")
    if not isinstance(payload_b64, str) or not payload_b64:
        return _err("peer_outbound requires non-empty payload_b64 string")
    client_ref = request.get("client_ref")
    if client_ref is not None and not isinstance(client_ref, str):
        return _err("client_ref must be a string when present")
    payload_type_m = request.get("payload_type")
    if payload_type_m is not None and not isinstance(payload_type_m, str):
        return _err("payload_type must be a string when present")
    route_hint = request.get("route_hint")
    if route_hint is not None and not isinstance(route_hint, str):
        return _err("route_hint must be a string when present")
    destination_peer = request.get("destination_peer")
    if destination_peer is not None and not isinstance(destination_peer, str):
        return _err("destination_peer must be a string when present")
    rk = (route_hint or destination_peer or "").strip() or "default"
    rid: str
    received_at: str
    if state.loopback is not None:
        try:
            item = state.runtime.enqueue(
                payload_b64=payload_b64,
                route_hint=rk,
                payload_type=payload_type_m,
                client_ref=client_ref,
            )
        except RuntimeError as exc:
            return _err(str(exc))
        rid = item.local_id
        received_at = item.received_at_iso
        runtime_log(
            category="ipc",
            event="peer_outbound_enqueued",
            route_hint=rk,
            local_id=rid,
            size_b64=len(payload_b64),
        )
    else:
        rid = str(uuid.uuid4())
        received_at = _now_iso()
    rec = {
        "received_at": received_at,
        "local_id": rid,
        "payload_type": payload_type_m,
        "size_b64": len(payload_b64),
        "client_ref": client_ref,
        "route_hint": rk,
        "destination_peer": destination_peer,
    }
    state.outbound_log.append(rec)
    return _ok(
        {
            "local_receipt": True,
            "local_id": rid,
            "received_at": received_at,
            "route_hint": rk,
            "note": "daemon accepted locally; remote delivery not implied",
        }
    )


def _handle_peer_inbound_import(
    *,
    request: Mapping[str, Any],
    seckit_argv: Optional[List[str]],
    child_env: Optional[Dict[str, str]],
) -> Dict[str, Any]:
    """Validate peer inbound wrapper and invoke ``seckit import`` for delivery."""
    allowed = {"op", "protocol_version", "wrapper", "payload_text", "signer"}
    extra = set(request.keys()) - allowed
    if extra:
        return _err(f"unexpected keys: {sorted(extra)}")
    wrapper = request.get("wrapper")
    if not isinstance(wrapper, dict):
        return _err("peer_inbound_import requires wrapper object")
    try:
        validate_transport_message_wrapper(wrapper)
    except ValidationError as exc:
        return _err(f"wrapper validation failed: {exc}")
    signer = request.get("signer")
    if not isinstance(signer, str) or not signer.strip():
        return _err("peer_inbound_import requires signer (peer alias)")
    payload_text = request.get("payload_text")
    if not isinstance(payload_text, str) or not payload_text:
        return _err("peer_inbound_import requires non-empty payload_text")
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


def _check_request_protocol(request: Mapping[str, Any]) -> Dict[str, Any] | None:
    """Reject unsupported major protocol versions when request declares one."""
    if "protocol_version" not in request:
        return None
    try:
        reject_unsupported_major(request.get("protocol_version"))
    except ProtocolVersionError as exc:
        return _err(str(exc))
    return None
