"""Compatibility import path for local daemon framing helpers."""

from secrets_kit.transport.framing import MAX_FRAME_BYTES, FramingError, frame_json, parse_json_object, read_frame

__all__ = ["MAX_FRAME_BYTES", "FramingError", "frame_json", "parse_json_object", "read_frame"]

