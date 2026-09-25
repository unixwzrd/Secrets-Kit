"""Protocol-level objects and canonical serialization helpers."""

from secrets_kit.protocol.envelope import (
    CANONICAL_ENVELOPE_VERSION,
    ENVELOPE_TYPE_TRANSACTION,
    CanonicalEnvelope,
    EnvelopeValidationError,
    build_transaction_envelope,
    canonical_envelope_bytes,
    canonical_envelope_dict,
    parse_envelope_bytes,
    parse_envelope_mapping,
    transaction_payload,
)
from secrets_kit.protocol.envelope_signing import (
    ENVELOPE_SIGNATURE_ALGORITHM,
    ENVELOPE_SIGNATURE_VERSION,
    EnvelopeSignatureError,
    sign_envelope,
    signing_public_key_fingerprint,
    verify_envelope_signature,
)
from secrets_kit.protocol.payload_codec import (
    ENCRYPTED_CODEC_MODE,
    PLAINTEXT_CODEC_MODE,
    EnvelopePayloadCodec,
    EnvelopePayloadCodecError,
    decode_envelope_payload,
    encrypted_envelope_payload_codec,
    plaintext_envelope_payload_codec,
)

__all__ = [
    "CANONICAL_ENVELOPE_VERSION",
    "ENVELOPE_TYPE_TRANSACTION",
    "CanonicalEnvelope",
    "EnvelopeValidationError",
    "build_transaction_envelope",
    "canonical_envelope_bytes",
    "canonical_envelope_dict",
    "parse_envelope_bytes",
    "parse_envelope_mapping",
    "transaction_payload",
    "ENCRYPTED_CODEC_MODE",
    "PLAINTEXT_CODEC_MODE",
    "EnvelopePayloadCodec",
    "EnvelopePayloadCodecError",
    "decode_envelope_payload",
    "encrypted_envelope_payload_codec",
    "plaintext_envelope_payload_codec",
    "ENVELOPE_SIGNATURE_ALGORITHM",
    "ENVELOPE_SIGNATURE_VERSION",
    "EnvelopeSignatureError",
    "sign_envelope",
    "signing_public_key_fingerprint",
    "verify_envelope_signature",
]
