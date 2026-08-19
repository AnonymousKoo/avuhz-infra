"""Safe runtime reason values; these mirror existing Slice 1 contract reason codes."""

from enum import StrEnum


class RuntimeReason(StrEnum):
    SCHEMA_UNSUPPORTED = "SCHEMA_UNSUPPORTED"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    FIELD_FORBIDDEN = "FIELD_FORBIDDEN"
    VERSION_REQUIRED = "VERSION_REQUIRED"
    AUTH_INVALID = "AUTH_INVALID"
    INTERNAL_INVARIANT_VIOLATION = "INTERNAL_INVARIANT_VIOLATION"
