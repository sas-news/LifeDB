from __future__ import annotations

import re

SOURCE_RE = re.compile(r"[^a-z0-9._-]+")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SOURCE_KIND_LENGTH = 128
MAX_URI_LENGTH = 8192
MAX_FILENAME_LENGTH = 255
MAX_EXTERNAL_ID_LENGTH = 512
MAX_SOURCE_METADATA_BYTES = 1 * 1024 * 1024
MAX_VAULT_METADATA_BYTES = 1 * 1024 * 1024
DURABLE_TOP_LEVEL = (
    "canon", "evidence", "objects", "quarantine", "policies", "schemas",
    "migrations", "runtime",
)
