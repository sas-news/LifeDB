from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretFinding:
    detector: str


class SecretDetectedError(ValueError):
    """Raised before bytes are persisted; matched material is never echoed."""

    def __init__(self, findings: list[SecretFinding]):
        names = ", ".join(sorted({finding.detector for finding in findings}))
        super().__init__(f"input looks like credential material ({names}); ingestion refused")
        self.findings = tuple(findings)


# These deliberately favor precision over recall. LifeDB cannot promise perfect
# detection for images, encrypted archives, or arbitrary binary formats.
PATTERNS = {
    "private-key": re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    ),
    "openai-api-key": re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b"),
    "github-token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "aws-access-key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "slack-token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "generic-bearer": re.compile(
        rb"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/-]{24,}={0,2}"
    ),
}


def detect_credentials(
    data: bytes, *, scan_limit: int | None = None
) -> list[SecretFinding]:
    if not isinstance(data, bytes):
        raise TypeError("secret scanner input must be bytes")
    if scan_limit is not None and (
        isinstance(scan_limit, bool) or not isinstance(scan_limit, int) or scan_limit < 0
    ):
        raise ValueError("secret scanner limit must be a non-negative integer or None")
    # Callers that pass bounded durable input use the complete representation
    # by default.  A smaller explicit limit remains available for deliberate
    # best-effort sampling of untrusted external streams.
    sample = data if scan_limit is None else data[:scan_limit]
    return [
        SecretFinding(detector=name)
        for name, pattern in PATTERNS.items()
        if pattern.search(sample) is not None
    ]


def assert_no_credentials(data: bytes) -> None:
    findings = detect_credentials(data)
    if findings:
        raise SecretDetectedError(findings)
