from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

import yaml

from .candidates import CandidateStore
from .context import build_context
from .expansion import ROLE_RE as EXPANSION_ROLE_RE, expand_evidence
from .index import index_watermark, rebuild_index, search
from .retention import RetentionManager
from .runtime import reset_runtime
from .server import serve
from .validation import validate_vault
from .vault import Vault, parse_time
from .markdown import BoundedStringTimestampSafeLoader
from .storage import read_bounded_regular_file, strict_json_loads
from .secrets import assert_no_credentials
from .evidence import _validate_actor


ROLE_RE = EXPANSION_ROLE_RE
MEDIA_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+(?:\s*;.*)?$")
MAX_RAW_INPUT_BYTES = 64 * 1024 * 1024
MAX_MAPPING_INPUT_BYTES = 1 * 1024 * 1024


def _stdin_bytes(limit: int) -> bytes:
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    value = stream.read(limit + 1)
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError("stdin could not be read as bytes")
    return bytes(value)


def _vault(args: argparse.Namespace) -> Vault:
    return Vault(args.vault or os.environ.get("LIFEDB_VAULT", "/data"))


def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _bytes(path_value: str) -> tuple[bytes, str]:
    if path_value == "-":
        data = _stdin_bytes(MAX_RAW_INPUT_BYTES)
        if len(data) > MAX_RAW_INPUT_BYTES:
            raise ValueError(f"stdin exceeds the maximum size of {MAX_RAW_INPUT_BYTES} bytes")
        return data, "stdin"
    path = Path(path_value)
    return read_bounded_regular_file(path, max_bytes=MAX_RAW_INPUT_BYTES), path.name


def _mapping(path_value: str) -> dict[str, Any]:
    if path_value == "-":
        payload = _stdin_bytes(MAX_MAPPING_INPUT_BYTES)
        if len(payload) > MAX_MAPPING_INPUT_BYTES:
            raise ValueError(
                f"stdin mapping exceeds the maximum size of {MAX_MAPPING_INPUT_BYTES} bytes"
            )
    else:
        payload = read_bounded_regular_file(path_value, max_bytes=MAX_MAPPING_INPUT_BYTES)
    try:
        text = payload.decode("utf-8")
        loaded = yaml.load(text, Loader=BoundedStringTimestampSafeLoader)
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError, MemoryError) as exc:
        raise ValueError("input is not valid bounded YAML/JSON") from exc
    if not isinstance(loaded, dict):
        raise ValueError("input must contain a JSON or YAML mapping")
    return loaded


def _source_metadata(value: str) -> dict[str, Any]:
    try:
        payload = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("--source-metadata must be valid UTF-8 JSON") from exc
    if len(payload) > MAX_MAPPING_INPUT_BYTES:
        raise ValueError("--source-metadata exceeds the 1 MiB limit")
    try:
        loaded = strict_json_loads(payload, max_bytes=MAX_MAPPING_INPUT_BYTES)
    except ValueError as exc:
        raise ValueError("--source-metadata must be a strict JSON object") from exc
    if not isinstance(loaded, dict):
        raise ValueError("--source-metadata must be a JSON object")
    return loaded


def _context_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("query")
    parser.add_argument("--client", default="cli")
    parser.add_argument("--principal", default="local-cli")
    parser.add_argument("--session")
    parser.add_argument("--workspace")
    parser.add_argument("--destination", default="local")
    parser.add_argument("--purpose", default="assistant")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--sensitivity-ceiling", default=None)
    parser.add_argument("--budget-chars", type=int, default=None)
    parser.add_argument("--core-chars", type=int, default=None)
    parser.add_argument(
        "--continuity-chars", type=int, default=None
    )
    parser.add_argument("--relevant-chars", type=int, default=None)
    parser.add_argument("--markdown", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lifedb")
    parser.add_argument("--vault", help="vault path; defaults to LIFEDB_VAULT or /data")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", help="initialize a durable vault")
    validate = commands.add_parser("validate", help="validate schemas, references, and objects")
    validate.add_argument("--no-hashes", action="store_true")
    commands.add_parser("rebuild", help="rebuild the disposable SQLite projections")
    commands.add_parser("doctor", help="validate the vault and report projection freshness")
    runtime = commands.add_parser("runtime", help="manage disposable runtime projections")
    runtime_commands = runtime.add_subparsers(dest="runtime_command", required=True)
    runtime_reset = runtime_commands.add_parser(
        "reset", help="delete and recreate the runtime projection"
    )
    runtime_reset.add_argument("--confirm", required=True, help="must be DELETE-RUNTIME")

    ingest = commands.add_parser("ingest", help="ingest a file or stdin as immutable Evidence")
    ingest.add_argument("path", help="path or - for stdin")
    ingest.add_argument("--source", default="manual")
    ingest.add_argument("--source-uri")
    ingest.add_argument("--external-id")
    ingest.add_argument("--source-metadata", help="JSON object")
    ingest.add_argument("--media-type", default="application/octet-stream")
    ingest.add_argument("--filename")
    ingest.add_argument("--retention", default="durable")
    ingest.add_argument("--sensitivity", default="personal")
    ingest.add_argument("--kind", default="artifact")
    ingest.add_argument("--captured-at")

    evidence = commands.add_parser("evidence", help="inspect or augment Evidence")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_show = evidence_commands.add_parser("show", help="show an effective Evidence view")
    evidence_show.add_argument("id")
    evidence_show.add_argument("--base", action="store_true", help="show the sealed capture only")
    representation = evidence_commands.add_parser(
        "add-representation", help="append a retained derived representation"
    )
    representation.add_argument("id", help="target Evidence UUIDv7")
    representation.add_argument("path", help="representation file or - for stdin")
    representation.add_argument("--role", required=True)
    representation.add_argument("--media-type", required=True)
    representation.add_argument("--actor", required=True)
    representation.add_argument("--producer-version", required=True)
    representation.add_argument("--created-at")
    evidence_expand = evidence_commands.add_parser(
        "expand", help="expand authorized textual Evidence material"
    )
    evidence_expand.add_argument("id", help="Evidence UUIDv7")
    evidence_expand.add_argument("--material", required=True, help="raw or representation:<role>")
    evidence_expand.add_argument("--max-chars", type=int, required=True)
    evidence_expand.add_argument("--sensitivity-ceiling", default="personal")

    search_parser = commands.add_parser("search", help="search the disposable lexical index")
    search_parser.add_argument("query")
    search_parser.add_argument("--limit", type=int, default=10)
    search_parser.add_argument("--sensitivity-ceiling", default="personal")

    context = commands.add_parser("context", help="build an authorized, budgeted Context Pack")
    _context_arguments(context)

    candidate = commands.add_parser("candidate", help="manage manual Canon Claim proposals")
    candidate_commands = candidate.add_subparsers(dest="candidate_command", required=True)
    candidate_create = candidate_commands.add_parser("create", help="create a pending Candidate")
    candidate_create.add_argument("target_document_id")
    candidate_create.add_argument("claim", help="JSON/YAML Claim proposal path, or -")
    candidate_create.add_argument("--actor", required=True)
    candidate_create.add_argument("--sensitivity", default="personal")
    candidate_list = candidate_commands.add_parser("list", help="list Candidate projections")
    candidate_list.add_argument("--status", choices=["pending", "promoted", "rejected"])
    candidate_show = candidate_commands.add_parser("show", help="show one Candidate")
    candidate_show.add_argument("id")
    candidate_promote = candidate_commands.add_parser("promote", help="promote through Canon transaction")
    candidate_promote.add_argument("id")
    candidate_promote.add_argument("--actor", required=True)
    candidate_reject = candidate_commands.add_parser("reject", help="reject a pending Candidate")
    candidate_reject.add_argument("id")
    candidate_reject.add_argument("--actor", required=True)
    candidate_reject.add_argument("--reason", required=True)

    canon = commands.add_parser("canon", help="inspect or compensate Canon history")
    canon_commands = canon.add_subparsers(dest="canon_command", required=True)
    canon_rollback = canon_commands.add_parser("rollback", help="create a compensating rollback transaction")
    canon_rollback.add_argument("transaction_id")
    canon_rollback.add_argument("--actor", required=True)
    canon_recover = canon_commands.add_parser("recover", help="reconcile interrupted Canon transactions")
    canon_recover.add_argument("--actor", default="process:lifedb-canon-recovery")

    retention = commands.add_parser("retention", help="preview or explicitly apply raw-payload eviction")
    retention_commands = retention.add_subparsers(dest="retention_command", required=True)
    retention_commands.add_parser("preview", help="write a dry-run proposal under runtime/")
    retention_commands.add_parser("recover", help="repair interrupted retention transactions")
    retention_apply = retention_commands.add_parser(
        "apply", help="apply one exact preview after revalidation"
    )
    retention_apply.add_argument("plan_id")
    retention_apply.add_argument("--confirm", required=True, help="exact preview confirmation digest")
    retention_apply.add_argument("--actor", required=True)
    retention_set = retention_commands.add_parser(
        "set", help="append an explicit Evidence retention-class change"
    )
    retention_set.add_argument("evidence_id")
    retention_set.add_argument("retention_class", metavar="class")
    retention_set.add_argument("--actor", required=True)
    retention_set.add_argument("--reason", required=True)

    server = commands.add_parser("serve", help="run the authenticated HTTP API")
    server.add_argument("--bind", default=os.environ.get("LIFEDB_SERVER_BIND", "127.0.0.1"))
    server.add_argument("--port", type=int, default=int(os.environ.get("LIFEDB_PORT", "7331")))
    server.add_argument(
        "--sensitivity-ceiling",
        default=os.environ.get("LIFEDB_SENSITIVITY_CEILING", "personal"),
    )
    server.add_argument(
        "--ingest-sensitivity-floor",
        default=os.environ.get("LIFEDB_INGEST_SENSITIVITY_FLOOR", "personal"),
    )
    return parser


def _context(vault: Vault, args: argparse.Namespace) -> dict[str, Any]:
    return build_context(
        vault,
        args.query,
        client=args.client,
        principal=args.principal,
        session=args.session,
        workspace=args.workspace,
        destination=args.destination,
        purpose=args.purpose,
        limit=args.limit,
        sensitivity_ceiling=args.sensitivity_ceiling,
        budget_chars=args.budget_chars,
        core_chars=args.core_chars,
        continuity_chars=args.continuity_chars,
        relevant_chars=args.relevant_chars,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    vault = _vault(args)
    try:
        if args.command == "init":
            _print(vault.init())
            return 0
        if args.command == "validate":
            report = validate_vault(vault.root, verify_hashes=not args.no_hashes)
            _print(report.as_dict())
            return 0 if report.valid else 1
        if args.command == "rebuild":
            _print(rebuild_index(vault))
            return 0
        if args.command == "doctor":
            report = validate_vault(vault.root)
            _print({"validation": report.as_dict(), "watermark": index_watermark(vault)})
            return 0 if report.valid else 1
        if args.command == "runtime" and args.runtime_command == "reset":
            _print(reset_runtime(vault, confirmation=args.confirm))
            return 0
        if args.command == "ingest":
            data, inferred_filename = _bytes(args.path)
            metadata = _source_metadata(args.source_metadata) if args.source_metadata else None
            _print(
                vault.ingest(
                    data,
                    source_kind=args.source,
                    source_uri=args.source_uri,
                    external_id=args.external_id,
                    source_metadata=metadata,
                    media_type=args.media_type,
                    filename=args.filename or inferred_filename,
                    retention=args.retention,
                    sensitivity=args.sensitivity,
                    kind=args.kind,
                    captured_at=args.captured_at,
                )
            )
            return 0
        if args.command == "evidence":
            if args.evidence_command == "show":
                record = (
                    vault.load_evidence(args.id)
                    if args.base
                    else vault.effective_evidence(args.id)
                )
                if record is None:
                    raise ValueError("Evidence not found")
                _print(record)
                return 0
            if args.evidence_command == "add-representation":
                capture = vault.load_evidence(args.id)
                if capture is None:
                    raise ValueError("Evidence not found")
                if ROLE_RE.fullmatch(args.role) is None:
                    raise ValueError("--role must be a lowercase stable name")
                if len(args.role) > 127:
                    raise ValueError("--role exceeds the maximum length")
                try:
                    _validate_actor(args.actor, location="--actor")
                except ValueError as exc:
                    raise ValueError(str(exc)) from exc
                if not isinstance(args.producer_version, str) or not args.producer_version.strip() or len(args.producer_version) > 256:
                    raise ValueError("--producer-version must be a non-empty string of at most 256 characters")
                if any(unicodedata.category(character).startswith("C") for character in args.producer_version):
                    raise ValueError("--producer-version contains control characters")
                try:
                    assert_no_credentials(args.producer_version.encode("utf-8"))
                except ValueError as exc:
                    raise ValueError("--producer-version contains forbidden credentials") from exc
                media_type = args.media_type.partition(";")[0].strip().lower()
                if (
                    len(args.media_type) > 255
                    or MEDIA_TYPE_RE.fullmatch(args.media_type) is None
                    or not media_type
                    or any(ord(character) < 0x20 for character in args.media_type)
                ):
                    raise ValueError("--media-type must be a valid media type")
                try:
                    assert_no_credentials(args.media_type.encode("utf-8"))
                except ValueError as exc:
                    raise ValueError("--media-type contains forbidden credentials") from exc
                try:
                    created_at = parse_time(args.created_at) if args.created_at else parse_time(None)
                except (TypeError, ValueError, OverflowError) as exc:
                    raise ValueError("--created-at must be an RFC 3339 date-time") from exc
                data, _ = _bytes(args.path)
                # All representation metadata is validated before publishing
                # the immutable Object, so malformed input cannot orphan one.
                digest, _ = vault.store_object(data)
                representation_value = {
                    "role": args.role,
                    "object": f"sha256:{digest}",
                    "media_type": args.media_type,
                    "created_at": created_at.isoformat().replace("+00:00", "Z"),
                    "producer": {"by": args.actor, "version": args.producer_version},
                    "derived_from": capture.get("payload", {}).get("object"),
                }
                if representation_value["derived_from"] is None:
                    representation_value.pop("derived_from")
                event = vault.append_event(
                    "representation.added",
                    actor=args.actor,
                    target=args.id,
                    sensitivity=str(capture.get("sensitivity", "personal")),
                    data={"representation": representation_value},
                )
                _print(event)
                return 0
            if args.evidence_command == "expand":
                _print(
                    expand_evidence(
                        vault,
                        args.id,
                        material=args.material,
                        max_chars=args.max_chars,
                        sensitivity_ceiling=args.sensitivity_ceiling,
                    )
                )
                return 0
        if args.command == "search":
            _print(
                search(
                    vault,
                    args.query,
                    limit=args.limit,
                    sensitivity_ceiling=args.sensitivity_ceiling,
                )
            )
            return 0
        if args.command == "context":
            pack = _context(vault, args)
            if args.markdown:
                print(pack["rendered_markdown"], end="")
            else:
                _print(pack)
            return 0
        if args.command == "candidate":
            store = CandidateStore(vault)
            if args.candidate_command == "create":
                _print(
                    store.create(
                        target_document_id=args.target_document_id,
                        claim=_mapping(args.claim),
                        actor=args.actor,
                        sensitivity=args.sensitivity,
                    )
                )
            elif args.candidate_command == "list":
                _print(store.list(status=args.status))
            elif args.candidate_command == "show":
                _print(store.get(args.id))
            elif args.candidate_command == "promote":
                _print(store.promote(args.id, actor=args.actor))
            elif args.candidate_command == "reject":
                _print(store.reject(args.id, actor=args.actor, reason=args.reason))
            return 0
        if args.command == "canon":
            store = CandidateStore(vault)
            if args.canon_command == "rollback":
                _print(store.rollback(args.transaction_id, actor=args.actor))
                return 0
            if args.canon_command == "recover":
                _print(store.canon.recover_interrupted(actor=args.actor))
                return 0
        if args.command == "retention":
            manager = RetentionManager(vault)
            if args.retention_command == "preview":
                _print(manager.preview())
            elif args.retention_command == "recover":
                _print(manager.recover_interrupted())
            elif args.retention_command == "apply":
                _print(
                    manager.apply(
                        args.plan_id,
                        confirmation=args.confirm,
                        actor=args.actor,
                    )
                )
            elif args.retention_command == "set":
                _print(
                    manager.change(
                        args.evidence_id,
                        args.retention_class,
                        actor=args.actor,
                        reason=args.reason,
                    )
                )
            return 0
        if args.command == "serve":
            token = os.environ.get("LIFEDB_API_TOKEN")
            serve(
                vault,
                args.bind,
                args.port,
                api_token=token,
                sensitivity_ceiling=args.sensitivity_ceiling,
                ingest_sensitivity_floor=args.ingest_sensitivity_floor,
            )
            return 0
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"lifedb: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
