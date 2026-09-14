from __future__ import annotations

import json
import http.client
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from lifedb.cli import build_parser
from lifedb.auth import (
    MAX_API_TOKEN_BYTES,
    MIN_API_TOKEN_BYTES,
    bearer_token_matches,
    effective_ingest_sensitivity,
    effective_sensitivity_ceiling,
    validate_api_token,
)
from lifedb.index import rebuild_index
from lifedb.server import MAX_BODY_BYTES, LifeDBHandler, LifeDBServer
from lifedb.vault import ExternalIDConflictError, Vault


class LifeDBHTTPTestCase(unittest.TestCase):
    TOKEN = "correct-horse-battery-staple-for-lifedb-tests"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.vault = Vault(Path(self.temporary.name) / "vault")
        self.vault.init()
        self.server = LifeDBServer(
            ("127.0.0.1", 0),
            self.vault,
            api_token=self.TOKEN,
            sensitivity_ceiling="personal",
            principal="test-http-principal",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(
        self,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
        method: str | None = None,
    ) -> tuple[int, dict, object]:
        request_headers = dict(headers or {})
        if authenticated:
            request_headers.setdefault("Authorization", f"Bearer {self.TOKEN}")
        request = urllib.request.Request(
            self.base + path,
            data=body,
            headers=request_headers,
            method=method or ("POST" if body is not None else "GET"),
        )
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read().decode("utf-8"))
            return exc.code, payload, exc.headers
        with response:
            payload = json.loads(response.read().decode("utf-8"))
            return response.status, payload, response.headers

    def test_only_health_is_unauthenticated_and_security_headers_are_set(self) -> None:
        status, health, headers = self.request("/health", authenticated=False)
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers.get_content_type(), "application/json")

        status, _, headers = self.request("/v1/search?q=x", authenticated=False)
        self.assertEqual(status, 401)
        self.assertTrue(headers["WWW-Authenticate"].startswith("Bearer"))

        status, _, _ = self.request(
            "/v1/search?q=x", headers={"Authorization": "Bearer wrong"}
        )
        self.assertEqual(status, 401)

        status, _, _ = self.request("/unknown")
        self.assertEqual(status, 404)

    def test_context_json_is_strict_and_get_query_names_are_allowlisted(self) -> None:
        headers = {"Content-Type": "application/json"}
        status, _, _ = self.request(
            "/v1/context", body=b'{"query":"x","query":"y"}', headers=headers
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/context", body=b'{"query":NaN}', headers=headers
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request("/v1/search?q=x&unexpected=1")
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/evidence/00000000-0000-7000-8000-000000000000?unexpected=1"
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/context", body=b'{"query":"x","ignored":true}', headers=headers
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/rebuild?ignored=1", body=b""
        )
        self.assertEqual(status, 400)

    def test_health_rejects_request_bodies_and_unsupported_methods_report_405(self) -> None:
        status, _, _ = self.request(
            "/health", body=b"ignored", method="GET", authenticated=False
        )
        self.assertEqual(status, 400)

        status, _, headers = self.request("/v1/search?q=private", method="PUT")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET, HEAD")

    def test_unconfigured_token_fails_closed_but_health_remains_available(self) -> None:
        server = LifeDBServer(("127.0.0.1", 0), self.vault, api_token=None)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(base + "/health", timeout=3) as response:
                self.assertEqual(response.status, 200)
            request = urllib.request.Request(
                base + "/v1/search?q=x",
                headers={"Authorization": f"Bearer {self.TOKEN}"},
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(raised.exception.code, 503)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_search_and_context_cannot_raise_the_server_ceiling(self) -> None:
        public = self.vault.ingest(
            b"shared ceiling marker",
            source_kind="test",
            sensitivity="public",
            media_type="text/plain",
        )
        personal = self.vault.ingest(
            b"shared ceiling marker",
            source_kind="test",
            sensitivity="personal",
            media_type="text/plain",
        )
        sensitive = self.vault.ingest(
            b"shared ceiling marker",
            source_kind="test",
            sensitivity="sensitive",
            media_type="text/plain",
        )
        rebuild_index(self.vault)

        status, value, _ = self.request(
            "/v1/search?q=ceiling&limit=10&sensitivity_ceiling=restricted"
        )
        self.assertEqual(status, 200)
        ids = {item["source_id"] for item in value["results"]}
        self.assertIn(public["id"], ids)
        self.assertIn(personal["id"], ids)
        self.assertNotIn(sensitive["id"], ids)

        status, value, _ = self.request(
            "/v1/search?q=ceiling&limit=10&sensitivity_ceiling=public"
        )
        self.assertEqual(status, 200)
        ids = {item["source_id"] for item in value["results"]}
        self.assertIn(public["id"], ids)
        self.assertNotIn(personal["id"], ids)

        body = json.dumps(
            {
                "query": "ceiling",
                "client": "display-label",
                "sensitivity_ceiling": "restricted",
                "budget_chars": 999_999,
            }
        ).encode()
        status, pack, _ = self.request(
            "/v1/context", body=body, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(pack["authorization"]["principal"], "test-http-principal")
        self.assertEqual(pack["authorization"]["sensitivity_ceiling"], "personal")
        self.assertEqual(pack["authorization"]["destination"], "local-http")
        self.assertEqual(pack["authorization"]["purpose"], "assistant")
        self.assertEqual(pack["budget"]["budget_chars"], 24_000)

    def test_context_accepts_empty_query_for_core_and_continuity(self) -> None:
        status, pack, _ = self.request(
            "/v1/context",
            body=json.dumps({"query": ""}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(pack["query"], "")
        self.assertTrue(pack["core"])

    def test_evidence_lookup_is_strict_effective_and_hides_unauthorized_ids(self) -> None:
        personal = self.vault.ingest(
            b"personal", source_kind="test", sensitivity="personal"
        )
        sensitive = self.vault.ingest(
            b"sensitive", source_kind="test", sensitivity="sensitive"
        )
        self.vault.append_event(
            "payload-redacted",
            actor="process:test",
            target=personal["id"],
            data={"reason": "test redaction"},
        )

        status, record, _ = self.request(f"/v1/evidence/{personal['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(record["payload"]["state"], "redacted")

        status, _, _ = self.request(
            f"/v1/evidence/{personal['id']}?sensitivity_ceiling=public"
        )
        self.assertEqual(status, 404)

        status, _, _ = self.request(f"/v1/evidence/{sensitive['id']}")
        self.assertEqual(status, 404)
        status, _, _ = self.request("/v1/evidence/not-a-uuid")
        self.assertEqual(status, 400)
        status, _, _ = self.request(f"/v1/evidence/{personal['id']}/extra")
        self.assertEqual(status, 400)

    def test_bad_limits_json_content_length_and_sensitivity_are_400(self) -> None:
        status, _, _ = self.request("/v1/search?q=x&limit=NaN")
        self.assertEqual(status, 400)
        status, _, _ = self.request("/v1/search?q=x&sensitivity_ceiling=unknown")
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/context", body=b"{", headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/context",
            body=json.dumps({"query": "x", "limit": False}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/rebuild",
            body=b"",
            headers={"Content-Length": "not-an-integer"},
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/ingest",
            body=b"",
            headers={"Content-Length": str(MAX_BODY_BYTES + 1)},
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/ingest",
            body=b"unknown label",
            headers={"X-LifeDB-Sensitivity": "secret"},
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/ingest",
            body=b"oversized length header",
            headers={"Content-Length": "9" * 5000},
        )
        self.assertEqual(status, 400)

    def test_ingest_assigns_transport_authority_and_supports_external_id(self) -> None:
        status, record, _ = self.request(
            "/v1/ingest",
            body=b"captured over HTTP",
            headers={
                "Content-Type": "text/plain",
                "X-LifeDB-Source": "self-asserted-superuser",
                "X-LifeDB-External-ID": "remote-event-42",
                "X-LifeDB-Sensitivity": "public",
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(record["source"]["kind"], "http")
        self.assertEqual(record["sensitivity"], "personal")
        self.assertEqual(record["source"]["external_id"], "remote-event-42")
        self.assertEqual(
            record["source"]["metadata"]["authenticated_principal"],
            "test-http-principal",
        )
        self.assertEqual(
            record["source"]["metadata"]["asserted_kind"],
            "self-asserted-superuser",
        )

        status, raised, _ = self.request(
            "/v1/ingest",
            body=b"conservatively classified",
            headers={"X-LifeDB-Sensitivity": "sensitive"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(raised["sensitivity"], "sensitive")

    def test_ingest_external_id_conflict_stays_backward_compatible(self) -> None:
        status, record, _ = self.request(
            "/v1/ingest",
            body=b"typed http replay",
            headers={
                "Content-Type": "text/plain",
                "X-LifeDB-External-ID": "typed-http-event-9",
                "X-LifeDB-Sensitivity": "public",
            },
        )
        self.assertEqual(status, 201)

        status, replay, _ = self.request(
            "/v1/ingest",
            body=b"typed http replay",
            headers={
                "Content-Type": "text/plain",
                "X-LifeDB-External-ID": "typed-http-event-9",
                "X-LifeDB-Sensitivity": "public",
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(replay["id"], record["id"])

        status, conflict, _ = self.request(
            "/v1/ingest",
            body=b"typed http replay changed",
            headers={
                "Content-Type": "text/plain",
                "X-LifeDB-External-ID": "typed-http-event-9",
                "X-LifeDB-Sensitivity": "public",
            },
        )
        self.assertEqual(status, 400)

        with self.assertRaises(ExternalIDConflictError):
            self.vault.ingest(
                b"typed http replay changed",
                source_kind="http",
                source_metadata={
                    "transport": "http",
                    "authenticated_principal": "test-http-principal",
                },
                external_id="typed-http-direct-9",
            )
            self.vault.ingest(
                b"typed http replay changed again",
                source_kind="http",
                source_metadata={
                    "transport": "http",
                    "authenticated_principal": "test-http-principal",
                },
                external_id="typed-http-direct-9",
            )

    def test_internal_exception_details_are_not_returned(self) -> None:
        with mock.patch(
            "lifedb.server.search", side_effect=RuntimeError("do-not-leak-this")
        ):
            status, value, _ = self.request("/v1/search?q=x")
        self.assertEqual(status, 500)
        self.assertEqual(value, {"error": "internal server error"})
        self.assertNotIn("do-not-leak-this", json.dumps(value))

    def test_evidence_content_expansion_and_authorization(self) -> None:
        record = self.vault.ingest(
            "alpha😀omega".encode(),
            source_kind="test",
            media_type="text/plain",
            sensitivity="personal",
        )
        status, expanded, headers = self.request(
            f"/v1/evidence/{record['id']}/content?material=raw&max_chars=6"
        )
        self.assertEqual(status, 200)
        self.assertEqual(expanded["text"], "alpha😀")
        self.assertTrue(expanded["truncated"])
        self.assertTrue(expanded["untrusted"])
        self.assertEqual(expanded["evidence_id"], record["id"])
        self.assertEqual(int(headers["Content-Length"]), len((json.dumps(expanded, ensure_ascii=False, indent=2) + "\n").encode()))

        representation_digest, _ = self.vault.store_object("OCR本文".encode())
        representation_event = self.vault.append_event(
            "representation.added",
            actor="process:test",
            target=record["id"],
            data={
                "representation": {
                    "role": "ocr",
                    "object": f"sha256:{representation_digest}",
                    "media_type": "text/plain",
                    "created_at": "2026-09-02T00:00:00Z",
                    "producer": {"by": "process:test", "version": "1"},
                }
            },
        )
        status, represented, _ = self.request(
            f"/v1/evidence/{record['id']}/content?material=representation%3Aocr"
        )
        self.assertEqual(status, 200)
        self.assertEqual(represented["role"], "ocr")
        self.assertEqual(represented["text"], "OCR本文")
        self.assertEqual(
            represented["watermark"]["event_sequence"],
            representation_event["sequence"],
        )

        raised = self.vault.ingest(
            b"classified by later event",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        self.vault.append_event(
            "audit.noted",
            actor="process:test",
            target=raised["id"],
            sensitivity="sensitive",
            data={},
        )
        status, hidden, _ = self.request(
            f"/v1/evidence/{raised['id']}/content?material=raw"
        )
        self.assertEqual(status, 404)
        self.assertEqual(hidden["code"], "evidence_not_found")

    def test_content_route_maps_unavailable_binary_and_invalid_utf8_to_stable_errors(self) -> None:
        redacted = self.vault.ingest(
            b"redacted", source_kind="test", media_type="text/plain"
        )
        self.vault.append_event(
            "payload.redacted",
            actor="process:test",
            target=redacted["id"],
            data={"reason": "test"},
        )
        binary = self.vault.ingest(
            b"\x89PNG\r\n\x1a\n", source_kind="test", media_type="image/png"
        )
        invalid = self.vault.ingest(
            b"bad\xffutf8", source_kind="test", media_type="text/plain"
        )
        cases = (
            (redacted["id"], 409, "material_unavailable"),
            (binary["id"], 415, "unsupported_media_type"),
            (invalid["id"], 422, "invalid_utf8"),
        )
        for evidence_id, expected_status, expected_code in cases:
            with self.subTest(code=expected_code):
                status, response, _ = self.request(
                    f"/v1/evidence/{evidence_id}/content?material=raw"
                )
                self.assertEqual(status, expected_status)
                self.assertEqual(response["code"], expected_code)

    def test_content_route_rejects_digest_traversal_duplicates_and_unknown_parameters(self) -> None:
        record = self.vault.ingest(
            b"content", source_kind="test", media_type="text/plain"
        )
        base = f"/v1/evidence/{record['id']}/content"
        bad_queries = (
            f"material={record['payload']['object']}",
            "material=representation%3A..%2Fraw",
            "material=raw&material=raw",
            "material=raw&max_chars=2&max_chars=3",
            "material=raw&object=sha256%3A" + "a" * 64,
            "max_chars=3",
        )
        for query in bad_queries:
            with self.subTest(query=query):
                status, _, _ = self.request(f"{base}?{query}")
                self.assertEqual(status, 400)

    def test_head_matches_get_headers_for_all_get_routes(self) -> None:
        record = self.vault.ingest(
            b"head content", source_kind="test", media_type="text/plain"
        )
        paths = (
            ("/health", False),
            ("/v1/search?q=head", True),
            (f"/v1/evidence/{record['id']}", True),
            (f"/v1/evidence/{record['id']}/content?material=raw&max_chars=4", True),
        )
        for path, authenticated in paths:
            with self.subTest(path=path):
                headers = {}
                if authenticated:
                    headers["Authorization"] = f"Bearer {self.TOKEN}"
                get_request = urllib.request.Request(self.base + path, headers=headers)
                with urllib.request.urlopen(get_request, timeout=3) as response:
                    get_status = response.status
                    get_length = response.headers["Content-Length"]
                    self.assertEqual(len(response.read()), int(get_length))
                head_request = urllib.request.Request(
                    self.base + path, headers=headers, method="HEAD"
                )
                with urllib.request.urlopen(head_request, timeout=3) as response:
                    self.assertEqual(response.status, get_status)
                    self.assertEqual(response.headers["Content-Length"], get_length)
                    self.assertEqual(response.read(), b"")

        head_context = urllib.request.Request(
            self.base + "/v1/context",
            headers={"Authorization": f"Bearer {self.TOKEN}"},
            method="HEAD",
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(head_context, timeout=3)
        self.assertEqual(raised.exception.code, 405)
        self.assertEqual(raised.exception.headers["Allow"], "POST")
        self.assertEqual(raised.exception.read(), b"")

    def test_post_media_type_empty_body_routes_and_unread_body_framing(self) -> None:
        status, _, _ = self.request("/v1/context", body=b"{}")
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/v1/context",
            body=b"{}",
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        self.assertEqual(status, 200)
        for media_type in (
            "application/json; boundary=not-json",
            "application/json; charset=iso-8859-1",
            "application/json; charset=utf-8; charset=utf-8",
        ):
            status, _, _ = self.request(
                "/v1/context", body=b"{}", headers={"Content-Type": media_type}
            )
            self.assertEqual(status, 400)
        for path in ("/v1/rebuild", "/v1/validate"):
            status, _, _ = self.request(path, body=b"not-empty")
            self.assertEqual(status, 400)

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.request(
            "POST",
            "/unknown",
            body=b"unread",
            headers={
                "Authorization": f"Bearer {self.TOKEN}",
                "Content-Length": "6",
            },
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 404)
        response.read()
        self.assertTrue(response.will_close)
        connection.close()

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.request(
            "PUT",
            "/v1/search?q=x",
            body=b"unread",
            headers={"Authorization": f"Bearer {self.TOKEN}"},
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 405)
        self.assertEqual(response.headers["Allow"], "GET, HEAD")
        response.read()
        self.assertTrue(response.will_close)
        connection.close()

    def test_duplicate_control_headers_and_get_transfer_encoding_fail_closed(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.putrequest("POST", "/v1/context")
        connection.putheader("Authorization", f"Bearer {self.TOKEN}")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Type", "text/plain")
        connection.putheader("Content-Length", "2")
        connection.endheaders(b"{}")
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        self.assertTrue(response.will_close)
        connection.close()

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.putrequest("GET", "/health")
        connection.putheader("Content-Length", "0")
        connection.putheader("Content-Length", "0")
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        self.assertTrue(response.will_close)
        connection.close()

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.putrequest("GET", "/health")
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders(b"0\r\n\r\n")
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        self.assertTrue(response.will_close)
        connection.close()


class AuthorizationUnitTest(unittest.TestCase):
    def test_bearer_authentication_uses_compare_digest(self) -> None:
        with mock.patch("lifedb.auth.hmac.compare_digest", return_value=True) as compare:
            self.assertTrue(bearer_token_matches("Bearer supplied", "configured"))
        compare.assert_called_once_with(b"supplied", b"configured")

    def test_bearer_authentication_rejects_unpaired_surrogates_without_leaking_them(self) -> None:
        supplied = "Bearer " + ("x" * MIN_API_TOKEN_BYTES) + "\ud800"
        configured = "x" * MIN_API_TOKEN_BYTES + "\ud800"
        self.assertFalse(bearer_token_matches(supplied, "x" * MIN_API_TOKEN_BYTES))
        self.assertFalse(bearer_token_matches("Bearer " + ("x" * MIN_API_TOKEN_BYTES), configured))

    def test_effective_ceiling_only_narrows(self) -> None:
        self.assertEqual(effective_sensitivity_ceiling("personal"), "personal")
        self.assertEqual(
            effective_sensitivity_ceiling("personal", "restricted"), "personal"
        )
        self.assertEqual(effective_sensitivity_ceiling("personal", "public"), "public")
        with self.assertRaises(ValueError):
            effective_sensitivity_ceiling("personal", "secret")

        self.assertEqual(effective_ingest_sensitivity("personal", "public"), "personal")
        self.assertEqual(
            effective_ingest_sensitivity("personal", "sensitive"), "sensitive"
        )

    def test_server_profile_is_validated_before_binding(self) -> None:
        with self.assertRaisesRegex(ValueError, "sensitivity ceiling"):
            LifeDBServer(
                ("127.0.0.1", 0),
                mock.sentinel.vault,
                sensitivity_ceiling="secret",
            )
        with self.assertRaisesRegex(ValueError, "principal"):
            LifeDBServer(("127.0.0.1", 0), mock.sentinel.vault, principal="")
        with self.assertRaisesRegex(ValueError, "ingestion sensitivity floor"):
            LifeDBServer(
                ("127.0.0.1", 0),
                mock.sentinel.vault,
                ingest_sensitivity_floor="secret",
            )

    def test_api_token_requires_safe_utf8_byte_length_and_rejects_whitespace(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 32 UTF-8 bytes"):
            LifeDBServer(("127.0.0.1", 0), mock.sentinel.vault, api_token="x" * 31)
        self.assertEqual(
            validate_api_token("x" * MIN_API_TOKEN_BYTES),
            "x" * MIN_API_TOKEN_BYTES,
        )

        # The limit is byte-based: eleven three-byte characters are accepted
        # while ten are below the 32-byte minimum.
        with self.assertRaisesRegex(ValueError, "at least 32 UTF-8 bytes"):
            LifeDBServer(("127.0.0.1", 0), mock.sentinel.vault, api_token="あ" * 10)
        self.assertEqual(validate_api_token("あ" * 11), "あ" * 11)

        with self.assertRaisesRegex(ValueError, "at most 4096 UTF-8 bytes"):
            LifeDBServer(
                ("127.0.0.1", 0),
                mock.sentinel.vault,
                api_token="x" * (MAX_API_TOKEN_BYTES + 1),
            )
        with self.assertRaisesRegex(ValueError, "must not contain whitespace"):
            LifeDBServer(("127.0.0.1", 0), mock.sentinel.vault, api_token="x" * 31 + " ")
        secret = "x" * MIN_API_TOKEN_BYTES + "\ud800"
        with self.assertRaisesRegex(ValueError, "must be valid UTF-8") as raised:
            validate_api_token(secret)
        self.assertNotIn(secret, str(raised.exception))

    def test_empty_and_unset_api_tokens_remain_unconfigured(self) -> None:
        self.assertIsNone(validate_api_token(None))
        self.assertIsNone(validate_api_token(""))

    def test_access_log_does_not_include_query_text(self) -> None:
        handler = LifeDBHandler.__new__(LifeDBHandler)
        handler.path = "/v1/search?q=do-not-log-this&token=also-secret"
        handler.command = "GET"
        handler.log_message = mock.Mock()

        handler.log_request(200)

        call = handler.log_message.call_args
        self.assertIsNotNone(call)
        self.assertEqual(call.args[:4], ("%s %s %s", "GET", "/v1/search", 200))
        self.assertNotIn("do-not-log-this", repr(call))

    def test_context_query_validation_allows_only_explicit_empty_mode(self) -> None:
        self.assertEqual(LifeDBHandler._query("", allow_empty=True), "")
        with self.assertRaises(ValueError):
            LifeDBHandler._query("")

    def test_cli_serve_exposes_ingestion_floor(self) -> None:
        args = build_parser().parse_args(
            ["serve", "--ingest-sensitivity-floor", "sensitive"]
        )
        self.assertEqual(args.ingest_sensitivity_floor, "sensitive")

    def test_metadata_route_applies_object_alias_floor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vault = Vault(Path(temporary) / "vault")
            vault.init()
            restricted = vault.ingest(
                b"server metadata restricted alias",
                source_kind="test",
                media_type="text/plain",
                sensitivity="restricted",
            )
            public = vault.ingest(
                b"public metadata",
                source_kind="test",
                media_type="application/octet-stream",
                sensitivity="public",
            )
            vault.append_event(
                "representation-added",
                actor="extractor:test",
                target=public["id"],
                data={
                    "role": "derived-text",
                    "object": restricted["payload"]["object"],
                    "media_type": "text/plain",
                    "created_at": "2026-09-01T00:00:00Z",
                    "producer": {"by": "extractor:test", "version": "1"},
                },
                sensitivity="public",
            )

            class Headers:
                def get_all(self, name, failobj=None):
                    return []

            handler = LifeDBHandler.__new__(LifeDBHandler)
            handler.path = f"/v1/evidence/{public['id']}"
            handler.headers = Headers()
            handler.server = SimpleNamespace(
                vault=vault,
                api_token="token",
                sensitivity_ceiling="public",
                principal="test-principal",
                destination="local",
                purpose="test",
                ingest_sensitivity_floor="public",
            )
            result = {}
            handler._authorize = lambda **kwargs: True
            handler._validate_get_framing = lambda: None
            handler._send_json_payload = lambda status, payload, **kwargs: result.update(
                status=int(status), value=json.loads(payload)
            )
            handler._handle_get()

            self.assertEqual(result["status"], 404)


if __name__ == "__main__":
    unittest.main()
