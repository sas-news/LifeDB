"""Failing-first boundary tests for the authenticated POST /v1/turns route."""

from __future__ import annotations

import http.client
import json
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from lifedb.server import MAX_BODY_BYTES, LifeDBServer
from lifedb.turns import MAX_TURN_REQUEST_BYTES
from lifedb.vault import Vault
from tests.turns_server_harness import TurnsServerHarness, build_turn_bytes


class TurnsServerTest(TurnsServerHarness):
    def test_create_and_identical_replay_share_one_evidence_id(self) -> None:
        body = build_turn_bytes("turn-001")
        status, record, _ = self.post_turn(body)
        self.assertEqual(status, 201)
        evidence_id = record.get("id")
        if not isinstance(evidence_id, str):
            self.fail("turn record id must be a string")
        self.assertEqual(record.get("kind"), "conversation")
        source = record.get("source")
        if not isinstance(source, dict):
            self.fail("turn record source must be an object")
        self.assertEqual(source.get("kind"), "opencode")
        self.assertEqual(record.get("sensitivity"), "personal")
        before = self.durable_counts()

        status, replay, _ = self.post_turn(body)
        self.assertEqual(status, 201)
        self.assertEqual(replay.get("id"), evidence_id)
        self.assertEqual(self.durable_counts(), before)

        get_request = urllib.request.Request(
            f"{self.base}/v1/evidence/{evidence_id}",
            headers={"Authorization": f"Bearer {self.TOKEN}"},
        )
        with urllib.request.urlopen(get_request, timeout=3) as response:
            self.assertEqual(response.status, 200)
            fetched: dict[str, object] = json.loads(response.read().decode("utf-8"))
        self.assertEqual(fetched.get("id"), evidence_id)

    def test_conflicting_text_is_409_without_growth_or_leak(self) -> None:
        changed_text = "A completely different assistant answer for conflict."
        self.assertEqual(self.post_turn(build_turn_bytes("turn-409"))[0], 201)
        before = self.durable_counts()
        status, conflict, _ = self.post_turn(
            build_turn_bytes("turn-409", assistant_text=changed_text)
        )
        self.assertEqual(status, 409)
        self.assertEqual(self.durable_counts(), before)
        self.assertNotIn(changed_text, json.dumps(conflict))

    def test_credential_material_is_422_without_growth_or_leak(self) -> None:
        credential = "sk-proj-abcdefghij1234567890XY"
        before = self.durable_counts()
        status, rejected, _ = self.post_turn(
            build_turn_bytes("turn-422", user_text=f"deploy with {credential} now")
        )
        self.assertEqual(status, 422)
        self.assertEqual(self.durable_counts(), before)
        self.assertNotIn(credential, json.dumps(rejected))

    def test_sensitivity_floor_is_raise_only(self) -> None:
        status, lowered, _ = self.post_turn(
            build_turn_bytes("turn-floor-low", sensitivity="public")
        )
        self.assertEqual(status, 201)
        self.assertEqual(lowered.get("sensitivity"), "personal")
        status, raised, _ = self.post_turn(
            build_turn_bytes("turn-floor-high", sensitivity="sensitive")
        )
        self.assertEqual(status, 201)
        self.assertEqual(raised.get("sensitivity"), "sensitive")

    def test_auth_matrix_401_503_and_health_open(self) -> None:
        status, _, headers = self.post_turn(build_turn_bytes("no-auth"), authenticated=False)
        self.assertEqual(status, 401)
        self.assertTrue(str(headers.get("WWW-Authenticate", "")).startswith("Bearer"))
        status, _, _ = self.post_turn(
            build_turn_bytes("bad-auth"), token="wrong-token-value-for-matrix-0000"
        )
        self.assertEqual(status, 401)

        bare = LifeDBServer(("127.0.0.1", 0), self.vault, api_token=None)
        thread = threading.Thread(target=bare.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{bare.server_port}/health") as ok:
                self.assertEqual(ok.status, 200)
            request = urllib.request.Request(
                f"http://127.0.0.1:{bare.server_port}/v1/turns",
                data=build_turn_bytes("unconfigured"),
                headers={
                    "Authorization": f"Bearer {self.TOKEN}",
                    "Content-Type": "application/json",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(raised.exception.code, 503)
        finally:
            bare.shutdown()
            bare.server_close()
            thread.join(timeout=2)

    def test_strict_json_unknown_fields_and_query_are_400(self) -> None:
        before = self.durable_counts()
        cases = (
            b'{"host":"opencode","host":"hermes"}',
            b'{"host":NaN}',
            b'{"host":"opencode"',
            b'["opencode"]',
            build_turn_bytes("unknown-field", model="m", extra="nope"),
        )
        for raw in cases:
            with self.subTest(raw=raw[:24]):
                status, _, _ = self.post_turn(raw)
                self.assertEqual(status, 400)
        status, _, _ = self.post_turn(
            build_turn_bytes("query-key"), path="/v1/turns?unexpected=1"
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.durable_counts(), before)

    def test_media_type_415_and_size_413(self) -> None:
        status, _, _ = self.post_turn(
            build_turn_bytes("media-plain"),
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(status, 415)
        status, _, _ = self.post_turn(
            build_turn_bytes("media-charset"),
            headers={"Content-Type": "application/json; charset=iso-8859-1"},
        )
        self.assertEqual(status, 415)
        status, _, _ = self.post_turn(
            build_turn_bytes("media-ok"),
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        self.assertEqual(status, 201)

        oversized = b'{"host":"opencode","pad":"' + b"x" * (MAX_TURN_REQUEST_BYTES + 1) + b'"}'
        status, too_large, _ = self.post_turn(oversized)
        self.assertEqual(status, 413)
        self.assertNotIn("xxxxx", json.dumps(too_large)[:200])

    def test_duplicate_headers_and_framing_fail_closed(self) -> None:
        body = build_turn_bytes("framing-dup")
        status, _, will_close = self.raw_turn(
            [
                ("Authorization", f"Bearer {self.TOKEN}"),
                ("Content-Type", "application/json"),
                ("Content-Type", "text/plain"),
            ],
            body,
        )
        self.assertEqual(status, 400)
        self.assertTrue(will_close)

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.putrequest("POST", "/v1/turns")
        connection.putheader("Authorization", f"Bearer {self.TOKEN}")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders(b"5\r\nhello\r\n0\r\n\r\n")
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        connection.close()

        status, _, _ = self.post_turn(
            body, headers={"Content-Length": "not-an-integer"}
        )
        self.assertEqual(status, 400)

    def test_duplicate_auth_and_length_and_giant_declaration(self) -> None:
        body = build_turn_bytes("framing-auth-dup")
        status, raw, will_close = self.raw_turn(
            [
                ("Authorization", f"Bearer {self.TOKEN}"),
                ("Authorization", "Bearer wrong-token-value-for-matrix-0000"),
                ("Content-Type", "application/json"),
            ],
            body,
        )
        self.assertEqual(status, 401)
        self.assertTrue(will_close)
        self.assertNotIn(self.TOKEN, raw.decode("utf-8"))

        before = self.durable_counts()
        small = build_turn_bytes("framing-length-dup")
        status, _, length_closed = self.raw_turn(
            [
                ("Authorization", f"Bearer {self.TOKEN}"),
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(small))),
                ("Content-Length", str(len(small))),
            ],
            small,
        )
        self.assertEqual(status, 400)
        self.assertTrue(length_closed)

        giant = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        giant.putrequest("POST", "/v1/turns")
        giant.putheader("Authorization", f"Bearer {self.TOKEN}")
        giant.putheader("Content-Type", "application/json")
        giant.putheader("Content-Length", str(MAX_BODY_BYTES + 1))
        giant.endheaders(build_turn_bytes("framing-giant"))
        giant_response = giant.getresponse()
        self.assertEqual(giant_response.status, 413)
        giant_response.read()
        giant.close()
        self.assertEqual(self.durable_counts(), before)

    def test_wrong_methods_report_allow_post(self) -> None:
        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                request = urllib.request.Request(
                    self.base + "/v1/turns",
                    headers={"Authorization": f"Bearer {self.TOKEN}"},
                    method=method,
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=3)
                self.assertEqual(raised.exception.code, 405)
                self.assertEqual(raised.exception.headers["Allow"], "POST")
        head = urllib.request.Request(
            self.base + "/v1/turns",
            headers={"Authorization": f"Bearer {self.TOKEN}"},
            method="HEAD",
        )
        with self.assertRaises(urllib.error.HTTPError) as raised_head:
            urllib.request.urlopen(head, timeout=3)
        self.assertEqual(raised_head.exception.code, 405)

    def test_validation_matrix_is_400_without_growth(self) -> None:
        before = self.durable_counts()
        cases = {
            "host": {"host": "slack"},
            "empty-text": {"user_text": "   "},
            "timestamp": {"captured_at": "not-a-time"},
            "control": {"user_text": "bad\x00text"},
            "sensitivity": {"sensitivity": "secret"},
        }
        for turn_id, override in cases.items():
            with self.subTest(turn=turn_id):
                status, _, _ = self.post_turn(build_turn_bytes(turn_id, **override))
                self.assertEqual(status, 400)
        self.assertEqual(self.durable_counts(), before)

    def test_unexpected_failure_is_fixed_500(self) -> None:
        with mock.patch.object(
            Vault, "ingest", side_effect=RuntimeError("do-not-leak-this")
        ):
            status, failure, _ = self.post_turn(build_turn_bytes("turn-500"))
        self.assertEqual(status, 500)
        self.assertEqual(failure, {"error": "internal server error"})
        self.assertNotIn("do-not-leak-this", json.dumps(failure))


if __name__ == "__main__":
    unittest.main()
