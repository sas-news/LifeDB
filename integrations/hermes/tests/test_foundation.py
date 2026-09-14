from collections.abc import Callable
import http.server
import inspect
import json
import threading
import tempfile
import time
import unittest
from pathlib import Path
from typing import get_type_hints

from integrations.hermes import bridge, logging_utils, payloads, settings, token_file, transport
from integrations.hermes.preflight import create_preflight


class FakeContext:
    def __init__(self, values: dict[str, str | int | float | bool | None]) -> None:
        self.values = values
        self.calls: list[str] = []
        self.registrations: list[tuple[str, Callable[..., None]]] = []

    def get_config(self, key: str, default: str | int | float | bool | None = None) -> str | int | float | bool | None:
        self.calls.append(key)
        return self.values.get(key, default)

    def register_hook(self, name: str, callback: Callable[..., None]) -> None:
        self.registrations.append((name, callback))


class FoundationTests(unittest.TestCase):
    def test_preflight_callback_annotations_resolve_with_get_type_hints(self) -> None:
        callback = create_preflight(FakeContext({}))
        self.assertIn("conversation_history", get_type_hints(callback))

    def test_manifest_is_minimal_and_declares_only_supported_hooks(self) -> None:
        manifest = Path(__file__).parents[1] / "plugin.yaml"
        text = manifest.read_text(encoding="utf-8")
        self.assertIn("name: lifedb-bridge", text)
        self.assertIn("  - pre_llm_call", text)
        self.assertIn("  - post_llm_call", text)
        self.assertIn("  - on_session_end", text)
        self.assertNotIn("pip_dependencies", text)
        self.assertNotIn("MemoryProvider", text)

    def test_package_import_does_not_require_hermes(self) -> None:
        self.assertEqual(bridge.__package__, "integrations.hermes")

    def test_registration_has_exactly_three_callbacks(self) -> None:
        from integrations import hermes as module
        context = FakeContext({})
        module.register(context)
        self.assertEqual([name for name, _ in context.registrations], [
            "pre_llm_call", "post_llm_call", "on_session_end",
        ])
        self.assertEqual(context.calls, [])
        self.assertTrue(all(not inspect.iscoroutinefunction(callback) for _, callback in context.registrations))
        self.assertIsNone(context.registrations[0][1]())
        self.assertIsNone(context.registrations[1][1]())
        self.assertIsNone(context.registrations[2][1]())
        self.assertEqual(context.calls, [])

    def test_settings_are_loaded_from_plugin_context(self) -> None:
        context = FakeContext({
            "url": "http://127.0.0.1:7331/",
            "token_file": "/tmp/lifedb-token",
            "timeout_seconds": 1.5,
            "max_response_bytes": 4096,
            "max_request_bytes": 8192,
        })
        loaded = settings.load_settings(context)
        self.assertEqual(loaded.base_url, "http://127.0.0.1:7331")
        self.assertEqual(loaded.token_file, "/tmp/lifedb-token")
        self.assertEqual(loaded.timeout_seconds, 1.5)
        self.assertEqual(loaded.max_response_bytes, 4096)
        self.assertEqual(loaded.max_request_bytes, 8192)
        self.assertEqual(context.calls, ["url", "token_file", "timeout_seconds", "max_response_bytes", "max_request_bytes"])

    def test_token_reader_preserves_exact_bytes_and_rejects_unsafe_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_bytes(b"a" * 32)
            path.chmod(0o600)
            self.assertEqual(token_file.read_token(path), "a" * 32)
            path.chmod(0o644)
            with self.assertRaises(token_file.TokenFileError):
                token_file.read_token(path)

    def test_canonical_payloads_are_stable_and_scalar_only(self) -> None:
        context_body = payloads.context_payload(
            query="hello", client="hermes", session="s", workspace="/tmp/x"
        )
        self.assertEqual(json.loads(context_body), {"client": "hermes", "query": "hello", "session": "s", "workspace": "/tmp/x"})
        turn_body = payloads.turn_payload(
            session_id="s", turn_id="t", user_text="u", assistant_text="a",
            captured_at="2026-09-07T00:00:00Z",
        )
        self.assertNotIn(b"conversation_history", turn_body)
        self.assertIn(b'"host":"hermes"', turn_body)

    def test_stdlib_transport_bounds_response_and_does_not_follow_redirects(self) -> None:
        response = transport.HttpResponse(status=200, body=b"{}")
        self.assertEqual(response.status, 200)
        with self.assertRaises(transport.TransportFailure):
            transport.require_json_response(transport.HttpResponse(200, b"x"), 0)
        with self.assertRaises(transport.TransportFailure):
            transport.require_json_response(transport.HttpResponse(200, b"not-json"), 100)

    def test_bridge_passes_pre_serialized_bytes_once(self) -> None:
        class FakeTransport:
            def request(self, url: str, token: str, body: bytes, timeout: float) -> transport.HttpResponse:
                self.body = body
                return transport.HttpResponse(200, b"{}")

        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "token"
            token_path.write_bytes(b"b" * 32)
            token_path.chmod(0o600)
            fake = FakeTransport()
            result = bridge.post_json(
                fake,
                settings.PluginSettings("http://127.0.0.1:7331", str(token_path), 1.25, 100, 1000),
                "/v1/context",
                payloads.context_payload(query="q", client="hermes"),
            )
            self.assertEqual(result, bridge.BridgeResult(200, b"{}"))
            self.assertEqual(fake.body, b'{"client":"hermes","query":"q"}')

    def test_bridge_rejects_request_over_cap_before_transport(self) -> None:
        class NeverTransport:
            def request(self, url: str, token: str, body: bytes, timeout: float) -> transport.HttpResponse:
                raise AssertionError("transport must not be called")

        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "token"
            token_path.write_bytes(b"c" * 32)
            token_path.chmod(0o600)
            result = bridge.post_json(
                NeverTransport(),
                settings.PluginSettings("http://127.0.0.1:7331", str(token_path), 1.0, 100, 4),
                "/v1/context",
                payloads.context_payload(query="too large", client="hermes"),
            )
            self.assertIsNone(result)

    def test_server_error_is_returned_without_following_or_retrying(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                self.send_response(500)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"error")

            def log_message(self, format: str, *args: str) -> None:
                return None

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = transport.StdlibTransport(100).request(
                f"http://127.0.0.1:{server.server_port}", "d" * 32, b"{}", 1.0
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
        self.assertEqual(result, transport.HttpResponse(500, b"error"))

    def test_slow_drip_body_observes_total_deadline(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                self.send_response(200)
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.03)
                except BrokenPipeError:
                    return

            def log_message(self, format: str, *args: str) -> None:
                return None

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    f"http://127.0.0.1:{server.server_port}", "e" * 32, b"{}", 0.1
                )
            elapsed = time.monotonic() - started
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
        self.assertLess(elapsed, 0.5)

    def test_injected_transport_receives_exact_bridge_request(self) -> None:
        class FakeTransport:
            def __init__(self) -> None:
                self.request_values: tuple[str, str, bytes, float] | None = None

            def request(self, url: str, token: str, body: bytes, timeout: float) -> transport.HttpResponse:
                self.request_values = (url, token, body, timeout)
                return transport.HttpResponse(200, b"{}")

        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "token"
            token_path.write_bytes(b"b" * 32)
            token_path.chmod(0o600)
            fake = FakeTransport()
            result = bridge.post_json(
                fake,
                settings.PluginSettings("http://127.0.0.1:7331", str(token_path), 1.25, 100),
                "/v1/context",
                payloads.context_payload(query="q", client="hermes"),
            )
            self.assertEqual(result, bridge.BridgeResult(200, b"{}"))
            self.assertIsNotNone(fake.request_values)
            assert fake.request_values is not None
            self.assertEqual(fake.request_values[0], "http://127.0.0.1:7331/v1/context")
            self.assertEqual(fake.request_values[1], "b" * 32)
            self.assertEqual(fake.request_values[3], 1.25)

    def test_logging_has_no_sensitive_fields(self) -> None:
        records: list[str] = []
        handler = __import__("logging").Handler()
        handler.emit = lambda record: records.append(record.getMessage())
        logging_utils.LOGGER.addHandler(handler)
        try:
            logging_utils.log_outcome("context.fetch", "fail-open", warning=True)
        finally:
            logging_utils.LOGGER.removeHandler(handler)
        self.assertEqual(records, ["lifedb bridge operation=context.fetch outcome=fail-open"])
