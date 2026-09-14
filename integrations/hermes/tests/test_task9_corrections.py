from __future__ import annotations

from io import BytesIO
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

from integrations.hermes import http_parser, settings, token_file, transport


class _ResponseReader:
    def __init__(self, payload: bytes) -> None:
        self._stream = BytesIO(payload)

    def read_until(self, delimiter: bytes, maximum: int) -> bytes:
        value = bytearray()
        while len(value) <= maximum:
            chunk = self._stream.read(1)
            if not chunk:
                raise AssertionError("unexpected EOF")
            value.extend(chunk)
            if value.endswith(delimiter):
                return bytes(value)
        raise AssertionError("reader limit exceeded")

    def read_exact(self, size: int) -> bytes:
        value = self._stream.read(size)
        if len(value) != size:
            raise AssertionError("unexpected EOF")
        return value

    def read_available(self) -> bytes:
        return self._stream.read()


class _Socket:
    def __init__(self, response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}") -> None:
        self.response = response
        self.timeouts: list[float] = []
        self.sent: list[bytes] = []
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def recv(self, size: int) -> bytes:
        if self.response:
            value, self.response = self.response, b""
            return value
        return b""

    def close(self) -> None:
        self.closed = True


class Task9CorrectionTests(unittest.TestCase):
    def test_token_file_rejects_every_c0_and_del(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for control in (*range(0x20), 0x7F):
                path = Path(directory) / f"token-{control:02x}"
                path.write_bytes(b"a" * 32 + bytes((control,)))
                path.chmod(0o600)
                with self.subTest(control=control), self.assertRaises(token_file.TokenFileError):
                    token_file.read_token(str(path))

    def test_token_file_rejects_ascii_and_unicode_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for whitespace in (" ", "\t", "\n", "\u00a0", "\u2003"):
                path = Path(directory) / "token"
                path.write_text("a" * 31 + whitespace, encoding="utf-8")
                path.chmod(0o600)
                with self.subTest(whitespace=repr(whitespace)):
                    with self.assertRaises(token_file.TokenFileError):
                        token_file.read_token(str(path))

    def test_direct_transport_token_controls_fail_before_connect(self) -> None:
        with mock.patch.object(transport.socket, "create_connection") as connect:
            for control in (*range(0x20), 0x7F):
                with self.subTest(control=control), self.assertRaises(transport.TransportFailure):
                    transport.StdlibTransport(100).request(
                        "http://127.0.0.1:7331", "a" * 32 + chr(control), b"{}", 1.0
                    )
        connect.assert_not_called()

    def test_settings_rejects_raw_controls_before_urlsplit(self) -> None:
        context = mock.Mock()
        context.get_config.return_value = "http://127.0.0.1:7331"
        for control in (*range(0x20), 0x7F):
            with self.subTest(control=control):
                context.get_config.side_effect = lambda key, default=None, c=control: (
                    chr(c) + "http://127.0.0.1:7331" if key == "url" else default
                )
                with mock.patch.object(settings, "urlsplit") as split:
                    with self.assertRaises(settings.SettingsError):
                        settings.load_settings(context)
                    split.assert_not_called()

    def test_host_serialization_preserves_non_default_port_and_ipv6(self) -> None:
        for url, expected in (
            ("http://example.test:8080/path", b"Host: example.test:8080\r\n"),
            ("http://[::1]:8080/path", b"Host: [::1]:8080\r\n"),
            ("https://[::1]:443/path", b"Host: [::1]\r\n"),
        ):
            with self.subTest(url=url):
                connection = _Socket()
                with mock.patch.object(transport, "_connect", return_value=connection):
                    transport.StdlibTransport(100).request(url, "a" * 32, b"{}", 1.0)
                self.assertEqual(len(connection.sent), 1)
                self.assertIn(expected, connection.sent[0])

    def test_non_ascii_host_and_unencodable_token_fail_before_connect(self) -> None:
        with mock.patch.object(transport.socket, "create_connection") as connect:
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    "http://münich.example/path", "a" * 32, b"{}", 1.0
                )
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    "http://127.0.0.1:7331", "a" * 32 + "\ud800", b"{}", 1.0
                )
        connect.assert_not_called()

    def test_invalid_origin_targets_fail_before_connect(self) -> None:
        urls = (
            "http://127.0.0.1:7331/safe path",
            "http://127.0.0.1:7331/%ZZ",
            "http://127.0.0.1:7331/caf\u00e9",
            "http://127.0.0.1:7331/path#fragment",
        )
        with mock.patch.object(transport.socket, "create_connection") as connect:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(transport.TransportFailure):
                    transport.StdlibTransport(100).request(url, "a" * 32, b"{}", 1.0)
        connect.assert_not_called()

    def test_settings_rejects_malformed_authority_and_zero_port(self) -> None:
        context = mock.Mock()
        for url in ("http://host:bad", "http://host:0", "http://[::1"):
            context.get_config.side_effect = lambda key, default=None, value=url: (
                value if key == "url" else default
            )
            with self.subTest(url=url), self.assertRaises(settings.SettingsError):
                settings.load_settings(context)

    def test_tls_wrap_failure_closes_raw_socket(self) -> None:
        connection = _Socket()
        context = mock.Mock()
        context.wrap_socket.side_effect = OSError("handshake failed")
        with mock.patch.object(transport.socket, "create_connection", return_value=connection):
            with mock.patch.object(transport.ssl, "create_default_context", return_value=context):
                with self.assertRaises(transport.TransportFailure):
                    transport.StdlibTransport(100).request(
                        "https://example.test/path", "a" * 32, b"{}", 1.0
                    )
        self.assertTrue(connection.closed)

    def test_tls_handshake_refreshes_timeout_from_remaining_deadline(self) -> None:
        connection = _Socket()
        context = mock.Mock()
        context.wrap_socket.return_value = connection
        with mock.patch.object(transport.socket, "create_connection", return_value=connection):
            with mock.patch.object(transport.ssl, "create_default_context", return_value=context):
                with mock.patch.object(
                    transport, "_remaining", side_effect=(0.8, 0.2, 0.1, 0.1)
                ) as remaining:
                    transport.StdlibTransport(100).request(
                        "https://example.test/path", "a" * 32, b"{}", 1.0
                    )
        self.assertEqual(connection.timeouts[0], 0.2)
        self.assertEqual(remaining.call_count, 4)

    def test_non_positive_timeout_fails_without_connecting(self) -> None:
        with mock.patch.object(transport.socket, "create_connection") as connect:
            for timeout in (0.0, -1.0):
                with self.subTest(timeout=timeout), self.assertRaises(transport.TransportFailure):
                    transport.StdlibTransport(100).request(
                        "http://127.0.0.1:7331", "a" * 32, b"{}", timeout
                    )
        connect.assert_not_called()

    def test_extreme_and_wrong_type_timeouts_fail_without_connecting(self) -> None:
        with mock.patch.object(transport.socket, "create_connection") as connect:
            for timeout in (1e308, True, "1.0"):
                with self.subTest(timeout=timeout), self.assertRaises(transport.TransportFailure):
                    transport.StdlibTransport(100).request(
                        "http://127.0.0.1:7331", "a" * 32, b"{}", timeout
                    )
        connect.assert_not_called()

    def test_transport_consumes_provisional_response(self) -> None:
        connection = _Socket(
            b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}"
        )
        with mock.patch.object(transport, "_connect", return_value=connection):
            response = transport.StdlibTransport(100).request(
                "http://example.test/path", "a" * 32, b"{}", 1.0
            )
        self.assertEqual(response, transport.HttpResponse(201, b"{}"))

    def test_forbidden_chunked_trailers_are_rejected(self) -> None:
        for trailer in (b"Content-Length: 9\r\n", b"Transfer-Encoding: chunked\r\n"):
            with self.subTest(trailer=trailer):
                reader = _ResponseReader(b"1\r\nx\r\n0\r\n" + trailer + b"\r\n")
                metadata = http_parser.ResponseMetadata(200, None, True)
                with self.assertRaises(http_parser.TransportFailure):
                    http_parser.read_response_body(reader, metadata, 100)

    def test_bodyless_framing_rejects_204_but_accepts_304_length(self) -> None:
        with self.assertRaises(http_parser.TransportFailure):
            http_parser.parse_response_metadata(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n"
            )
        metadata = http_parser.parse_response_metadata(
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n"
        )
        self.assertEqual(metadata.content_length, 9)
        self.assertEqual(http_parser.read_response_body(_ResponseReader(b""), metadata, 100), b"")

    def test_successful_json_requires_finite_top_level_object(self) -> None:
        accepted = transport.require_json_response(transport.HttpResponse(201, b"{}"), 100)
        self.assertEqual(accepted, b"{}")
        for body in (b"NaN", b"Infinity", b"-Infinity", b"[]", b"null", b"1"):
            with self.subTest(body=body), self.assertRaises(transport.TransportFailure):
                transport.require_json_response(transport.HttpResponse(200, body), 100)


if __name__ == "__main__":
    unittest.main()
