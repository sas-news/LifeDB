from __future__ import annotations

from io import BytesIO
import unittest
from unittest import mock

from integrations.hermes import settings, transport, url_validation


class _Socket:
    def __init__(self, response: bytes) -> None:
        self._response = BytesIO(response)
        self.closed = False

    def settimeout(self, value: float) -> None:
        del value

    def sendall(self, value: bytes) -> None:
        del value

    def recv(self, size: int) -> bytes:
        return self._response.read(size)

    def close(self) -> None:
        self.closed = True


class Task9BlockerTests(unittest.TestCase):
    def test_wrong_direct_url_types_fail_safely_before_connect(self) -> None:
        urls = (None, 123, b"http://127.0.0.1:7331", [])
        with mock.patch.object(transport.socket, "create_connection") as connect:
            for url in urls:
                with self.subTest(url_type=type(url).__name__):
                    with self.assertRaisesRegex(
                        transport.TransportFailure, "^bridge request unavailable$"
                    ):
                        transport.StdlibTransport(100).request(
                            url, "a" * 32, b"{}", 1.0
                        )
        connect.assert_not_called()

    def test_raw_authority_and_delimiter_inputs_fail_before_connect(self) -> None:
        urls = (
            "http://host%ZZ/path",
            "http://host%/path",
            "http://host%0/path",
            "http:// host/path",
            "http://host /path",
            "http://@host/path",
            "http://:@host/path",
            " http://127.0.0.1:7331/safe",
            "http://127.0.0.1:7331/safe ",
            "http://127.0.0.1:7331/safe#",
            "http://127.0.0.1:7331/safe#fragment",
        )
        with mock.patch.object(
            transport.socket, "create_connection", side_effect=AssertionError
        ) as connect:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(transport.TransportFailure):
                    transport.StdlibTransport(100).request(
                        url, "a" * 32, b"{}", 1.0
                    )
        connect.assert_not_called()

    def test_encoded_target_and_query_are_preserved(self) -> None:
        endpoint = url_validation.parse_endpoint(
            "http://example.test/safe%2Fpath?x=%23%20yes"
        )
        self.assertEqual(endpoint.target, "/safe%2Fpath?x=%23%20yes")

    def test_settings_rejects_raw_authority_and_delimiter_inputs(self) -> None:
        for url in (
            "http://host%ZZ/path",
            "http://host%/path",
            "http:// host/path",
            "http://@host/path",
            " http://host/path",
            "http://host/path#",
        ):
            context = mock.Mock()
            context.get_config.side_effect = lambda key, default=None, value=url: (
                value if key == "url" else default
            )
            with self.subTest(url=url), self.assertRaises(settings.SettingsError):
                settings.load_settings(context)

    def test_extreme_settings_timeouts_raise_settings_error(self) -> None:
        for timeout in (10**1000, -(10**1000), True, "1.0", []):
            context = mock.Mock()
            context.get_config.side_effect = lambda key, default=None, value=timeout: (
                value if key == "timeout_seconds" else default
            )
            with self.subTest(timeout=type(timeout).__name__), self.assertRaises(
                settings.SettingsError
            ):
                settings.load_settings(context)

    def test_extreme_direct_timeouts_raise_transport_failure_before_connect(self) -> None:
        with mock.patch.object(
            transport.socket, "create_connection", side_effect=AssertionError
        ) as connect:
            for timeout in (10**1000, -(10**1000), True, "1.0", []):
                with self.subTest(timeout=type(timeout).__name__), self.assertRaises(
                    transport.TransportFailure
                ):
                    transport.StdlibTransport(100).request(
                        "http://127.0.0.1:7331", "a" * 32, b"{}", timeout
                    )
        connect.assert_not_called()

    def test_constructor_rejects_invalid_response_caps_before_io(self) -> None:
        caps = (True, False, 1.0, "100", -1, 0, 16_777_217, 10**1000)
        with mock.patch.object(transport.socket, "create_connection") as connect:
            for cap in caps:
                with self.subTest(cap=repr(cap)), self.assertRaises(
                    transport.TransportFailure
                ):
                    transport.StdlibTransport(cap)
        connect.assert_not_called()

    def test_provisional_response_bound_accepts_exact_limit(self) -> None:
        provisional = b"HTTP/1.1 100 Continue\r\n\r\n"
        final = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}"
        connection = _Socket(provisional * 1000 + final)
        with mock.patch.object(transport, "_connect", return_value=connection):
            result = transport.StdlibTransport(100).request(
                "http://example.test/path", "a" * 32, b"{}", 1.0
            )
        self.assertEqual(result, transport.HttpResponse(201, b"{}"))

    def test_provisional_response_bound_rejects_one_over_limit(self) -> None:
        provisional = b"HTTP/1.1 100 Continue\r\n\r\n"
        final = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}"
        connection = _Socket(provisional * 1001 + final)
        with mock.patch.object(transport, "_connect", return_value=connection):
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    "http://example.test/path", "a" * 32, b"{}", 1.0
                )

    def test_switching_protocols_remains_terminal_bodyless_response(self) -> None:
        connection = _Socket(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        with mock.patch.object(transport, "_connect", return_value=connection):
            result = transport.StdlibTransport(100).request(
                "http://example.test/path", "a" * 32, b"{}", 1.0
            )
        self.assertEqual(result, transport.HttpResponse(101, b""))


if __name__ == "__main__":
    unittest.main()
