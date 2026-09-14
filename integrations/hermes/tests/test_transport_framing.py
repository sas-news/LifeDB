from __future__ import annotations

import socket
from threading import Event, Thread
import unittest

from integrations.hermes import transport


def _start_raw_peer(
    response: bytes, hold: Event | None = None
) -> tuple[socket.socket, int, Thread, list[bytes]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.2)
    observed: list[bytes] = []

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                observed.append(connection.recv(65_536))
                connection.sendall(response)
                if hold is not None:
                    hold.wait(1)
        except (OSError, TimeoutError):
            return None

    thread = Thread(target=serve, daemon=True)
    thread.start()
    return listener, listener.getsockname()[1], thread, observed


class TransportFramingTests(unittest.TestCase):
    def test_malformed_status_line_fails_closed(self) -> None:
        listener, port, thread, _ = _start_raw_peer(
            b"BOGUS +200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        try:
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    f"http://127.0.0.1:{port}", "f" * 32, b"{}", 1.0
                )
        finally:
            listener.close()
            thread.join(timeout=1)

    def test_ambiguous_content_length_fails_closed(self) -> None:
        listener, port, thread, _ = _start_raw_peer(
            b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx"
        )
        try:
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    f"http://127.0.0.1:{port}", "g" * 32, b"{}", 1.0
                )
        finally:
            listener.close()
            thread.join(timeout=1)

    def test_non_decimal_content_lengths_fail_closed(self) -> None:
        for value in (b"-1", b"1.0", b"1,1", b"1 1"):
            with self.subTest(value=value):
                listener, port, thread, _ = _start_raw_peer(
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + value
                    + b"\r\n\r\nx"
                )
                try:
                    with self.assertRaises(transport.TransportFailure):
                        transport.StdlibTransport(100).request(
                            f"http://127.0.0.1:{port}", "g" * 32, b"{}", 1.0
                        )
                finally:
                    listener.close()
                    thread.join(timeout=1)

    def test_duplicate_content_length_fails_closed(self) -> None:
        listener, port, thread, _ = _start_raw_peer(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 1\r\nContent-Length: 1\r\n\r\nx"
        )
        try:
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    f"http://127.0.0.1:{port}", "h" * 32, b"{}", 1.0
                )
        finally:
            listener.close()
            thread.join(timeout=1)

    def test_unsupported_transfer_encoding_fails_closed(self) -> None:
        listener, port, thread, _ = _start_raw_peer(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nx"
        )
        try:
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    f"http://127.0.0.1:{port}", "i" * 32, b"{}", 1.0
                )
        finally:
            listener.close()
            thread.join(timeout=1)

    def test_bodyless_status_returns_without_waiting_for_peer_close(self) -> None:
        for status, reason in (
            (101, "Switching Protocols"),
            (204, "No Content"),
            (304, "Not Modified"),
        ):
            with self.subTest(status=status):
                hold = Event()
                listener, port, thread, _ = _start_raw_peer(
                    f"HTTP/1.1 {status} {reason}\r\n\r\n".encode(), hold
                )
                try:
                    result = transport.StdlibTransport(100).request(
                        f"http://127.0.0.1:{port}", "j" * 32, b"{}", 0.1
                    )
                finally:
                    hold.set()
                    listener.close()
                    thread.join(timeout=1)
                self.assertEqual(result, transport.HttpResponse(status, b""))

    def test_transport_rejects_crlf_token_before_sending_request(self) -> None:
        listener, port, thread, observed = _start_raw_peer(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
        )
        try:
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    f"http://127.0.0.1:{port}",
                    "k" * 32 + "\r\nX-Injected: yes",
                    b"{}",
                    1.0,
                )
        finally:
            listener.close()
            thread.join(timeout=1)
        self.assertEqual(observed, [])

    def test_transport_rejects_raw_url_controls_before_connecting(self) -> None:
        for control in ("\r", "\n", "\x00", "\x7f"):
            with self.subTest(component="path", control=repr(control)):
                listener, port, thread, observed = _start_raw_peer(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                )
                try:
                    with self.assertRaises(transport.TransportFailure):
                        transport.StdlibTransport(100).request(
                            f"http://127.0.0.1:{port}/safe{control}X-Injected: yes",
                            "l" * 32,
                            b"{}",
                            1.0,
                        )
                finally:
                    listener.close()
                    thread.join(timeout=1)
                self.assertEqual(observed, [])

            with self.subTest(component="authority", control=repr(control)):
                listener, port, thread, observed = _start_raw_peer(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                )
                try:
                    with self.assertRaises(transport.TransportFailure):
                        transport.StdlibTransport(100).request(
                            f"http://127.0.0.1{control}X-Injected: yes:{port}/safe",
                            "l" * 32,
                            b"{}",
                            1.0,
                        )
                finally:
                    listener.close()
                    thread.join(timeout=1)
                self.assertEqual(observed, [])

            for component in ("query", "fragment"):
                with self.subTest(component=component, control=repr(control)):
                    listener, port, thread, observed = _start_raw_peer(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                    )
                    suffix = (
                        f"/safe?x=1{control}X-Injected: yes"
                        if component == "query"
                        else f"/safe#frag{control}X-Injected: yes"
                    )
                    try:
                        with self.assertRaises(transport.TransportFailure):
                            transport.StdlibTransport(100).request(
                                f"http://127.0.0.1:{port}{suffix}",
                                "l" * 32,
                                b"{}",
                                1.0,
                            )
                    finally:
                        listener.close()
                        thread.join(timeout=1)
                    self.assertEqual(observed, [])

    def test_transport_preserves_percent_encoded_url_path(self) -> None:
        listener, port, thread, observed = _start_raw_peer(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
        )
        try:
            result = transport.StdlibTransport(100).request(
                f"http://127.0.0.1:{port}/safe%0D%0AX-Injected%3A%20yes",
                "m" * 32,
                b"{}",
                1.0,
            )
        finally:
            listener.close()
            thread.join(timeout=1)
        self.assertEqual(result, transport.HttpResponse(200, b"{}"))
        self.assertEqual(
            observed[0].split(b"\r\n", 1)[0],
            b"POST /safe%0D%0AX-Injected%3A%20yes HTTP/1.1",
        )
