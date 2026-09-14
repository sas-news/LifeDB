from __future__ import annotations

import http.server
import socket
from threading import Event, Thread
import threading
import time
import unittest

from integrations.hermes import transport


class TransportLifecycleTests(unittest.TestCase):
    def test_repeated_stalled_headers_leave_no_client_workers(self) -> None:
        release = Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                release.wait()

            def log_message(self, format: str, *args: str) -> None:
                return None

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            client = transport.StdlibTransport(100)
            for _ in range(5):
                with self.assertRaises(transport.TransportFailure):
                    client.request(
                        f"http://127.0.0.1:{server.server_port}",
                        "a" * 32,
                        b"{}",
                        0.03,
                    )
            workers = [
                thread for thread in threading.enumerate()
                if thread.name.endswith("(open_request)")
            ]
            self.assertEqual(workers, [])
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=1)

    def test_stalled_body_fails_at_total_deadline_without_worker(self) -> None:
        first_byte_sent = Event()
        connection_closed = Event()
        release = Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                self.send_response(500)
                self.send_header("Content-Length", "20")
                self.end_headers()
                self.wfile.write(b"x")
                self.wfile.flush()
                first_byte_sent.set()
                release.wait()
                try:
                    self.connection.settimeout(1.0)
                    if self.connection.recv(1) == b"":
                        connection_closed.set()
                except socket.timeout:
                    connection_closed.set()

            def log_message(self, format: str, *args: str) -> None:
                return None

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            started = time.monotonic()
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(100).request(
                    f"http://127.0.0.1:{server.server_port}",
                    "b" * 32,
                    b"{}",
                    0.1,
                )
            elapsed = time.monotonic() - started
            self.assertTrue(first_byte_sent.wait(1))
            self.assertLess(elapsed, 0.5)
            release.set()
            self.assertTrue(connection_closed.wait(1))
            self.assertEqual(
                [
                    thread for thread in threading.enumerate()
                    if thread.name.endswith("(open_request)")
                ],
                [],
            )
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=1)

    def test_connect_timeout_does_not_create_transport_worker(self) -> None:
        with self.assertRaises(transport.TransportFailure):
            transport.StdlibTransport(100).request(
                "http://127.0.0.1:1", "c" * 32, b"{}", 0.1
            )
        self.assertEqual(
            [
                thread for thread in threading.enumerate()
                if thread.name.endswith("(open_request)")
            ],
            [],
        )

    def test_response_cap_closes_owned_connection(self) -> None:
        reached = Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                self.send_response(200)
                self.send_header("Content-Length", "9")
                self.end_headers()
                self.wfile.write(b"too-large")
                self.wfile.flush()
                reached.set()

            def log_message(self, format: str, *args: str) -> None:
                return None

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            with self.assertRaises(transport.TransportFailure):
                transport.StdlibTransport(3).request(
                    f"http://127.0.0.1:{server.server_port}",
                    "d" * 32,
                    b"{}",
                    1.0,
                )
            self.assertTrue(reached.wait(1))
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=1)

    def test_redirect_is_returned_without_follow_up_request(self) -> None:
        destination_hits = 0

        class DestinationHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                nonlocal destination_hits
                destination_hits += 1

            def log_message(self, format: str, *args: str) -> None:
                return None

        destination = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), DestinationHandler
        )
        destination_thread = Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()

        class SourceHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                self.send_response(302)
                self.send_header(
                    "Location", f"http://127.0.0.1:{destination.server_port}/next"
                )
                self.send_header("Content-Length", "3")
                self.end_headers()
                self.wfile.write(b"no!")

            def log_message(self, format: str, *args: str) -> None:
                return None

        source = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
        source_thread = Thread(target=source.serve_forever, daemon=True)
        source_thread.start()
        try:
            result = transport.StdlibTransport(100).request(
                f"http://127.0.0.1:{source.server_port}/start",
                "e" * 32,
                b"{}",
                1.0,
            )
        finally:
            source.shutdown()
            source.server_close()
            source_thread.join(timeout=1)
            destination.shutdown()
            destination.server_close()
            destination_thread.join(timeout=1)
        self.assertEqual(result, transport.HttpResponse(302, b"no!"))
        self.assertEqual(destination_hits, 0)
