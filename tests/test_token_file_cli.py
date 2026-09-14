from __future__ import annotations

import os
import unittest

from tests.token_file_helpers import (
    TokenFileCase,
    run_serve,
    valid_token,
    write_token_file,
)
from lifedb import auth


class CliServeTokenStartupTest(TokenFileCase):
    def setUp(self) -> None:
        super().setUp()
        self.vault = self.directory / "vault"
        self.vault.mkdir()

    def test_serve_with_direct_token_reaches_serve(self) -> None:
        token = valid_token()
        result = run_serve(self.vault, {"LIFEDB_API_TOKEN": token})
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(result.calls), 1)
        self.assertEqual(result.calls[0].api_token, token)

    def test_serve_with_token_file_reaches_serve_with_exact_bytes(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode(), 0o600)
        result = run_serve(self.vault, {"LIFEDB_API_TOKEN_FILE": path})
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(result.calls), 1)
        self.assertEqual(result.calls[0].api_token, token)

    def test_serve_with_both_sources_fails_before_listening(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode(), 0o600)
        result = run_serve(
            self.vault,
            {"LIFEDB_API_TOKEN": token, "LIFEDB_API_TOKEN_FILE": path},
        )
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.calls, [])
        self.assertNotIn(token, result.stderr)
        self.assertNotIn(path, result.stderr)

    def test_serve_with_permissive_file_fails_before_listening(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode(), 0o644)
        result = run_serve(self.vault, {"LIFEDB_API_TOKEN_FILE": path})
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.calls, [])
        self.assertNotIn(token, result.stderr)
        self.assertNotIn(path, result.stderr)

    def test_serve_with_trailing_newline_fails_before_listening(self) -> None:
        token = valid_token()
        path = write_token_file(
            self.directory, "token", (token + "\n").encode(), 0o600
        )
        result = run_serve(self.vault, {"LIFEDB_API_TOKEN_FILE": path})
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.calls, [])

    def test_serve_with_empty_file_fails_before_listening(self) -> None:
        path = write_token_file(self.directory, "token", b"", 0o600)
        result = run_serve(self.vault, {"LIFEDB_API_TOKEN_FILE": path})
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.calls, [])
        self.assertNotIn(path, result.stderr)

    def test_serve_with_final_symlink_fails_before_listening(self) -> None:
        token = valid_token()
        real = write_token_file(self.directory, "real", token.encode(), 0o600)
        link = str(self.directory / "link")
        os.symlink(real, link)
        result = run_serve(self.vault, {"LIFEDB_API_TOKEN_FILE": link})
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.calls, [])
        self.assertNotIn(token, result.stderr)
        self.assertNotIn(link, result.stderr)
        self.assertNotIn(real, result.stderr)

    def test_serve_unset_tokens_starts_unconfigured(self) -> None:
        result = run_serve(self.vault, {})
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(result.calls), 1)
        self.assertIsNone(result.calls[0].api_token)

    def test_empty_env_values_are_unset(self) -> None:
        result = run_serve(
            self.vault, {"LIFEDB_API_TOKEN": "", "LIFEDB_API_TOKEN_FILE": ""}
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(result.calls), 1)

    def test_resolve_from_env_mapping(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())
        self.assertEqual(
            auth.resolve_api_token_from_env({"LIFEDB_API_TOKEN": token}),
            token,
        )
        self.assertEqual(
            auth.resolve_api_token_from_env({"LIFEDB_API_TOKEN_FILE": path}),
            token,
        )
        self.assertIsNone(auth.resolve_api_token_from_env({}))
        self.assertIsNone(
            auth.resolve_api_token_from_env(
                {"LIFEDB_API_TOKEN": "", "LIFEDB_API_TOKEN_FILE": ""}
            ),
            None,
        )
        with self.assertRaises(ValueError):
            auth.resolve_api_token_from_env(
                {"LIFEDB_API_TOKEN": token, "LIFEDB_API_TOKEN_FILE": path}
            )


if __name__ == "__main__":
    unittest.main()
