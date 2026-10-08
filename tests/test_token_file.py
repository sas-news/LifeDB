from __future__ import annotations

import os
import stat
import unittest
from unittest.mock import patch

from lifedb import auth
from lifedb.auth import validate_api_token
from tests.token_file_helpers import TokenFileCase, valid_token, write_token_file


class ResolveApiTokenTest(TokenFileCase):
    def test_unset_sources_mean_unconfigured(self) -> None:
        self.assertIsNone(auth.resolve_api_token(None, None))

    def test_empty_values_are_treated_as_unset(self) -> None:
        self.assertIsNone(auth.resolve_api_token("", ""))
        path = write_token_file(self.directory, "token", valid_token().encode())
        self.assertEqual(auth.resolve_api_token("", path), valid_token())
        self.assertEqual(auth.resolve_api_token(valid_token(), ""), valid_token())

    def test_direct_only_passes_through_validation(self) -> None:
        self.assertEqual(auth.resolve_api_token(valid_token(), None), valid_token())

    def test_direct_invalid_token_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            auth.resolve_api_token("short", None)

    def test_file_only_valid_0600(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode(), 0o600)
        self.assertEqual(auth.resolve_api_token(None, path), token)

    def test_both_sources_is_an_error(self) -> None:
        path = write_token_file(self.directory, "token", valid_token().encode())
        with self.assertRaises(ValueError) as caught:
            auth.resolve_api_token(valid_token(), path)
        self.assertNotIn(valid_token(), str(caught.exception))
        self.assertNotIn(path, str(caught.exception))

    def test_relative_path_is_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            auth.resolve_api_token(None, "relative/token")
        self.assertNotIn("relative/token", str(caught.exception))

    def test_missing_file_is_rejected(self) -> None:
        missing = str(self.directory / "does-not-exist")
        with self.assertRaises(ValueError) as caught:
            auth.resolve_api_token(None, missing)
        self.assertNotIn(missing, str(caught.exception))

    def test_directory_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            auth.resolve_api_token(None, str(self.directory))

    def test_fifo_is_rejected_without_blocking(self) -> None:
        fifo = self.directory / "token.fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            auth.read_token_file(str(fifo))

    def test_final_symlink_is_rejected(self) -> None:
        token = valid_token()
        real = write_token_file(self.directory, "real", token.encode())
        link = str(self.directory / "link")
        os.symlink(real, link)
        with self.assertRaises(ValueError) as caught:
            auth.resolve_api_token(None, link)
        self.assertNotIn(real, str(caught.exception))
        self.assertNotIn(link, str(caught.exception))

    def test_wrong_owner_is_rejected(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())
        original_fstat = os.fstat

        def fake_fstat(descriptor: int) -> os.stat_result:
            result = original_fstat(descriptor)
            values = list(result)
            values[stat.ST_UID] = result.st_uid + 1
            return os.stat_result(values)

        with patch.object(auth.os, "fstat", side_effect=fake_fstat):
            with self.assertRaises(ValueError):
                auth.resolve_api_token(None, path)

    def test_permissive_modes_are_rejected(self) -> None:
        token = valid_token()
        for mode in (0o644, 0o640, 0o604, 0o600 | 0o070, 0o666, 0o601):
            path = write_token_file(self.directory, f"token-{mode:o}", token.encode(), mode)
            with self.assertRaises(ValueError, msg=f"mode {mode:o}"):
                auth.resolve_api_token(None, path)

    def test_short_file_token_is_rejected(self) -> None:
        path = write_token_file(self.directory, "token", b"short")
        with self.assertRaises(ValueError):
            auth.resolve_api_token(None, path)

    def test_long_file_token_is_rejected(self) -> None:
        path = write_token_file(self.directory, "token", b"a" * 4097)
        with self.assertRaises(ValueError):
            auth.resolve_api_token(None, path)

    def test_exact_maximum_length_is_accepted(self) -> None:
        token = "a" * 4096
        validate_api_token(token)
        path = write_token_file(self.directory, "token", token.encode())
        self.assertEqual(auth.resolve_api_token(None, path), token)

    def test_whitespace_is_not_trimmed_and_is_rejected(self) -> None:
        for payload in (
            valid_token() + "\n",
            " " + valid_token(),
            valid_token() + " ",
            "a" * 20 + " " + "b" * 20,
        ):
            path = write_token_file(self.directory, "token", payload.encode())
            with self.assertRaises(ValueError, msg=repr(payload)):
                auth.resolve_api_token(None, path)

    def test_invalid_utf8_is_rejected(self) -> None:
        path = write_token_file(self.directory, "token", b"a" * 31 + b"\xff")
        with self.assertRaises(ValueError) as caught:
            auth.resolve_api_token(None, path)
        self.assertNotIn(path, str(caught.exception))

    def test_mutation_between_inspect_and_open_is_rejected(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())
        original_open = os.open

        def swapping_open(path_value: str, flags: int, mode: int = 0o777) -> int:
            descriptor = original_open(path_value, flags, mode)
            with open(path, "wb") as stream:
                stream.write(b"mutated-" + b"x" * 40)
            os.chmod(path, 0o600)
            return descriptor

        with patch.object(auth.os, "open", side_effect=swapping_open):
            with self.assertRaises(ValueError):
                auth.resolve_api_token(None, path)

    def test_same_size_mutation_during_read_is_rejected(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())
        original_read = os.read

        def mutating_read(descriptor: int, length: int) -> bytes:
            data = original_read(descriptor, length)
            if data:
                preserved = os.stat(path)
                with open(path, "wb") as stream:
                    stream.write(b"X" + token.encode()[1:])
                # Keep the metadata comparison honest: restore the previous
                # timestamps so only the byte re-read can detect this write.
                os.utime(path, ns=(preserved.st_atime_ns, preserved.st_mtime_ns))
                os.chmod(path, 0o600)
            return data

        with patch.object(auth.os, "read", side_effect=mutating_read):
            with self.assertRaises(ValueError):
                auth.resolve_api_token(None, path)

    def test_permission_change_during_read_is_rejected(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())
        original_read = os.read

        def relaxing_read(descriptor: int, length: int) -> bytes:
            data = original_read(descriptor, length)
            if data:
                os.chmod(path, 0o644)
            return data

        try:
            with patch.object(auth.os, "read", side_effect=relaxing_read):
                with self.assertRaises(ValueError):
                    auth.resolve_api_token(None, path)
        finally:
            os.chmod(path, 0o600)

    def test_owner_change_during_read_is_rejected(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())
        original_read = os.read
        original_fstat = os.fstat
        calls = 0

        def owner_changing_fstat(descriptor: int) -> os.stat_result:
            nonlocal calls
            result = original_fstat(descriptor)
            calls += 1
            if calls > 1:
                values = list(result)
                values[stat.ST_UID] = result.st_uid + 1
                return os.stat_result(values)
            return result

        def plain_read(descriptor: int, length: int) -> bytes:
            return original_read(descriptor, length)

        with patch.object(auth.os, "fstat", side_effect=owner_changing_fstat):
            with self.assertRaises(ValueError):
                auth.resolve_api_token(None, path)

    def test_fstat_failure_is_sanitized(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())

        def failing_fstat(descriptor: int) -> os.stat_result:
            raise OSError("injected fstat failure")

        with patch.object(auth.os, "fstat", side_effect=failing_fstat):
            with self.assertRaises(ValueError) as caught:
                auth.resolve_api_token(None, path)
            self.assertNotIn(path, str(caught.exception))

    def test_close_failure_is_sanitized(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())
        original_close = os.close

        def failing_close(descriptor: int) -> None:
            original_close(descriptor)
            raise OSError("injected close failure")

        with patch.object(auth.os, "close", side_effect=failing_close):
            with self.assertRaises(ValueError) as caught:
                auth.resolve_api_token(None, path)
            self.assertNotIn(path, str(caught.exception))

    def test_empty_file_is_rejected_not_unconfigured(self) -> None:
        path = write_token_file(self.directory, "token", b"")
        with self.assertRaises(ValueError):
            auth.resolve_api_token(None, path)

    def test_path_race_symlink_swap_is_rejected(self) -> None:
        token = valid_token()
        real = write_token_file(self.directory, "real", token.encode())
        victim = str(self.directory / "victim")
        os.link(real, victim)
        original_open = os.open

        def swap_to_symlink(path_value: str, flags: int, mode: int = 0o777) -> int:
            os.unlink(victim)
            os.symlink(real, victim)
            return original_open(path_value, flags, mode)

        with patch.object(auth.os, "open", side_effect=swap_to_symlink):
            with self.assertRaises(ValueError):
                auth.resolve_api_token(None, victim)

    def test_opened_descriptor_is_verified_regular(self) -> None:
        token = valid_token()
        path = write_token_file(self.directory, "token", token.encode())
        original_fstat = os.fstat

        def fifo_fstat(descriptor: int) -> os.stat_result:
            result = original_fstat(descriptor)
            values = list(result)
            values[stat.ST_MODE] = stat.S_IFIFO | 0o600
            return os.stat_result(values)

        with patch.object(auth.os, "fstat", side_effect=fifo_fstat):
            with self.assertRaises(ValueError):
                auth.resolve_api_token(None, path)

    def test_errors_never_echo_token_or_path(self) -> None:
        token = valid_token(char="z")
        path = write_token_file(self.directory, "token", token.encode(), 0o644)
        try:
            auth.resolve_api_token(None, path)
        except ValueError as exc:
            self.assertNotIn(token, str(exc))
            self.assertNotIn(path, str(exc))
        else:
            self.fail("expected ValueError")

    def test_non_string_inputs_are_rejected_safely(self) -> None:
        bad_direct: object = 123
        with self.assertRaises((TypeError, ValueError)):
            auth.resolve_api_token(None, bad_direct)
        bad_path: object = None
        with self.assertRaises((TypeError, ValueError)):
            auth.read_token_file(bad_path)


if __name__ == "__main__":
    unittest.main()
