from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import lifedb.markdown as markdown_module
from lifedb.markdown import (
    MAX_FRONTMATTER_BYTES,
    MAX_MARKDOWN_BYTES,
    MAX_YAML_ALIASES,
    canon_documents,
    parse_markdown,
)


def _write_document(path: Path, frontmatter: str, body: str = "body\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")


class MarkdownBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_parse_preserves_unknown_fields_and_timestamp_strings(self) -> None:
        path = self.root / "normal.md"
        _write_document(
            path,
            "title: Example\n"
            "observed_at: 2026-09-02T12:34:56Z\n"
            "future-field:\n"
            "  nested: [preserved, 7]",
        )

        document = parse_markdown(path)

        self.assertEqual(document.frontmatter["observed_at"], "2026-09-02T12:34:56Z")
        self.assertEqual(
            document.frontmatter["future-field"], {"nested": ["preserved", 7]}
        )
        self.assertEqual(document.body, "body\n")

    def test_parse_rejects_file_symlink(self) -> None:
        target = self.root / "target.md"
        link = self.root / "link.md"
        _write_document(target, "title: Target")
        link.symlink_to(target)

        with self.assertRaisesRegex(ValueError, "regular file"):
            parse_markdown(link)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO is not supported")
    def test_parse_rejects_fifo_without_opening_it(self) -> None:
        fifo = self.root / "pipe.md"
        os.mkfifo(fifo)

        with self.assertRaisesRegex(ValueError, "regular file"):
            parse_markdown(fifo)

    def test_parse_rejects_oversized_document_before_reading(self) -> None:
        path = self.root / "large.md"
        with path.open("wb") as stream:
            stream.truncate(MAX_MARKDOWN_BYTES + 1)

        with self.assertRaisesRegex(ValueError, "size limit"):
            parse_markdown(path)

    def test_parse_rejects_oversized_frontmatter(self) -> None:
        path = self.root / "large-frontmatter.md"
        value = "x" * MAX_FRONTMATTER_BYTES
        path.write_text(f"---\nvalue: {value}\n---\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "frontmatter.*size limit"):
            parse_markdown(path)

    def test_parse_normalizes_malformed_utf8(self) -> None:
        path = self.root / "invalid.md"
        path.write_bytes(b"---\ntitle: invalid\n---\n\xff")

        with self.assertRaisesRegex(ValueError, "not valid UTF-8") as raised:
            parse_markdown(path)
        self.assertNotIn("\\xff", str(raised.exception))

    def test_parse_normalizes_yaml_errors_without_echoing_content(self) -> None:
        path = self.root / "invalid-yaml.md"
        secret_marker = "DO_NOT_ECHO_THIS_VALUE"
        _write_document(path, f"title: [{secret_marker}")

        with self.assertRaisesRegex(ValueError, "^invalid YAML frontmatter$") as raised:
            parse_markdown(path)
        self.assertNotIn(secret_marker, str(raised.exception))

    def test_parse_normalizes_yaml_constructor_errors(self) -> None:
        path = self.root / "invalid-constructor.md"
        _write_document(path, "value: " + ("9" * 5_000))

        with self.assertRaisesRegex(ValueError, "^invalid YAML frontmatter$"):
            parse_markdown(path)

    def test_parse_rejects_duplicate_top_level_key(self) -> None:
        path = self.root / "duplicate-top.md"
        _write_document(path, "title: First\ntitle: Second")

        with self.assertRaisesRegex(ValueError, "^invalid YAML frontmatter$"):
            parse_markdown(path)

    def test_parse_rejects_duplicate_nested_key(self) -> None:
        path = self.root / "duplicate-nested.md"
        _write_document(
            path,
            "x-lifedb:\n"
            "  claims:\n"
            "    - id: first\n"
            "      state: active\n"
            "      state: disputed",
        )

        with self.assertRaisesRegex(ValueError, "^invalid YAML frontmatter$"):
            parse_markdown(path)

    def test_parse_normalizes_unhashable_mapping_key(self) -> None:
        path = self.root / "complex-key.md"
        secret_marker = "DO_NOT_ECHO_COMPLEX_KEY"
        _write_document(path, f"? [{secret_marker}]\n: value")

        with self.assertRaisesRegex(ValueError, "^invalid YAML frontmatter$") as raised:
            parse_markdown(path)
        self.assertNotIn(secret_marker, str(raised.exception))

    def test_parse_rejects_alias_bomb(self) -> None:
        path = self.root / "aliases.md"
        aliases = "\n".join(f"  - *shared" for _ in range(MAX_YAML_ALIASES + 1))
        _write_document(path, f"shared: &shared value\naliases:\n{aliases}")

        with self.assertRaisesRegex(ValueError, "^invalid YAML frontmatter$"):
            parse_markdown(path)

    def test_parse_rejects_large_logical_alias_expansion(self) -> None:
        path = self.root / "expanded-aliases.md"
        levels = ["level0: &level0 [base]"]
        for level in range(1, 6):
            references = ", ".join([f"*level{level - 1}"] * 10)
            levels.append(f"level{level}: &level{level} [{references}]")
        _write_document(path, "\n".join(levels))

        # This uses exactly 50 aliases, so the expanded-graph budget (rather
        # than the simple alias counter) is what rejects it.
        with self.assertRaisesRegex(ValueError, "^invalid YAML frontmatter$"):
            parse_markdown(path)

    def test_parse_rejects_deeply_nested_yaml(self) -> None:
        path = self.root / "deep.md"
        # Each nested sequence adds one composer level. This is intentionally
        # beyond the public limit without being a large input.
        nested = "value"
        for _ in range(70):
            nested = f"[{nested}]"
        _write_document(path, f"nested: {nested}")

        with self.assertRaisesRegex(ValueError, "^invalid YAML frontmatter$"):
            parse_markdown(path)

    def test_canon_walk_is_deterministic_and_skips_special_entries(self) -> None:
        canon = self.root / "canon"
        _write_document(canon / "zeta.md", "title: Zeta")
        _write_document(canon / "alpha.md", "title: Alpha")
        _write_document(canon / "nested" / "inside.md", "title: Inside")
        _write_document(canon / "index.md", "title: Index")

        outside = self.root / "outside"
        _write_document(outside / "escaped.md", "title: Escaped")
        (canon / "linked-directory").symlink_to(outside, target_is_directory=True)
        (canon / "linked-file.md").symlink_to(outside / "escaped.md")
        if hasattr(os, "mkfifo"):
            os.mkfifo(canon / "pipe.md")

        first = [
            document.path.relative_to(canon).as_posix()
            for document in canon_documents(canon)
        ]
        second = [
            document.path.relative_to(canon).as_posix()
            for document in canon_documents(canon)
        ]

        self.assertEqual(first, second)
        self.assertEqual(first, ["alpha.md", "zeta.md", "nested/inside.md"])
        self.assertNotIn("linked-directory/escaped.md", first)
        self.assertNotIn("linked-file.md", first)
        self.assertNotIn("pipe.md", first)

    def test_canon_root_symlink_is_not_traversed(self) -> None:
        actual = self.root / "actual"
        _write_document(actual / "document.md", "title: Actual")
        linked_root = self.root / "linked-canon"
        linked_root.symlink_to(actual, target_is_directory=True)

        self.assertEqual(list(canon_documents(linked_root)), [])

    def test_canon_walk_keeps_descriptor_boundary_when_parent_is_swapped(self) -> None:
        canon = self.root / "canon"
        _write_document(canon / "inside.md", "title: Inside")
        outside = self.root / "outside"
        _write_document(outside / "inside.md", "title: Outside")
        saved = self.root / "canon.saved"
        original_stat = os.stat
        swapped = False

        def swap_before_file_stat(name, *, dir_fd=None, follow_symlinks=True):
            nonlocal swapped
            result = original_stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
            if name == "inside.md" and dir_fd is not None and not swapped:
                swapped = True
                canon.rename(saved)
                canon.symlink_to(outside, target_is_directory=True)
            return result

        with patch.object(markdown_module.os, "stat", side_effect=swap_before_file_stat):
            documents = list(canon_documents(canon))

        self.assertTrue(swapped)
        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0].frontmatter["title"], "Inside")


if __name__ == "__main__":
    unittest.main()
