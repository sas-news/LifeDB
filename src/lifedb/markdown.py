from __future__ import annotations

import errno
import os
import stat
from collections.abc import Hashable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


# These limits are deliberately large enough for a human-readable Canon document,
# but small enough that an untrusted document cannot consume unbounded resources.
MAX_MARKDOWN_BYTES = 8 * 1024 * 1024
MAX_FRONTMATTER_BYTES = 1 * 1024 * 1024
MAX_YAML_ALIASES = 50
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 100_000
MAX_YAML_EXPANDED_NODES = 100_000


class StringTimestampSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that keeps timestamps as strings for portability."""


StringTimestampSafeLoader.yaml_implicit_resolvers = {
    key: [
        (tag, regex)
        for tag, regex in resolvers
        if tag != "tag:yaml.org,2002:timestamp"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


class BoundedStringTimestampSafeLoader(StringTimestampSafeLoader):
    """Safe loader with structural limits for untrusted frontmatter.

    PyYAML represents aliases as shared nodes. Merely limiting the source size
    therefore does not bound the logical expansion of an alias graph. The
    composer limits below reject excessive aliases, excessive nesting, cycles,
    and graphs whose expanded traversal would be too large.
    """

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._alias_count = 0
        self._composition_depth = 0
        self._composed_nodes = 0

    def compose_node(self, parent: Node | None, index: Any) -> Node:
        self._composed_nodes += 1
        if self._composed_nodes > MAX_YAML_NODES:
            raise yaml.YAMLError("YAML node limit exceeded")
        if self.check_event(AliasEvent):
            self._alias_count += 1
            if self._alias_count > MAX_YAML_ALIASES:
                raise yaml.YAMLError("YAML alias limit exceeded")

        self._composition_depth += 1
        try:
            if self._composition_depth > MAX_YAML_DEPTH:
                raise yaml.YAMLError("YAML nesting limit exceeded")
            return super().compose_node(parent, index)
        finally:
            self._composition_depth -= 1

    def compose_document(self) -> Node:
        node = super().compose_document()
        self._validate_expanded_graph(node)
        return node

    def construct_mapping(
        self, node: MappingNode, deep: bool = False
    ) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise yaml.YAMLError("expected a YAML mapping")

        # Apply merge keys before checking uniqueness, so an explicit key that
        # ambiguously overrides a merged key also fails closed.
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, Hashable):
                raise yaml.YAMLError("unhashable YAML mapping key")
            if key in mapping:
                raise yaml.YAMLError("duplicate YAML mapping key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping

    @staticmethod
    def _validate_expanded_graph(root: Node) -> None:
        visited = 0
        active: set[int] = set()

        def visit(node: Node, depth: int) -> None:
            nonlocal visited
            visited += 1
            if visited > MAX_YAML_EXPANDED_NODES:
                raise yaml.YAMLError("YAML expanded node limit exceeded")
            if depth > MAX_YAML_DEPTH:
                raise yaml.YAMLError("YAML expanded nesting limit exceeded")

            identity = id(node)
            if identity in active:
                raise yaml.YAMLError("cyclic YAML aliases are not supported")
            if isinstance(node, ScalarNode):
                return

            active.add(identity)
            try:
                if isinstance(node, SequenceNode):
                    for child in node.value:
                        visit(child, depth + 1)
                elif isinstance(node, MappingNode):
                    for key, value in node.value:
                        visit(key, depth + 1)
                        visit(value, depth + 1)
            finally:
                active.remove(identity)

        visit(root, 1)


@dataclass(frozen=True)
class MarkdownDocument:
    path: Path
    frontmatter: dict[str, Any]
    body: str


def _read_regular_file(path: Path) -> bytes:
    """Read a bounded regular file without following a final symlink."""

    initial = os.lstat(path)
    if not stat.S_ISREG(initial.st_mode):
        raise ValueError("Markdown document must be a regular file")
    if initial.st_size > MAX_MARKDOWN_BYTES:
        raise ValueError("Markdown document exceeds the size limit")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise ValueError("Markdown document must be a regular file") from None
        raise

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("Markdown document must be a regular file")
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise ValueError("Markdown document changed while being opened")
        if opened.st_size > MAX_MARKDOWN_BYTES:
            raise ValueError("Markdown document exceeds the size limit")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            data = stream.read(MAX_MARKDOWN_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if len(data) > MAX_MARKDOWN_BYTES:
        raise ValueError("Markdown document exceeds the size limit")
    return data


def _read_regular_descriptor(descriptor: int, initial: os.stat_result) -> bytes:
    """Read one already-open Markdown file and verify its identity/size."""
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        raise ValueError("Markdown document must be a regular file")
    if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
        raise ValueError("Markdown document changed while being opened")
    if opened.st_size > MAX_MARKDOWN_BYTES:
        raise ValueError("Markdown document exceeds the size limit")
    data = b""
    while len(data) <= MAX_MARKDOWN_BYTES:
        chunk = os.read(descriptor, min(64 * 1024, MAX_MARKDOWN_BYTES + 1 - len(data)))
        if not chunk:
            break
        data += chunk
    if len(data) > MAX_MARKDOWN_BYTES:
        raise ValueError("Markdown document exceeds the size limit")
    return data


def _parse_markdown_bytes(path: Path, data: bytes) -> MarkdownDocument:
    """Parse bytes already read from a boundary-checked descriptor."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Markdown document is not valid UTF-8") from None
    if not text.startswith("---\n"):
        raise ValueError("missing opening YAML frontmatter delimiter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError("missing closing YAML frontmatter delimiter")
    raw_frontmatter = text[4:end]
    if len(raw_frontmatter.encode("utf-8")) > MAX_FRONTMATTER_BYTES:
        raise ValueError("YAML frontmatter exceeds the size limit")
    try:
        loaded = yaml.load(raw_frontmatter, Loader=BoundedStringTimestampSafeLoader)
    except (
        yaml.YAMLError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
        MemoryError,
    ):
        raise ValueError("invalid YAML frontmatter") from None
    if not isinstance(loaded, dict):
        raise ValueError("frontmatter must be a mapping")
    return MarkdownDocument(path=path, frontmatter=loaded, body=text[end + 5 :])


def parse_markdown(path: Path) -> MarkdownDocument:
    path = Path(path)
    data = _read_regular_file(path)
    return _parse_markdown_bytes(path, data)


def canon_documents(canon_dir: Path) -> Iterator[MarkdownDocument]:
    """Enumerate Canon documents from a descriptor-rooted directory tree."""
    canon_dir = Path(canon_dir)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_descriptor = os.open(canon_dir, flags)
    except FileNotFoundError:
        return
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            return
        raise

    def walk(directory: int, directory_path: Path) -> Iterator[MarkdownDocument]:
        try:
            # Match os.walk's stable shape: files in this directory first,
            # followed by child directories in lexical order.  The ordering
            # is part of Canon projection determinism.
            entries = sorted(
                os.scandir(directory),
                key=lambda entry: (entry.is_dir(follow_symlinks=False), entry.name),
            )
        except OSError:
            raise ValueError("Canon directory changed while being read") from None
        try:
            for entry in entries:
                name = entry.name
                try:
                    status = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except OSError:
                    raise ValueError("Canon directory entry changed while being read") from None
                if stat.S_ISDIR(status.st_mode):
                    try:
                        child = os.open(name, flags, dir_fd=directory)
                    except OSError:
                        raise ValueError("Canon directory entry changed while being read") from None
                    try:
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
                            raise ValueError("Canon directory entry changed while being read")
                        yield from walk(child, directory_path / name)
                    finally:
                        os.close(child)
                    continue
                if (
                    not name.endswith(".md")
                    or name in {"index.md", "log.md"}
                    or not stat.S_ISREG(status.st_mode)
                ):
                    continue
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=directory,
                    )
                except OSError:
                    raise ValueError("Canon document changed while being read") from None
                try:
                    yield _parse_markdown_bytes(
                        directory_path / name,
                        _read_regular_descriptor(descriptor, status),
                    )
                finally:
                    os.close(descriptor)
        finally:
            pass

    try:
        yield from walk(root_descriptor, canon_dir)
    finally:
        os.close(root_descriptor)
