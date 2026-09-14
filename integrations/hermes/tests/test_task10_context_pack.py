from __future__ import annotations

import json
import unittest

from integrations.hermes.context_pack import JsonValue, parse_context_pack


PACK: dict[str, JsonValue] = {
    "schema": "0.2",
    "id": "019d0000-0000-7000-8000-000000000001",
    "generated_at": "2026-09-09T00:00:00Z",
    "query": "hello",
    "client": "hermes",
    "core": [],
    "continuity": [],
    "relevant": [],
    "evidence_handles": [],
    "rendered_markdown": "# LifeDB Context Pack\n\nmarker\n",
    "authorization": {
        "principal": "owner",
        "sensitivity_ceiling": "personal",
    },
    "budget": {
        "budget_chars": 12000,
        "core_chars": 4000,
        "continuity_chars": 2000,
        "relevant_chars": 6000,
        "used_chars": 0,
    },
    "watermark": {"durable_sequence": 1, "indexed_sequence": 1, "dirty": False},
    "truncated": False,
    "degraded": [],
}


def encoded(pack: dict[str, JsonValue] = PACK) -> bytes:
    return json.dumps(pack, separators=(",", ":")).encode()


class Task10ContextPackParserTests(unittest.TestCase):
    def test_valid_pack_preserves_marker_and_schema_extensions(self) -> None:
        pack = dict(PACK)
        pack["extension"] = {"schema_permitted": ["value"]}
        parsed = parse_context_pack(encoded(pack), max_bytes=100_000)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["rendered_markdown"], PACK["rendered_markdown"])
        self.assertEqual(parsed["extension"], {"schema_permitted": ["value"]})

    def test_empty_layers_with_nonempty_rendering_are_valid(self) -> None:
        parsed = parse_context_pack(encoded(), max_bytes=100_000)
        self.assertIsNotNone(parsed)

    def test_recorded_malformed_matrix_is_rejected(self) -> None:
        cases: list[tuple[str, bytes]] = []

        duplicate = b'{"schema":"0.2","schema":"0.2"}'
        cases.append(("duplicate top-level key", duplicate))

        pack = dict(PACK)
        pack["evidence_handles"] = [
            "019d0000-0000-7000-8000-000000000001",
            "019d0000-0000-7000-8000-000000000001",
        ]
        cases.append(("duplicate evidence handle", encoded(pack)))

        for field in ("budget_chars", "core_chars", "continuity_chars", "relevant_chars", "used_chars"):
            pack = json.loads(encoded())
            pack["budget"][field] = True
            cases.append((f"boolean budget {field}", encoded(pack)))
        for field in ("durable_sequence", "indexed_sequence"):
            pack = json.loads(encoded())
            pack["watermark"][field] = False
            cases.append((f"boolean watermark {field}", encoded(pack)))

        pack = json.loads(encoded())
        pack["generated_at"] = "2026-02-30T25:99:99+99:99"
        cases.append(("invalid calendar timestamp", encoded(pack)))

        pack = json.loads(encoded())
        pack["query"] = 7
        cases.append(("wrong query type", encoded(pack)))
        pack = json.loads(encoded())
        pack["authorization"]["destination"] = 7
        cases.append(("wrong authorization optional type", encoded(pack)))
        pack = json.loads(encoded())
        pack["degraded"] = [7]
        cases.append(("wrong degraded item type", encoded(pack)))
        pack = json.loads(encoded())
        pack["truncation"] = [False]
        cases.append(("wrong truncation item type", encoded(pack)))
        pack = json.loads(encoded())
        pack["budget"]["unknown"] = 1
        cases.append(("unknown budget key", encoded(pack)))

        pack = json.loads(encoded())
        pack["rendered_markdown"] = "valid\x01markdown"
        cases.append(("control rendered markdown", encoded(pack)))
        cases.append(("lone surrogate rendered markdown", b'{"rendered_markdown":"\\ud800"}'))

        pack = json.loads(encoded())
        pack["budget"]["budget_chars"] = 1_000_001
        cases.append(("huge budget", encoded(pack)))
        pack = json.loads(encoded())
        pack["budget"]["core_chars"] = 7_000
        pack["budget"]["continuity_chars"] = 7_000
        cases.append(("layer sums exceed budget", encoded(pack)))
        pack = json.loads(encoded())
        pack["budget"]["used_chars"] = 12_001
        cases.append(("used exceeds budget", encoded(pack)))
        pack = json.loads(encoded())
        pack["watermark"]["indexed_sequence"] = 2
        cases.append(("indexed ahead of durable", encoded(pack)))

        for name, raw in cases:
            with self.subTest(name=name):
                self.assertIsNone(parse_context_pack(raw, max_bytes=100_000))

    def test_nested_duplicate_and_nonfinite_values_are_rejected(self) -> None:
        duplicate = encoded()
        duplicate = duplicate[:-1] + b',"authorization":{"principal":"owner","principal":"other","sensitivity_ceiling":"personal"}}'
        self.assertIsNone(parse_context_pack(duplicate, max_bytes=100_000))
        nonfinite = encoded().replace(b'"used_chars":0', b'"used_chars":NaN')
        self.assertIsNone(parse_context_pack(nonfinite, max_bytes=100_000))

    def test_invalid_utf8_and_forbidden_controls_are_rejected(self) -> None:
        self.assertIsNone(parse_context_pack(encoded()[:-1] + b"\xff", max_bytes=100_000))
        for value in ("x\x00", "x\x1f", "x\x7f"):
            pack = dict(PACK)
            pack["rendered_markdown"] = value
            self.assertIsNone(parse_context_pack(encoded(pack), max_bytes=100_000))
        pack = dict(PACK)
        pack["rendered_markdown"] = "tab\tline\nnext\r"
        self.assertIsNotNone(parse_context_pack(encoded(pack), max_bytes=100_000))


if __name__ == "__main__":
    unittest.main()
