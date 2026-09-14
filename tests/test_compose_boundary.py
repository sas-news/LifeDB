from __future__ import annotations

import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).parents[1]
TOKEN_DEST = "/run/secrets/lifedb-api-token"


def load_compose() -> object:
    text = (REPO / "compose.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def service_config() -> dict[str, object]:
    raw: object = load_compose()
    if not isinstance(raw, dict):
        raise TypeError("compose.yaml must be a mapping")
    services = raw.get("services")
    if not isinstance(services, dict):
        raise TypeError("compose.yaml services must be a mapping")
    service = services.get("lifedb")
    if not isinstance(service, dict):
        raise TypeError("compose.yaml must define a lifedb service")
    return service


def environment_entries(service: dict[str, object]) -> list[str]:
    environment = service.get("environment")
    if isinstance(environment, dict):
        return [f"{key}={value}" for key, value in environment.items()]
    if isinstance(environment, list):
        entries: list[str] = []
        for item in environment:
            if not isinstance(item, str):
                raise TypeError("environment entries must be strings")
            entries.append(item)
        return entries
    raise TypeError("environment must be a mapping or a list")


def volume_entries(service: dict[str, object]) -> list[dict[str, object]]:
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        raise TypeError("volumes must be a list")
    entries: list[dict[str, object]] = []
    for item in volumes:
        if not isinstance(item, dict):
            raise TypeError("volume entries must be long-syntax mappings")
        entries.append(item)
    return entries


class ComposeTokenMountTest(unittest.TestCase):
    def test_no_token_value_environment(self) -> None:
        text = (REPO / "compose.yaml").read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            name = stripped.split("=", 1)[0].split(":", 1)[0].strip().strip("'\"")
            self.assertNotEqual(name, "LIFEDB_API_TOKEN")
        self.assertNotIn("${LIFEDB_API_TOKEN:-", text)
        self.assertNotIn("${LIFEDB_API_TOKEN:", text)

    def test_only_container_token_file_path_reaches_service(self) -> None:
        entries = environment_entries(service_config())
        file_entries = [
            entry for entry in entries if entry.startswith("LIFEDB_API_TOKEN_FILE=")
        ]
        self.assertEqual(len(file_entries), 1)
        self.assertEqual(file_entries[0], f"LIFEDB_API_TOKEN_FILE={TOKEN_DEST}")

    def test_token_bind_is_read_only_at_secret_path(self) -> None:
        matches = [
            volume
            for volume in volume_entries(service_config())
            if volume.get("target") == TOKEN_DEST
        ]
        self.assertEqual(len(matches), 1)
        token = matches[0]
        self.assertEqual(token.get("type"), "bind")
        source = token.get("source")
        self.assertIsInstance(source, str)
        assert isinstance(source, str)
        self.assertIn("LIFEDB_API_TOKEN_FILE", source)
        self.assertTrue(token.get("read_only") is True)
        bind = token.get("bind")
        self.assertIsInstance(bind, dict)
        assert isinstance(bind, dict)
        self.assertTrue(bind.get("create_host_path") is False)

    def test_token_source_is_required(self) -> None:
        text = (REPO / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("${LIFEDB_API_TOKEN_FILE:?", text)

    def test_vault_bind_targets_data_and_is_required(self) -> None:
        matches = [
            volume
            for volume in volume_entries(service_config())
            if volume.get("target") == "/data"
        ]
        self.assertEqual(len(matches), 1)
        source = matches[0].get("source")
        self.assertIsInstance(source, str)
        assert isinstance(source, str)
        self.assertIn("LIFEDB_VAULT", source)
        text = (REPO / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("${LIFEDB_VAULT:?", text)
        vault = matches[0].get("bind")
        self.assertIsInstance(vault, dict)
        assert isinstance(vault, dict)
        self.assertTrue(vault.get("create_host_path") is False)


class ComposeHardeningPreservedTest(unittest.TestCase):
    def test_loopback_default_preserved(self) -> None:
        service = service_config()
        ports = service.get("ports")
        self.assertIsInstance(ports, list)
        assert isinstance(ports, list)
        self.assertTrue(
            any(
                isinstance(item, str) and "127.0.0.1" in item
                for item in ports
            )
        )

    def test_configured_nonroot_user_preserved(self) -> None:
        service = service_config()
        user = service.get("user")
        self.assertIsInstance(user, str)
        assert isinstance(user, str)
        self.assertIn("LIFEDB_UID", user)
        self.assertIn("LIFEDB_GID", user)

    def test_readonly_rootfs_tmpfs_capdrop_nonewprivs(self) -> None:
        service = service_config()
        self.assertTrue(service.get("read_only") is True)
        tmpfs = service.get("tmpfs")
        self.assertIsInstance(tmpfs, list)
        assert isinstance(tmpfs, list)
        self.assertTrue(any("/tmp" in str(item) for item in tmpfs))
        cap_drop = service.get("cap_drop")
        self.assertIsInstance(cap_drop, list)
        assert isinstance(cap_drop, list)
        self.assertIn("ALL", cap_drop)
        security_opt = service.get("security_opt")
        self.assertIsInstance(security_opt, list)
        assert isinstance(security_opt, list)
        self.assertIn("no-new-privileges:true", list(security_opt))

    def test_restart_and_healthcheck_preserved(self) -> None:
        service = service_config()
        self.assertEqual(service.get("restart"), "unless-stopped")
        healthcheck = service.get("healthcheck")
        self.assertIsInstance(healthcheck, dict)
        assert isinstance(healthcheck, dict)
        test = healthcheck.get("test")
        self.assertIsInstance(test, list)
        assert isinstance(test, list)
        self.assertTrue(any("/health" in str(item) for item in test))


class ComposeEnvExampleTest(unittest.TestCase):
    def test_production_paths_absolute_and_token_file_documented(self) -> None:
        text = (REPO / ".env.example").read_text(encoding="utf-8")
        vault_lines = [
            line
            for line in text.splitlines()
            if line.strip().startswith("LIFEDB_VAULT=")
        ]
        self.assertEqual(len(vault_lines), 1)
        self.assertTrue(vault_lines[0].split("=", 1)[1].startswith("/"))
        token_lines = [
            line
            for line in text.splitlines()
            if line.strip().startswith("LIFEDB_API_TOKEN_FILE=")
        ]
        self.assertEqual(len(token_lines), 1)
        self.assertTrue(token_lines[0].split("=", 1)[1].startswith("/"))
        value_lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip().startswith("LIFEDB_API_TOKEN=")
        ]
        self.assertEqual(value_lines, [])
        lowered = text.lower()
        self.assertIn("absolute", lowered)
        self.assertIn("0600", text)
        self.assertIn("auth.py", text)
        self.assertIn("lifedb-compose.py", text)
        self.assertIn("docker compose` bypasses", text)


if __name__ == "__main__":
    unittest.main()
