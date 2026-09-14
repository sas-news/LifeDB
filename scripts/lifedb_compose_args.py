"""Parse and reject unsafe Docker Compose run options."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


BOUNDARY_MOUNTS = frozenset({"/data", "/run/secrets/lifedb-api-token"})


class ComposeArgumentError(ValueError):
    """A protected Compose run option was supplied."""
BOUNDARY_ENV = frozenset(
    {
        "LIFEDB_API_TOKEN",
        "LIFEDB_API_TOKEN_FILE",
        "LIFEDB_VAULT",
        "LIFEDB_UID",
        "LIFEDB_GID",
        "LIFEDB_BIND",
        "LIFEDB_PORT",
        "LIFEDB_SERVER_BIND",
    }
)
FORBIDDEN_RUN_OPTIONS = frozenset(
    {
        "--user",
        "-u",
        "--entrypoint",
        "--privileged",
        "--cap-add",
        "--security-opt",
        "--publish",
        "-p",
        "--expose",
        "--service-ports",
        "--network",
        "--volumes-from",
        "--device",
    }
)
RUN_OPTIONS_WITH_VALUES = frozenset(
    {
        "--name",
        "--workdir",
        "-w",
        "--env",
        "-e",
        "--env-from-file",
        "--label",
        "-l",
        "--volume",
        "-v",
        "--mount",
        "--entrypoint",
        "--user",
        "-u",
        "--cap-add",
        "--cap-drop",
        "--security-opt",
        "--publish",
        "-p",
        "--expose",
        "--network",
        "--volumes-from",
        "--device",
        "--pid",
        "--uts",
        "--ipc",
        "--dns",
        "--dns-search",
        "--add-host",
        "--stop-signal",
        "--pull",
        "--scale",
        "--index",
    }
)


def _option_and_value(argument: str) -> tuple[str, str | None]:
    if argument.startswith("--") and "=" in argument:
        return argument.split("=", 1)
    for option in RUN_OPTIONS_WITH_VALUES:
        if option.startswith("-") and not option.startswith("--") and argument.startswith(option):
            suffix = argument[len(option) :]
            if suffix:
                return option, suffix
    return argument, None


def _mount_target(value: str) -> str:
    fields: Mapping[str, str] = {
        key: part.split("=", 1)[1]
        for part in value.split(",")
        if "=" in part
        for key in (part.split("=", 1)[0],)
    }
    for key in ("target", "destination", "dst"):
        if key in fields:
            return fields[key]
    return ""


def _volume_target(value: str) -> str:
    if ":" not in value:
        return ""
    parts = value.rsplit(":", 2)
    return parts[-1] if len(parts) == 2 else parts[-2]


def _reject_run_option(option: str, value: str | None) -> None:
    if option in FORBIDDEN_RUN_OPTIONS:
        raise ComposeArgumentError("service security overrides are not supported")
    if option in {"-e", "--env"} and value is not None:
        if value.split("=", 1)[0] in BOUNDARY_ENV:
            raise ComposeArgumentError("service environment overrides are not supported")
    if option in {"-v", "--volume", "--mount"} and value is not None:
        target = _mount_target(value) if option == "--mount" else _volume_target(value)
        if target in BOUNDARY_MOUNTS:
            raise ComposeArgumentError("service mount overrides are not supported")


def reject_run_overrides(arguments: Sequence[str]) -> None:
    """Reject protected Compose run options before the service name."""

    try:
        run_index = arguments.index("run")
    except ValueError:
        return
    run_arguments = arguments[run_index + 1 :]
    index = 0
    while index < len(run_arguments):
        argument = run_arguments[index]
        if argument == "--" or not argument.startswith("-"):
            return
        option, value = _option_and_value(argument)
        _reject_run_option(option, value)
        if value is None and option in RUN_OPTIONS_WITH_VALUES:
            if index + 1 >= len(run_arguments):
                raise ComposeArgumentError("Compose run option is missing a value")
            value = run_arguments[index + 1]
            _reject_run_option(option, value)
            index += 1
        index += 1
