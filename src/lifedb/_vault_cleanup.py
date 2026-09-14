from __future__ import annotations

import os


def discard_temp_at(parent_fd: int, temp_name: str) -> None:
    try:
        os.unlink(temp_name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
