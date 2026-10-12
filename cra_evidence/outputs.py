# SPDX-License-Identifier: AGPL-3.0-or-later
"""Files a command promises to write (the pack of `cra pack --out`, the sidecar of `cra sign`, the drop file of
`cra notice`, the seed file of `cra keygen`). A file that cannot be written whole raises OutputNotWritten; the CLI
turns it into exit 74 with a `receipt not written: <reason>` line, like a receipt stdout refused (12/10/2026). Nothing
is left half-written: the bytes go to `<path>.tmp` first and are renamed over the path only once complete."""
from __future__ import annotations

import os


class OutputNotWritten(OSError):
    """an output file the command promises could not be written whole (the command's own refusals stay ValueError)"""


class TipNotWritten(OutputNotWritten):
    """the ledger line IS appended and synced, but the signed tip (`<ledger>.tip.json`) could not be replaced: the
    record is in the chain and the tip still names the previous entry"""


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def write_tmp(path: str, text: str) -> str:
    """write `text` to `<path>.tmp` and return that name; on failure remove it and raise OutputNotWritten"""
    tmp = str(path) + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
    except OSError as e:
        _unlink_quietly(tmp)
        raise OutputNotWritten(f"{path}: {e.strerror or e}") from None
    return tmp


def commit_tmp(tmp: str, path: str) -> None:
    """rename `tmp` over `path`; on failure remove `tmp` and raise OutputNotWritten"""
    try:
        os.replace(tmp, path)
    except OSError as e:
        _unlink_quietly(tmp)
        raise OutputNotWritten(f"{path}: {e.strerror or e}") from None


def write_file(path: str, text: str) -> None:
    """the whole text at `path`, or nothing new there and OutputNotWritten"""
    commit_tmp(write_tmp(path, text), path)


def refuse_directory(path: str) -> None:
    """a path that names a directory (or ends with a separator) can never receive the file: say so before any work"""
    p = str(path)
    if p.endswith(("/", os.sep)) or os.path.isdir(p):
        raise OutputNotWritten(f"{path}: is a directory")
