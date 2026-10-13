# SPDX-License-Identifier: AGPL-3.0-or-later
"""Files a command promises to write (the pack of `cra pack --out`, the sidecar of `cra sign`, the drop file of
`cra notice`, the seed file of `cra keygen`). A file that cannot be written whole raises OutputNotWritten; the CLI
turns it into exit 74 with a `receipt not written: <reason>` line, like a receipt stdout refused (12/10/2026). Nothing
is left half-written: the bytes go to a temporary file of a name nobody can predict, created with O_EXCL in the same
folder (`<path>.<16 hex>.tmp`: a symlink or FIFO planted at a predictable `<path>.tmp` was followed or blocked the run
until 0.5.1), written in a loop that checks the count, fsynced and closed, and renamed over the path only once
complete."""
from __future__ import annotations

import os
import secrets


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


def write_tmp(path: str, text) -> str:
    """write `text` (str as UTF-8, or bytes) to a new temporary file next to `path` and return its name; on failure remove it and raise
    OutputNotWritten. The name is `<path>.<16 random hex>.tmp`, created with O_CREAT|O_EXCL (never an existing file, a
    symlink or a FIFO); the mode is 0666 less the umask, as `open(path, "w")` gives."""
    data = memoryview(text if isinstance(text, bytes) else text.encode("utf-8"))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    tmp = f"{path}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(tmp, flags, 0o666)
    except OSError as e:
        raise OutputNotWritten(f"{path}: {e.strerror or e}") from None
    try:
        try:
            while data:
                n = os.write(fd, data)
                if n <= 0:
                    raise OSError(f"short write: {len(data)} bytes not written")
                data = data[n:]
            os.fsync(fd)
        finally:
            os.close(fd)   # inside the try: a deferred error (NFS, a full disk at close) is a failed write too
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
