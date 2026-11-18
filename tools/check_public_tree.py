# SPDX-License-Identifier: GPL-3.0-only
"""Screen Git publication candidates for common privacy leaks, without printing their contents."""

import argparse
import codecs
import os
import re
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath


PRIVATE_NAMES = {
    "certificate.dat", "credentials.json", ".git-credentials", ".netrc", "_netrc",
    "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
}
PRIVATE_EXTENSIONS = {".pem", ".key", ".ppk", ".pfx", ".p12", ".cer", ".crt"}
PRIVATE_DIRS = {".local", "tdata", "xwechat_files", "wechat files"}
ARTIFACT_EXTENSIONS = {
    ".exe", ".msi", ".msix", ".dll", ".sys", ".pdb", ".obj", ".ilk", ".dmp", ".etl", ".log", ".pyc",
}
PATTERNS = {
    "personal home path": re.compile(
        r"(?:\b[A-Z]:[\\/]+Users[\\/]+|(?<![\w/])/(?:home|Users)/)"
        r"(?!(?:Public|Default(?: User)?|All Users)(?:[\\/\s]|$))"
        r"[\w][\w.\-]*", re.IGNORECASE,
    ),
    "private key header": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    "credential token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{28,}|github_pat_[A-Za-z0-9_]{40,}|"
        r"(?:AKIA|ASIA)[A-Z0-9]{16}|sk-(?:proj-|svcacct-)?[\w-]{24,}|"
        r"xox[baprs]-[\w-]{16,})", re.ASCII,
    ),
}


def path_issue(name):
    path = PurePosixPath(name.casefold())
    if (PRIVATE_DIRS.intersection(path.parts) or path.name == "sandboxie.ini"
            or ("handoff" in path.name and path.suffix == ".md")):
        return "private project material"
    if (path.name in PRIVATE_NAMES or path.suffix in PRIVATE_EXTENSIONS
            or {".ssh", ".aws"}.intersection(path.parts)
            or (path.name.split(".")[:2] == ["", "env"]
                and path.suffix not in {".example", ".sample", ".template"})):
        return "credential or certificate file"
    if path.suffix in ARTIFACT_EXTENSIONS:
        return "build artifact or log"
    return None


def content_issues(stream):
    # Incremental decoding also covers Windows tools that emit UTF-16 with a BOM.
    head = stream.read(4)
    encoding = "utf-16" if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8"
    decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
    found = set()
    tail = decoder.decode(head)
    while True:
        chunk = stream.read(65536)
        text = tail + decoder.decode(chunk, final=not chunk)
        found.update(label for label, pattern in PATTERNS.items() if pattern.search(text))
        if not chunk:
            return found
        tail = text[-256:]


def git(*args, cwd=None):
    return subprocess.check_output(["git", *args], cwd=cwd, stderr=subprocess.DEVNULL)


def staged_files(root):
    for entry in git("ls-files", "--stage", "-z", cwd=root).split(b"\0"):
        if entry:
            meta, raw_name = entry.split(b"\t", 1)
            mode, oid, stage = meta.split()
            if stage != b"0":
                raise ValueError("unmerged index")
            if mode != b"160000":  # Gitlinks contain a commit ID and no file contents.
                yield os.fsdecode(raw_name), oid.decode("ascii")


def index_issues(root, oid):
    with subprocess.Popen(
        ["git", "cat-file", "blob", oid], cwd=root, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        issues = content_issues(process.stdout)
        if process.wait():
            raise ValueError("unreadable index blob")
    return issues


def worktree_issues(root, name):
    path = root
    for part in PurePosixPath(name).parts:
        path = path / part
        try:
            info = path.lstat()
        except FileNotFoundError:
            return set()  # Unstaged deletion.
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            # Only a link's text would be published by Git. Never follow it.
            if path != root / name or not stat.S_ISLNK(info.st_mode):
                return {"uninspectable redirected path"}
            target = os.readlink(path)
            return {label for label, pattern in PATTERNS.items() if pattern.search(target)}
    if not stat.S_ISREG(info.st_mode):
        return set() if path.is_dir() else {"uninspectable file"}
    with path.open("rb") as stream:
        return content_issues(stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="scan the complete index snapshot")
    args = parser.parse_args()
    root = Path(os.fsdecode(git("rev-parse", "--show-toplevel").rstrip(b"\r\n")))
    if args.staged:
        candidates = staged_files(root)
    else:
        names = git("ls-files", "-z", "--cached", "--others", "--exclude-standard", cwd=root)
        candidates = ((os.fsdecode(name), None) for name in names.split(b"\0") if name)
    counts = Counter()
    checked = 0
    for name, oid in candidates:
        checked += 1
        issue = path_issue(name)
        if issue:
            counts[issue] += 1
        else:
            counts.update(index_issues(root, oid) if oid else worktree_issues(root, name))
    print(f"Public tree screen: {checked} Git candidates")
    for issue, count in sorted(counts.items()):
        print(f"{issue}: {count}")
    return int(bool(counts))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        sys.exit("Public tree screen could not inspect the Git snapshot.")
