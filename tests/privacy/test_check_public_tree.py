# SPDX-License-Identifier: GPL-3.0-only
import codecs
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[2]
SCANNER = PROJECT / "tools" / "check_public_tree.py"
HANDOFF = "Example_Handoff.md"
FAKE_TOKEN = "ghp_" + "z" * 36


class PublicTreeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def check(self, *options):
        proc = subprocess.run(
            [sys.executable, str(SCANNER), *options], cwd=self.root,
            text=True, capture_output=True,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def test_index_is_independent_of_worktree(self):
        self.put("sample.md", FAKE_TOKEN.encode())
        self.git("add", "sample.md")
        self.put("sample.md", b"clean")
        self.assertEqual(self.check()[0], 0)
        status, output = self.check("--staged")
        self.assertEqual(status, 1)
        self.assertIn("credential token", output)
        self.assertNotIn(FAKE_TOKEN, output)
        self.git("add", "sample.md")
        self.put("sample.md", FAKE_TOKEN.encode())
        self.assertEqual(self.check("--staged")[0], 0)
        self.assertEqual(self.check()[0], 1)

    def test_ignored_then_force_added_files(self):
        names = [
            HANDOFF, ".local/report.txt", "tdata/state", "xwechat_files/file",
            "Sandboxie.ini", "Certificate.dat", "key.pfx", ".env", "app.exe", "run.log",
        ]
        self.put(".gitignore", (PROJECT / ".gitignore").read_bytes())
        self.put(".env.example", b"EXAMPLE=value")  # Public configuration template.
        for name in names:
            self.put(name, FAKE_TOKEN.encode())
        self.assertEqual(self.check()[0], 0)
        self.git("add", "-f", "--", *names)
        for options in [(), ("--staged",)]:
            status, output = self.check(*options)
            self.assertEqual(status, 1)
            self.assertIn("private project material: 5", output)
            self.assertIn("credential or certificate file: 3", output)
            self.assertIn("build artifact or log: 2", output)
            self.assertNotIn("credential token", output)
            self.assertNotIn(HANDOFF, output)

    def test_synthetic_content_and_encoding_boundaries(self):
        sample_path = "C:" + "\\Users\\" + "synthetic-person" + "\\demo"
        # Split the key marker at the read boundary.
        pem_header = "-----BEGIN " + "OPENSSH " + "PRIVATE KEY-----"
        self.put("sample.md", b" " * 65532 + pem_header.encode())
        self.put("sample.ini", codecs.BOM_UTF16_LE + sample_path.encode("utf-16-le"))
        status, output = self.check()
        self.assertEqual(status, 1)
        self.assertIn("personal home path: 1", output)
        self.assertIn("private key header: 1", output)
        self.assertNotIn("synthetic-person", output)
        self.assertNotIn(pem_header, output)

    def test_symlink_does_not_expose_ignored_target(self):
        self.put(".gitignore", b"/.local/\n")
        self.put(".local/notes", FAKE_TOKEN.encode())
        try:
            os.symlink(".local/notes", self.root / "link")
        except OSError:
            self.skipTest("symlinks unavailable to this account")
        self.assertEqual(self.check()[0], 0)


if __name__ == "__main__":
    unittest.main()
