#!/usr/bin/env python3
# Copyright (c) 2026 Alexandru Iosif Mocanu (Sonelu). All rights reserved.
"""
Automated test suite for Athena-CLI v2.0.
Verifies command routing, help/version outputs, typo suggestions, and all 14 tools.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import athena  # noqa: E402


class TestAthenaCLI(unittest.TestCase):
    """Unit and integration tests for Athena-CLI."""

    def test_version_flag(self):
        self.assertEqual(athena.main(["--version"]), 0)
        self.assertEqual(athena.main(["-V"]), 0)
        self.assertEqual(athena.main(["version"]), 0)

    def test_help_flag(self):
        self.assertEqual(athena.main(["--help"]), 0)
        self.assertEqual(athena.main(["-h"]), 0)
        self.assertEqual(athena.main(["help"]), 0)

    def test_list_command(self):
        self.assertEqual(athena.main(["list"]), 0)

    def test_web_command(self):
        self.assertEqual(athena.main(["web"]), 0)

    def test_unknown_command_returns_error(self):
        self.assertEqual(athena.main(["nonexistent-tool-xyz"]), 1)

    def test_typo_suggestion(self):
        self.assertEqual(athena.suggest("pcpa"), "pcap")
        self.assertEqual(athena.suggest("phsh"), "phish")
        self.assertEqual(athena.suggest("headrs"), "headers")
        self.assertIsNone(athena.suggest("zzzzzzzzzzz"))

    def test_split_args_preserves_paths(self):
        args = athena.split_args('"my folder/file.txt" --demo')
        self.assertEqual(args, ["my folder/file.txt", "--demo"])

    def test_all_14_tool_scripts_exist(self):
        self.assertEqual(len(athena.COMMANDS), 14)
        for name, team, rel_script, _syntax, _desc, _ex in athena.COMMANDS:
            script_path = athena.TOOLS_DIR / rel_script
            self.assertTrue(
                script_path.is_file(),
                f"Missing script for '{name}' ({team}): {script_path}",
            )

    def test_all_14_tools_help_subcommand(self):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", NO_COLOR="1")
        for name, _team, _script, _syntax, _desc, _ex in athena.COMMANDS:
            with self.subTest(tool=name):
                proc = subprocess.run(
                    [sys.executable, str(BASE_DIR / "athena.py"), name, "--help"],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=15,
                )
                self.assertEqual(
                    proc.returncode,
                    0,
                    f"Tool '{name} --help' failed with code {proc.returncode}: {proc.stderr}",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
