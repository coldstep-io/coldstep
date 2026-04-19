import unittest
from unittest import mock

from scripts.elon_orchestrator.vault_cli import vault_cli


class VaultCliTests(unittest.TestCase):

    @mock.patch("scripts.elon_orchestrator.vault_cli.subprocess.run")
    def test_passes_subcommand_and_args_unchanged(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout=b"ok\n", stderr=b"")
        vault_cli("open", "wiki/ietf-rfcs")
        called_with = mock_run.call_args.args[0]
        self.assertEqual(called_with[0], "obsidian-cli")
        self.assertIn("open", called_with)
        self.assertIn("wiki/ietf-rfcs", called_with)

    @mock.patch("scripts.elon_orchestrator.vault_cli.subprocess.run")
    def test_returns_completed_process_on_zero_exit(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout=b"hello\n", stderr=b"")
        result = vault_cli("ping")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"hello\n")

    @mock.patch("scripts.elon_orchestrator.vault_cli.subprocess.run")
    def test_does_not_raise_on_nonzero_exit_returns_completed_process(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=2, stdout=b"", stderr=b"err\n")
        result = vault_cli("nonexistent-subcommand")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"err\n")

    @mock.patch("scripts.elon_orchestrator.vault_cli.subprocess.run")
    def test_passes_kwargs_through_to_subprocess_run(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        vault_cli("open", "x", timeout=5)
        self.assertEqual(mock_run.call_args.kwargs.get("timeout"), 5)


if __name__ == "__main__":
    unittest.main()
