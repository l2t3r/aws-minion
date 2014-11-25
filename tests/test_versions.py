import pytest
from unittest.mock import MagicMock
from click.testing import CliRunner
from aws_minion.cli import cli


def test_list_versions(monkeypatch):

    context = MagicMock()

    monkeypatch.setattr('aws_minion.cli.Context', context)

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['versions'], catch_exceptions=False)
        print(result.output)
