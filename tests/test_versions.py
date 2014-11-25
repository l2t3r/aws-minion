import pytest
from unittest.mock import MagicMock
from click.testing import CliRunner
from aws_minion.cli import cli
from aws_minion.context import Context, ApplicationVersion


def test_list_versions(monkeypatch):


    auto_scaling_group = MagicMock()
    auto_scaling_group.tags = [MagicMock(key='DockerImage', value='foo/bar:123')]
    auto_scaling_group.desired_capacity = 3

    version = ApplicationVersion('myregion', 'myapp', '1.0', auto_scaling_group)
    version.weight = 120

    context = Context({})
    context.get_versions = lambda: [version]
    context_constructor = lambda x: context

    monkeypatch.setattr('aws_minion.cli.Context', context_constructor)

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['versions'], catch_exceptions=False)

    lines = result.output.splitlines()
    cols = lines[1].split()
    assert cols == ['myapp', '1.0', 'foo/bar:123', '(no', 'instances)', '3', '60.0']
