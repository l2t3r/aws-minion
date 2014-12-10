

import pytest
from textwrap import dedent
from click.testing import CliRunner
from aws_minion.cli import cli


def test_print_version(monkeypatch):
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--version'], catch_exceptions=False)

    assert 'AWS Minion' in result.output
    assert result.exit_code == 0


def test_configure(monkeypatch):

    monkeypatch.setattr('aws_minion.cli.AWS_CREDENTIALS_PATH', 'aws-credentials')
    monkeypatch.setattr('aws_minion.cli.CONFIG_DIR_PATH', 'config')
    monkeypatch.setattr('aws_minion.cli.CONFIG_FILE_PATH', 'config/aws-minion.yaml')

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('aws-credentials', 'w') as fd:
            fd.write(dedent('''\
                [default]
                aws_access_key_id     = mykey
                aws_secret_access_key = mysecret
                '''))
        result = runner.invoke(cli, ['configure', '--region', 'non-existing-region'], catch_exceptions=False, input='1')

    assert 'Connecting to region non-existing-region.. FAILED' in result.output
    assert result.exit_code == 0