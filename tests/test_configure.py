

import pytest
from textwrap import dedent
from click.testing import CliRunner
from aws_minion.cli import cli


def test_configure(monkeypatch):

    monkeypatch.setattr('aws_minion.cli.AWS_CREDENTIALS_PATH', 'aws-credentials')

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('aws-credentials', 'w') as fd:
            fd.write(dedent('''\
                [default]
                aws_access_key_id     = mykey
                aws_secret_access_key = mysecret
                '''))
        result = runner.invoke(cli, ['configure', '--region', 'non-existing-region', '--vpc', 'vpc-abc123', '--domain', 'apps.example.org'], catch_exceptions=False, input='n')

    assert 'Connecting to region non-existing-region.. FAILED' in result.output
    assert result.exit_code == 0