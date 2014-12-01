import json
import pytest
from unittest.mock import MagicMock
from click.testing import CliRunner
import yaml
from aws_minion.cli import cli
from aws_minion.context import Context, ApplicationVersion, Application


def test_list_versions(monkeypatch):


    auto_scaling_group = MagicMock()
    auto_scaling_group.tags = [MagicMock(key='DockerImage', value='foo/bar:123')]
    auto_scaling_group.desired_capacity = 3

    version = ApplicationVersion('myregion', 'myapp', '1.0', auto_scaling_group)
    version.weight = 120

    context = Context({'region': 'caprica'})
    context.get_versions = lambda: [version]
    context_constructor = lambda x, y: context

    monkeypatch.setattr('aws_minion.cli.Context', context_constructor)

    runner = CliRunner()

    with runner.isolated_filesystem():
        context.write_config('config.yaml')
        result = runner.invoke(cli, ['--config-file', 'config.yaml', 'versions'], catch_exceptions=False)

    lines = result.output.splitlines()
    cols = lines[1].split()
    assert cols == ['myapp', '1.0', 'foo/bar:123', '(no', 'instances)', '3', '60.0']


def test_create_version(monkeypatch):
    subnet = MagicMock()
    subnet.id = 'subnet-mysubnet'
    vpc_conn = MagicMock()
    vpc_conn.get_all_subnets = lambda x: [subnet]

    monkeypatch.setattr('boto.vpc.connect_to_region', vpc_conn)
    monkeypatch.setattr('boto.ec2.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.ec2.autoscale.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.ec2.elb.connect_to_region', MagicMock())
    monkeypatch.setattr('time.sleep', lambda s: s)
    monkeypatch.setattr('aws_minion.cli.map_subnets', lambda s, r: {'public': [subnet], 'private': []})

    security_group = MagicMock()
    security_group.tags = {'Manifest': json.dumps({'exposed_ports': [8080], 'team_name': 'MyTeam'})}

    security_groups = {'app-myapp': security_group, 'app-myapp-lb': MagicMock()}

    auto_scaling_group = MagicMock()
    auto_scaling_group.tags = [MagicMock(key='DockerImage', value='foo/bar:123')]
    auto_scaling_group.desired_capacity = 3

    app = Application('myapp', security_group)

    version = ApplicationVersion('myregion', 'myapp', '1.0', auto_scaling_group)
    version.weight = 120

    context = Context({'region': 'caprica', 'vpc': 'myvpc', 'loggly_auth_token': 'abc'})
    context.get_versions = lambda: [version]
    context.get_application = lambda x: app
    context.get_security_group = lambda x: security_groups.get(x)
    context_constructor = lambda x, y: context

    monkeypatch.setattr('aws_minion.cli.Context', context_constructor)

    runner = CliRunner()

    with runner.isolated_filesystem():
        context.write_config('config.yaml')
        result = runner.invoke(cli, ['--config-file', 'config.yaml', 'versions', 'create', 'myapp', '1.0', 'mydocker:2.3', '-e', 'MY_ENV_VAR=123'], catch_exceptions=False)

    assert 'ABORTED. Default health check time to wait for members to become active has been exceeded.' in result.output
