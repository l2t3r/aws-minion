import json
from unittest.mock import MagicMock, Mock
from click.testing import CliRunner
import collections
from aws_minion.cli import cli, map_subnets, PERCENT_RESOLUTION
from aws_minion.context import Context, ApplicationVersion, Application


def test_versions_list(monkeypatch):
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
        result = runner.invoke(cli, ['-p', 'default', '--config-file', 'config.yaml', 'versions'], catch_exceptions=False)

    lines = result.output.splitlines()
    cols = lines[1].split()
    assert cols == ['myapp', '1.0', 'foo/bar:123', '(no', 'instances)', '3', '60.0']


def test_versions_create(monkeypatch):
    subnet = MagicMock()
    subnet.id = 'subnet-mysubnet'
    vpc_conn = MagicMock()
    vpc_conn.get_all_subnets = lambda x: [subnet]

    monkeypatch.setattr('boto.vpc.connect_to_region', vpc_conn)
    monkeypatch.setattr('boto.ec2.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.route53.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.ec2.autoscale.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.ec2.elb.connect_to_region', MagicMock())
    monkeypatch.setattr('time.sleep', lambda s: s)
    monkeypatch.setattr('aws_minion.cli.map_subnets', lambda s, r: {'public': [subnet], 'shared': [], 'private': []})

    security_group = MagicMock()
    security_group.tags = {'Manifest': json.dumps({'exposed_ports': [8080], 'team_name': 'MyTeam'})}

    security_groups = {'app-myapp': security_group, 'app-myapp-lb': MagicMock()}

    auto_scaling_group = MagicMock()
    auto_scaling_group.tags = [MagicMock(key='DockerImage', value='foo/bar:123')]
    auto_scaling_group.desired_capacity = 3

    app = Application('myapp', security_group)

    version = ApplicationVersion('myregion', 'myapp', '1.0', auto_scaling_group)
    version.weight = 120

    context = Context({'region': 'caprica', 'vpc': 'myvpc', 'loggly_auth_token': 'abc', 'domain': 'mydomain'})
    context.get_versions = lambda: [version]
    context.get_application = lambda x: app
    context.get_security_group = lambda x: security_groups.get(x)
    context_constructor = lambda x, y: context

    monkeypatch.setattr('aws_minion.cli.Context', context_constructor)

    runner = CliRunner()

    with runner.isolated_filesystem():
        context.write_config('config.yaml')
        result = runner.invoke(cli, ['-p', 'default', '--config-file', 'config.yaml', 'versions', 'create', 'myapp', '1.0',
                                     'mydocker:2.3', '-e', 'MY_ENV_VAR=123'],
                               catch_exceptions=False)

    assert 'ABORTED. Default health check time to wait for members to become active has been exceeded.' in result.output


def test_map_subnets_empty():
    res = map_subnets([], [])
    assert res == {'public': [], 'shared': [], 'private': []}


def test_versions_traffic(monkeypatch):
    monkeypatch.setattr('boto.vpc.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.ec2.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.ec2.autoscale.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.ec2.elb.connect_to_region', MagicMock())
    monkeypatch.setattr('time.sleep', lambda s: s)

    security_group = MagicMock()
    security_group.tags = {'Manifest': json.dumps({'exposed_ports': [8080], 'team_name': 'MyTeam'})}

    security_groups = {'app-myapp': security_group, 'app-myapp-lb': MagicMock()}

    auto_scaling_group = MagicMock()
    auto_scaling_group.tags = [MagicMock(key='DockerImage', value='foo/bar:123')]
    auto_scaling_group.desired_capacity = 3

    app = Application('myapp', security_group)

    # start creating mocking of the route53 record sets and Application Versions
    # this is a lot of dirty and nasty code. Please, somebody help this code.
    versions = [ApplicationVersion('myregion', 'myapp', '1.0', auto_scaling_group),
                ApplicationVersion('myregion', 'myapp', '2.0', auto_scaling_group),
                ApplicationVersion('myregion', 'myapp', '3.0', auto_scaling_group),
                ApplicationVersion('myregion', 'myapp', '4.0', auto_scaling_group),
                ]
    versions[0].weight = 60 * PERCENT_RESOLUTION
    versions[1].weight = 30 * PERCENT_RESOLUTION
    versions[2].weight = 10 * PERCENT_RESOLUTION
    versions[3].weight = 0

    r53conn = Mock(name='r53conn')
    rr = MagicMock()
    records = collections.OrderedDict((versions[i].dns_identifier,
                                       MagicMock(weight=versions[i].weight,
                                                 identifier=versions[i].dns_identifier
                                                 )) for i in (0, 1, 2, 3))

    rr.__iter__ = lambda x: iter(records.values())
    for r in rr:
        r.name = "myapp.example.org."
        r.type = "CNAME"

    def add_change(op, dns_name, rtype, ttl, identifier, weight):
        if op == 'CREATE':
            x = MagicMock(weight=weight, identifier=identifier)
            x.name = "myapp.example.org"
            x.type = "CNAME"
            records[identifier] = x
        return Mock(name='change')

    def add_change_record(op, record):
        if op == 'DELETE':
            records[record.identifier].weight = 0
        elif op == 'USPERT':
            assert records[record.identifier].weight == record.weight

    rr.add_change = add_change
    rr.add_change_record = add_change_record

    r53conn().get_zone().get_records.return_value = rr
    monkeypatch.setattr('boto.route53.connect_to_region', r53conn)

    context = Context({'region': 'caprica', 'vpc': 'myvpc', 'loggly_auth_token': 'abc', 'domain': 'example.org'})
    context.get_versions = lambda v=None: versions
    context.get_application = lambda x: app
    context.get_security_group = lambda x: security_groups.get(x)
    context_constructor = Mock(return_value=context)

    monkeypatch.setattr('aws_minion.cli.Context', context_constructor)

    runner = CliRunner()

    common_opts = ['-p', 'default', '--config-file', 'config.yaml', 'versions', 'traffic', 'myapp']

    def run(opts):
        return runner.invoke(cli, common_opts + opts, catch_exceptions=False)

    with runner.isolated_filesystem():
        context.write_config('config.yaml')

        run(['4.0', '100'])

        ri = iter(rr)
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 200

        run(['3.0', '10'])
        ri = iter(rr)
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 20
        assert next(ri).weight == 180

        run(['2.0', '0.5'])
        ri = iter(rr)
        assert next(ri).weight == 0
        assert next(ri).weight == 1
        assert next(ri).weight == 20
        assert next(ri).weight == 179

        run(['1.0', '1'])
        ri = iter(rr)
        assert next(ri).weight == 2
        assert next(ri).weight == 1
        assert next(ri).weight == 19
        assert next(ri).weight == 178

        run(['4.0', '95'])
        ri = iter(rr)
        assert next(ri).weight == 1
        assert next(ri).weight == 1
        assert next(ri).weight == 13
        assert next(ri).weight == 185

        run(['4.0', '100'])
        ri = iter(rr)
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 200

        run(['4.0', '10'])
        ri = iter(rr)
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 200

        run(['4.0', '0'])
        ri = iter(rr)
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 0
        assert next(ri).weight == 0
