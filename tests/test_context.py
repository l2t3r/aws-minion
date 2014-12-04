

import pytest
from unittest.mock import MagicMock
from aws_minion.context import Context, ApplicationNotFound, ApplicationVersion


def test_get_application_not_found(monkeypatch):
    monkeypatch.setattr('boto.ec2.connect_to_region', MagicMock())

    ctx = Context({'region': 'someregion'})
    with pytest.raises(ApplicationNotFound):
        ctx.get_application('myapp-non-existing')


def test_get_applications(monkeypatch):
    conn = MagicMock(name='conn')
    sg1 = MagicMock(name='invalid sg')
    sg2 = MagicMock(name='valid sg')
    sg2.name = 'app-myapp'
    sg2.tags = {'Manifest': 'a: b'}
    sg2.vpc_id = 'myvpc'
    sg3 = MagicMock(name='another invalid sg')
    sg3.name = 'app-myapp-db'
    sg3.vpc_id = 'myvpc'
    conn.get_all_security_groups.return_value = [sg1, sg2, sg3]
    monkeypatch.setattr('boto.ec2.connect_to_region', MagicMock(name='connect_to_region', return_value=conn))
    ctx = Context({'region': 'someregion', 'domain': 'apps.example.com', 'vpc': 'myvpc'})
    apps = ctx.get_applications()
    assert len(apps) == 1

    app = ctx.get_application('myapp')
    assert app == apps[0]


def test_get_versions(monkeypatch):

    record = MagicMock()
    record.type = 'CNAME'
    record.identifier = 'app-myapp'
    record.weight = 100

    zone = MagicMock(name='zone')
    zone.get_records.return_value = [record]

    dns_conn = MagicMock(name='dns_conn')
    dns_conn.get_zone.return_value = zone


    group = MagicMock(name='auto scale group')
    group.name = 'app-myapp-1.0'


    autoscale = MagicMock(name='autoscale_conn')
    autoscale.get_all_groups.return_value = [group]

    monkeypatch.setattr('boto.ec2.autoscale.connect_to_region', MagicMock(return_value=autoscale))
    monkeypatch.setattr('boto.route53.connect_to_region', MagicMock(return_value=dns_conn))
    ctx = Context({'region': 'someregion', 'domain': 'apps.example.com'})
    versions = ctx.get_versions('myapp', '0.1')
    assert versions == []

    versions = ctx.get_versions('myapp', '1.0')
    assert len(versions) == 1
    assert versions[0].application_name == 'myapp'
    assert versions[0].version == '1.0'

    version = ctx.get_version('myapp', '1.0')
    assert version == versions[0]

    with pytest.raises(Exception):
        ctx.get_version('non-existing-app', '0.1')


def test_sort_versions():
    unsorted = [
        ApplicationVersion('myreg', 'myapp', '0.10', MagicMock()),
        ApplicationVersion('myreg', 'myapp', '0.1', MagicMock()),
        ApplicationVersion('myreg', 'myapp', '0.2', MagicMock()),
    ]
    unsorted.sort()
    # TODO: ...


def test_get_instances(monkeypatch):
    conn = MagicMock(name='conn')
    instance = MagicMock(name='instance')
    instance.tags = {'Name': 'app-myapp-123'}
    instance.vpc_id = 'myvpc'
    instance.id = 'myid'
    conn.get_only_instances.return_value = [instance]
    monkeypatch.setattr('boto.ec2.connect_to_region', MagicMock(name='connect_to_region', return_value=conn))

    ctx = Context({'region': 'someregion', 'domain': 'apps.example.com', 'vpc': 'myvpc'})
    instances = ctx.get_instances()
    assert len(instances) == 1

    instance = ctx.get_instance_by_id('myid')
    assert instance.tags == instances[0].tags

    assert ctx.get_instance_by_id('000') is None
