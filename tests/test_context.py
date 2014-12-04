

import pytest
from unittest.mock import MagicMock
from aws_minion.context import Context, ApplicationNotFound


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


def test_get_versions(monkeypatch):

    record = MagicMock()
    record.type = 'CNAME'
    record.identifier = 'app-myapp'
    record.weight = 100

    zone = MagicMock(name='zone')
    zone.get_records.return_value = [record]

    dns_conn = MagicMock(name='dns_conn')
    dns_conn.get_zone.return_value = zone

    monkeypatch.setattr('boto.ec2.autoscale.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.route53.connect_to_region', MagicMock(return_value=dns_conn))
    ctx = Context({'region': 'someregion', 'domain': 'apps.example.com'})
    versions = ctx.get_versions('myapp', '1.0')
    assert versions == []
