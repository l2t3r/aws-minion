

import pytest
from unittest.mock import MagicMock
from aws_minion.context import Context, ApplicationNotFound


def test_get_application_not_found(monkeypatch):
    monkeypatch.setattr('boto.ec2.connect_to_region', MagicMock())

    ctx = Context({'region': 'someregion'})
    with pytest.raises(ApplicationNotFound):
        ctx.get_application('myapp-non-existing')


def test_get_versions(monkeypatch):
    monkeypatch.setattr('boto.ec2.autoscale.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.route53.connect_to_region', MagicMock())
    ctx = Context({'region': 'someregion', 'domain': 'apps.example.com'})
    versions = ctx.get_versions('myapp', '1.0')
    assert versions == []
