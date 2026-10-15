from collections.abc import Callable
from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from inventory import threat_intel_client
from inventory.models import Application, Device, Tenant

from .fake_threat_intel import FakeThreatIntel, make_fake_threat_intel

APPLICATIONS_URL = '/api/applications/'
DEVICES_URL = '/api/devices/'


def checkin_url(agent_guid: str) -> str:
    return f'/api/agent/{agent_guid}/checkin/'


def scan_url(device_id: int) -> str:
    return f'/api/devices/{device_id}/vulnerability-scan/'


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def tenant(db) -> Tenant:
    return Tenant.objects.create(name='Acme Industries')


@pytest.fixture
def other_tenant(db) -> Tenant:
    return Tenant.objects.create(name='Globex')


@pytest.fixture
def make_device(db) -> Callable[..., Device]:
    def _make_device(
        tenant: Tenant,
        hostname: str = 'srv-01',
        agent_guid: str | None = None,
        os_name: str = 'Ubuntu',
        os_version: str = '22.04',
    ) -> Device:
        return Device.objects.create(
            tenant=tenant,
            hostname=hostname,
            ip_address='10.0.0.1',
            agent_guid=agent_guid,
            os_name=os_name,
            os_version=os_version,
        )

    return _make_device


@pytest.fixture
def make_application(db, make_device) -> Callable[..., Application]:
    def _make_application(tenant: Tenant, device: Device | None = None, **kwargs) -> Application:
        device = device or make_device(tenant=tenant)
        now = timezone.now()
        defaults = {
            'name': 'nginx',
            'discovered_on': now - timedelta(days=1),
            'last_seen': now,
        }

        return Application.objects.create(tenant=tenant, device=device, **{**defaults, **kwargs})

    return _make_application


@pytest.fixture
def threat_intel(monkeypatch) -> FakeThreatIntel:
    """The in-process Threat Intel of Exercise 4, injected wherever `get_threat_intel_client` is looked up."""
    fake = make_fake_threat_intel()

    monkeypatch.setattr(threat_intel_client, 'get_threat_intel_client', lambda: fake.client)
    # In case the view imported the function by name rather than the module.
    from inventory import vulnerability_scan_view

    monkeypatch.setattr(vulnerability_scan_view, 'get_threat_intel_client', lambda: fake.client, raising=False)

    return fake
