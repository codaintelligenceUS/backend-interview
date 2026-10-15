"""Contract tests for POST /api/agent/<guid>/checkin/ (Exercise 3).

These tests are the specification. They fail against the stub you start from
and the exercise is done when they pass. They are in priority order: make the
first ones pass first.
"""

from datetime import datetime, timezone

import pytest

from inventory.models import Application, Device

from .conftest import checkin_url

pytestmark = pytest.mark.django_db

GUID = '6f1c2a3e-agent-0001'
T1 = '2026-10-15T10:00:00Z'
T2 = '2026-10-15T11:00:00Z'
T3 = '2026-10-15T12:00:00Z'


def as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def payload(reported_at: str = T1, applications: list[dict] | None = None, **overrides) -> dict:
    return {
        'reported_at': reported_at,
        'hostname': 'acme-lt-042',
        'ip_address': '10.1.2.3',
        'os': {'name': 'Ubuntu', 'version': '22.04'},
        'applications': [{'name': 'nginx', 'version': '1.24.0'}, {'name': 'sshd', 'version': '9.6p1'}]
        if applications is None
        else applications,
        **overrides,
    }


def agent_apps(device: Device) -> dict[tuple[str, str], Application]:
    return {(app.name, app.version): app for app in device.applications.all()}


def test_first_checkin_creates_the_device_and_its_applications(api_client, tenant):
    response = api_client.post(checkin_url(GUID), payload(), format='json', headers={'X-Tenant-Id': tenant.id})

    assert response.status_code == 201
    device = Device.objects.get(tenant=tenant, agent_guid=GUID)
    assert response.data == {
        'device_id': device.id,
        'created': True,
        'applications': {'added': 2, 'seen': 0, 'offline': 0},
    }
    assert (device.hostname, device.ip_address) == ('acme-lt-042', '10.1.2.3')
    assert (device.os_name, device.os_version) == ('Ubuntu', '22.04')
    assert device.last_checkin == as_datetime(T1)

    apps = agent_apps(device)
    assert set(apps) == {('nginx', '1.24.0'), ('sshd', '9.6p1')}
    nginx = apps[('nginx', '1.24.0')]
    assert nginx.tenant_id == tenant.id
    assert nginx.status == Application.StatusType.ONLINE
    assert nginx.discovered_on == nginx.last_seen == as_datetime(T1)


def test_second_checkin_updates_the_existing_device(api_client, tenant):
    api_client.post(checkin_url(GUID), payload(T1), format='json', headers={'X-Tenant-Id': tenant.id})

    response = api_client.post(
        checkin_url(GUID), payload(T2, hostname='acme-lt-042-renamed'), format='json', headers={'X-Tenant-Id': tenant.id}
    )

    assert response.status_code == 200
    assert response.data['created'] is False
    assert Device.objects.filter(tenant=tenant).count() == 1
    device = Device.objects.get(agent_guid=GUID)
    assert device.hostname == 'acme-lt-042-renamed'
    assert device.last_checkin == as_datetime(T2)


def test_applications_are_diffed_not_replaced(api_client, tenant):
    api_client.post(checkin_url(GUID), payload(T1), format='json', headers={'X-Tenant-Id': tenant.id})
    nginx_id = Application.objects.get(name='nginx').id

    response = api_client.post(
        checkin_url(GUID),
        payload(T2, applications=[{'name': 'nginx', 'version': '1.24.0'}, {'name': 'redis-server', 'version': '7.2.4'}]),
        format='json',
        headers={'X-Tenant-Id': tenant.id},
    )

    assert response.data['applications'] == {'added': 1, 'seen': 1, 'offline': 1}
    apps = agent_apps(Device.objects.get(agent_guid=GUID))
    assert len(apps) == 3

    nginx = apps[('nginx', '1.24.0')]
    assert nginx.id == nginx_id, 'a seen application is updated, not re-created'
    assert nginx.status == Application.StatusType.ONLINE
    assert nginx.discovered_on == as_datetime(T1)
    assert nginx.last_seen == as_datetime(T2)

    sshd = apps[('sshd', '9.6p1')]
    assert sshd.status == Application.StatusType.OFFLINE
    assert sshd.last_seen == as_datetime(T1), 'an application that went missing keeps its last sighting'

    redis = apps[('redis-server', '7.2.4')]
    assert redis.status == Application.StatusType.ONLINE
    assert redis.discovered_on == redis.last_seen == as_datetime(T2)


def test_a_new_version_is_a_new_application(api_client, tenant):
    api_client.post(checkin_url(GUID), payload(T1), format='json', headers={'X-Tenant-Id': tenant.id})

    api_client.post(
        checkin_url(GUID),
        payload(T2, applications=[{'name': 'nginx', 'version': '1.26.1'}]),
        format='json',
        headers={'X-Tenant-Id': tenant.id},
    )

    apps = agent_apps(Device.objects.get(agent_guid=GUID))
    assert apps[('nginx', '1.24.0')].status == Application.StatusType.OFFLINE
    assert apps[('nginx', '1.26.1')].status == Application.StatusType.ONLINE


def test_an_application_that_comes_back_is_online_again(api_client, tenant):
    api_client.post(checkin_url(GUID), payload(T1), format='json', headers={'X-Tenant-Id': tenant.id})
    api_client.post(checkin_url(GUID), payload(T2, applications=[]), format='json', headers={'X-Tenant-Id': tenant.id})

    response = api_client.post(checkin_url(GUID), payload(T3), format='json', headers={'X-Tenant-Id': tenant.id})

    assert response.data['applications'] == {'added': 0, 'seen': 2, 'offline': 0}
    nginx = agent_apps(Device.objects.get(agent_guid=GUID))[('nginx', '1.24.0')]
    assert nginx.status == Application.StatusType.ONLINE
    assert nginx.discovered_on == as_datetime(T1)
    assert nginx.last_seen == as_datetime(T3)


def test_rejects_payloads_older_than_the_last_checkin(api_client, tenant):
    api_client.post(checkin_url(GUID), payload(T2), format='json', headers={'X-Tenant-Id': tenant.id})

    response = api_client.post(
        checkin_url(GUID),
        payload(T1, hostname='stale', applications=[]),
        format='json',
        headers={'X-Tenant-Id': tenant.id},
    )

    assert response.status_code == 409
    device = Device.objects.get(agent_guid=GUID)
    assert device.hostname == 'acme-lt-042'
    assert device.last_checkin == as_datetime(T2)
    assert all(app.status == Application.StatusType.ONLINE for app in device.applications.all())


def test_rejects_malformed_payloads_but_not_well_formed_ones(api_client, tenant):
    broken = payload()
    del broken['applications']

    response = api_client.post(checkin_url(GUID), broken, format='json', headers={'X-Tenant-Id': tenant.id})

    assert response.status_code == 400
    assert not Device.objects.exists()

    # Validation must not get in the way of a correct payload.
    response = api_client.post(checkin_url(GUID), payload(), format='json', headers={'X-Tenant-Id': tenant.id})

    assert response.status_code == 201
    assert Device.objects.filter(tenant=tenant, agent_guid=GUID).exists()


def test_the_same_guid_is_a_different_device_in_another_tenant(api_client, tenant, other_tenant):
    api_client.post(checkin_url(GUID), payload(), format='json', headers={'X-Tenant-Id': tenant.id})

    response = api_client.post(checkin_url(GUID), payload(), format='json', headers={'X-Tenant-Id': other_tenant.id})

    assert response.status_code == 201
    assert Device.objects.filter(agent_guid=GUID).count() == 2
    theirs = Device.objects.get(tenant=other_tenant, agent_guid=GUID)
    assert theirs.applications.count() == 2
    assert all(app.tenant_id == other_tenant.id for app in theirs.applications.all())


def test_does_not_run_a_query_per_application(api_client, tenant, django_assert_max_num_queries):
    first = [{'name': f'pkg-{index}', 'version': '1.0'} for index in range(40)]
    api_client.post(checkin_url(GUID), payload(T1, applications=first), format='json', headers={'X-Tenant-Id': tenant.id})

    # 20 kept, 20 gone, 20 new. The budget is the same whether that is 60 or 6000.
    second = first[:20] + [{'name': f'pkg-{index}', 'version': '1.0'} for index in range(40, 60)]
    with django_assert_max_num_queries(10):
        response = api_client.post(
            checkin_url(GUID), payload(T2, applications=second), format='json', headers={'X-Tenant-Id': tenant.id}
        )

    assert response.data['applications'] == {'added': 20, 'seen': 20, 'offline': 20}
