"""Contract tests for GET /api/applications/ (Exercise 1).

These tests are the specification. They fail against the stub you start from
and the exercise is done when they pass. They are in priority order.
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from inventory.models import Application

from .conftest import APPLICATIONS_URL

pytestmark = pytest.mark.django_db


def test_returns_a_paginated_envelope(api_client, tenant, make_application):
    for index in range(3):
        make_application(tenant=tenant, name=f'app-{index}')

    response = api_client.get(APPLICATIONS_URL, {'size': 2}, headers={'X-Tenant-Id': tenant.id})

    assert response.status_code == 200
    assert response.data['page'] == 1
    assert response.data['total_pages'] == 2
    assert response.data['total_count'] == 3
    assert len(response.data['items']) == 2


def test_returns_the_requested_page(api_client, tenant, make_application):
    for index in range(3):
        make_application(tenant=tenant, name=f'app-{index}')

    response = api_client.get(APPLICATIONS_URL, {'page': 2, 'size': 2}, headers={'X-Tenant-Id': tenant.id})

    assert response.data['page'] == 2
    assert len(response.data['items']) == 1


def test_caps_the_page_size(api_client, tenant, make_application):
    make_application(tenant=tenant)

    response = api_client.get(APPLICATIONS_URL, {'size': 5000}, headers={'X-Tenant-Id': tenant.id})

    # A client must not be able to ask for the whole table in one request.
    assert response.data['total_pages'] == 1
    assert response.status_code == 200


def test_scopes_results_to_the_request_tenant(api_client, tenant, other_tenant, make_application):
    make_application(tenant=tenant, name='mine')
    make_application(tenant=other_tenant, name='theirs')

    response = api_client.get(APPLICATIONS_URL, headers={'X-Tenant-Id': tenant.id})

    assert [item['name'] for item in response.data['items']] == ['mine']


def test_filters_by_name_case_insensitively(api_client, tenant, make_application):
    make_application(tenant=tenant, name='PostgreSQL')
    make_application(tenant=tenant, name='nginx')

    response = api_client.get(APPLICATIONS_URL, {'name': 'gres'}, headers={'X-Tenant-Id': tenant.id})

    assert [item['name'] for item in response.data['items']] == ['PostgreSQL']


def test_filters_by_multiple_statuses(api_client, tenant, make_application):
    make_application(tenant=tenant, name='on', status=Application.StatusType.ONLINE)
    make_application(tenant=tenant, name='off', status=Application.StatusType.OFFLINE)
    make_application(tenant=tenant, name='gone', status=Application.StatusType.DECOMMISSIONED)

    response = api_client.get(APPLICATIONS_URL, {'status': 'online,offline'}, headers={'X-Tenant-Id': tenant.id})

    assert sorted(item['name'] for item in response.data['items']) == ['off', 'on']


def test_search_matches_name_and_device_hostname(api_client, tenant, make_device, make_application):
    make_application(tenant=tenant, device=make_device(tenant=tenant, hostname='db-01'), name='postgres')
    make_application(tenant=tenant, device=make_device(tenant=tenant, hostname='web-01'), name='nginx')

    by_name = api_client.get(APPLICATIONS_URL, {'search': 'postg'}, headers={'X-Tenant-Id': tenant.id})
    by_hostname = api_client.get(APPLICATIONS_URL, {'search': 'web'}, headers={'X-Tenant-Id': tenant.id})

    assert [item['name'] for item in by_name.data['items']] == ['postgres']
    assert [item['name'] for item in by_hostname.data['items']] == ['nginx']


def test_defaults_to_newest_discovered_first(api_client, tenant, make_application):
    now = timezone.now()
    make_application(tenant=tenant, name='older', discovered_on=now - timedelta(days=5))
    make_application(tenant=tenant, name='newer', discovered_on=now - timedelta(days=1))

    response = api_client.get(APPLICATIONS_URL, headers={'X-Tenant-Id': tenant.id})

    assert [item['name'] for item in response.data['items']] == ['newer', 'older']


def test_orders_by_device_hostname(api_client, tenant, make_device, make_application):
    make_application(tenant=tenant, device=make_device(tenant=tenant, hostname='zeta'), name='last')
    make_application(tenant=tenant, device=make_device(tenant=tenant, hostname='alpha'), name='first')

    response = api_client.get(APPLICATIONS_URL, {'ordering': 'hostname'}, headers={'X-Tenant-Id': tenant.id})

    assert [item['name'] for item in response.data['items']] == ['first', 'last']


def test_serializes_display_labels_and_derived_fields(api_client, tenant, make_device, make_application):
    device = make_device(tenant=tenant, hostname='web-01')
    make_application(
        tenant=tenant,
        device=device,
        name='nginx',
        version='1.18.0',
        status=Application.StatusType.NOT_SEEN,
        risk_level=Application.RiskLevelType.HIGH,
        is_scanned=True,
    )

    response = api_client.get(APPLICATIONS_URL, headers={'X-Tenant-Id': tenant.id})
    item = response.data['items'][0]

    assert item['hostname'] == 'web-01'
    assert item['device_id'] == device.id
    assert item['version'] == '1.18.0'
    # Human readable labels, not raw DB values.
    assert item['status'] == 'Not Seen on Last Scan'
    assert item['risk_level'] == 'High'
    assert item['scan_type'] == 'Scanned'


def test_scan_type_is_discovered_until_scanned(api_client, tenant, make_application):
    make_application(tenant=tenant, is_scanned=False)

    response = api_client.get(APPLICATIONS_URL, headers={'X-Tenant-Id': tenant.id})
    item = response.data['items'][0]

    assert item['scan_type'] == 'Discovered'
    assert item['last_scanned'] is None


def test_does_not_run_a_query_per_row(api_client, tenant, make_device, make_application, django_assert_max_num_queries):
    device = make_device(tenant=tenant)
    for index in range(20):
        make_application(tenant=tenant, device=device, name=f'app-{index}')

    # One count + one page of rows. Reading the hostname must not cost 20 extra queries.
    with django_assert_max_num_queries(4):
        response = api_client.get(APPLICATIONS_URL, headers={'X-Tenant-Id': tenant.id})

    assert len(response.data['items']) == 20
