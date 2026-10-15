"""Contract tests for GET /api/devices/ (Exercise 2).

These tests ARE the specification. They all fail against the endpoint you are
given: it is functionally correct but it runs a handful of queries *per device*,
and every test here caps the whole listing at `MAX_QUERIES`. Make them pass
without changing the response shape. `make seed` gives you enough data to
*feel* the problem: hit `/api/devices/` with `X-Tenant-Id: 1` and read
`elapsed_ms` before you fix it.
"""

import pytest

from inventory.models import Application

from .conftest import DEVICES_URL

pytestmark = pytest.mark.django_db

# The whole listing, however many devices it returns.
MAX_QUERIES = 3


def test_returns_devices_with_application_summaries(
    api_client, tenant, make_device, make_application, django_assert_max_num_queries
):
    device = make_device(tenant=tenant, hostname='web-01')
    make_application(tenant=tenant, device=device, name='nginx', status=Application.StatusType.ONLINE)
    make_application(tenant=tenant, device=device, name='postgres', status=Application.StatusType.OFFLINE)

    with django_assert_max_num_queries(MAX_QUERIES):
        response = api_client.get(DEVICES_URL, headers={'X-Tenant-Id': tenant.id})

    assert response.status_code == 200
    assert response.data['total_count'] == 1
    assert isinstance(response.data['elapsed_ms'], int)

    item = response.data['items'][0]
    assert item['hostname'] == 'web-01'
    assert item['tenant_name'] == tenant.name
    assert item['application_count'] == 2
    assert item['online_count'] == 1
    assert sorted(item['application_names']) == ['nginx', 'postgres']


def test_scopes_devices_to_the_request_tenant(
    api_client, tenant, other_tenant, make_device, django_assert_max_num_queries
):
    make_device(tenant=tenant, hostname='mine')
    make_device(tenant=other_tenant, hostname='theirs')

    with django_assert_max_num_queries(MAX_QUERIES):
        response = api_client.get(DEVICES_URL, headers={'X-Tenant-Id': tenant.id})

    assert [item['hostname'] for item in response.data['items']] == ['mine']


def test_orders_devices_by_hostname(api_client, tenant, make_device, django_assert_max_num_queries):
    make_device(tenant=tenant, hostname='zeta')
    make_device(tenant=tenant, hostname='alpha')

    with django_assert_max_num_queries(MAX_QUERIES):
        response = api_client.get(DEVICES_URL, headers={'X-Tenant-Id': tenant.id})

    assert [item['hostname'] for item in response.data['items']] == ['alpha', 'zeta']


def test_does_not_run_a_query_per_device(
    api_client, tenant, make_device, make_application, django_assert_max_num_queries
):
    for index in range(15):
        device = make_device(tenant=tenant, hostname=f'srv-{index:02d}')
        make_application(tenant=tenant, device=device, name='nginx', status=Application.StatusType.ONLINE)
        make_application(tenant=tenant, device=device, name='sshd')

    # Same budget as every other test here: the cost must not scale with rows.
    with django_assert_max_num_queries(MAX_QUERIES):
        response = api_client.get(DEVICES_URL, headers={'X-Tenant-Id': tenant.id})

    assert response.data['total_count'] == 15
    assert all(item['application_count'] == 2 for item in response.data['items'])
