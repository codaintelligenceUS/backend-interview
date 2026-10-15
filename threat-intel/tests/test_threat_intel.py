"""Sanity tests for the simulated Threat Intel. Not an exercise - they pass as given."""

import pytest
from fastapi.testclient import TestClient

from threat_intel.catalogue import AffectedRange, Catalogue, Cve, Product
from threat_intel.main import MAX_CVE_BATCH_SIZE, create_app
from threat_intel.versions import ComparableVersion, version_in_range

API_KEY = 'test-key'


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(api_key=API_KEY, latency_ms=0))


@pytest.fixture
def auth() -> dict:
    return {'X-API-Key': API_KEY}


# --------------------------------------------------------------------------- #
# Versions
# --------------------------------------------------------------------------- #


def test_versions_compare_numerically_not_lexically():
    assert ComparableVersion('1.10.0') > ComparableVersion('1.9.0')
    assert ComparableVersion('8.0.35') < ComparableVersion('8.4.0')


def test_openssh_style_versions_fall_back_to_segments():
    assert ComparableVersion('9.6p1') > ComparableVersion('9.3p2')
    assert version_in_range('8.9p1', start_including='8.5p1', end_excluding='9.8p1')
    assert not version_in_range('9.9p1', start_including='8.5p1', end_excluding='9.8p1')


def test_range_bounds_are_inclusive_or_exclusive_as_named():
    assert version_in_range('2.4.49', start_including='2.4.49', end_including='2.4.49')
    assert not version_in_range('2.4.56', start_including='2.4.0', end_excluding='2.4.56')
    assert version_in_range('1.0', end_excluding='9.6p1')


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #


def test_catalogue_maps_aliases_and_versions():
    catalogue = Catalogue(
        products=[Product(name='openssh', vendor='openbsd', aliases=('sshd',))],
        cves=[
            Cve('CVE-2024-6387', 's', '2024-07-01T13:15Z', 8.1, 'HIGH',
                affected=(AffectedRange('openssh', version_start_including='8.5p1', version_end_excluding='9.8p1'),)),
        ],
    )

    assert catalogue.map_product('sshd', '8.9p1') == ('cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*', ['CVE-2024-6387'])
    assert catalogue.map_product('SSHD', '9.9p1') == ('cpe:2.3:a:openbsd:openssh:9.9p1:*:*:*:*:*:*:*', [])
    assert catalogue.map_product('legacy-crm', '2.0') == (None, [])
    assert catalogue.map_product('sshd', '') == (None, [])


def test_shipped_catalogue_loads():
    catalogue = Catalogue.load()

    assert len(catalogue) > 20
    cpe, cves = catalogue.map_product('apache2', '2.4.49')
    assert cpe == 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'
    assert 'CVE-2021-41773' in cves and 'CVE-2021-42013' in cves


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


def test_health_needs_no_key_but_everything_else_does(client, auth):
    assert client.get('/api/_health/').status_code == 200
    assert client.get('/api/_health/test-auth/').status_code == 401
    assert client.get('/api/_health/test-auth/', headers={'X-API-Key': 'nope'}).status_code == 401
    assert client.get('/api/_health/test-auth/', headers=auth).status_code == 200


def test_vulnerability_mapping_echoes_items_with_cpe_and_cves(client, auth):
    payload = {
        'os': {'id': 0, 'product_type': 'os', 'product_name': 'ubuntu', 'product_version': '22.04'},
        'applications': [
            {'id': 7, 'product_name': 'nginx', 'product_version': '1.18.0'},
            {'id': 9, 'product_name': 'legacy-crm', 'product_version': '2.0'},
        ],
    }

    response = client.post('/api/linux/vulnerability-mapping/', json=payload, headers=auth)

    assert response.status_code == 200
    body = response.json()
    assert body['os']['cpe'] == 'cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*'
    nginx, crm = body['applications']
    assert nginx['id'] == 7
    assert nginx['cve_list'] == ['CVE-2021-23017', 'CVE-2022-41741', 'CVE-2022-41742']
    assert crm['id'] == 9 and crm['cpe'] is None and crm['cve_list'] == []


def test_cve_list_details_returns_documents_sorted_and_stubs_unknown_ids(client, auth):
    response = client.post(
        '/api/search/cve-list-details/',
        json={'cve_list': ['CVE-2024-6387', 'CVE-1999-0001', 'CVE-2024-6387']},
        headers=auth,
    )

    assert response.status_code == 200
    unknown, known = response.json()
    assert unknown['cve'] == 'CVE-1999-0001' and unknown['impact'] == {}
    assert known['cve'] == 'CVE-2024-6387'
    assert known['impact']['baseMetricV3']['cvssV3']['baseScore'] == 8.1
    assert known['is_weaponized'] is True


def test_cve_list_details_rejects_oversized_batches(client, auth):
    too_many = [f'CVE-2024-{index:04d}' for index in range(MAX_CVE_BATCH_SIZE + 1)]

    response = client.post('/api/search/cve-list-details/', json={'cve_list': too_many}, headers=auth)

    assert response.status_code == 413


def test_single_cve_details_returns_empty_object_for_unknown_id(client, auth):
    assert client.get('/api/search/cve-details/CVE-2024-6387/', headers=auth).json()['cve'] == 'CVE-2024-6387'
    assert client.get('/api/search/cve-details/CVE-1999-0001/', headers=auth).json() == {}
