"""HTTP client for Threat Intel, the vulnerability intelligence service. Given.

Threat Intel answers two questions the Platform API cares about:

  * `vulnerability_mapping`: "here is what runs on a device, which CPEs and
    CVEs does that correspond to?" One request per device, every application
    tagged with an `id` so the answer can be matched back to the row it came
    from. Threat Intel does not promise to keep the order you sent.
  * `cve_list_details`: "tell me about these CVEs". At most
    `settings.THREAT_INTEL_MAX_CVE_BATCH_SIZE` ids per request; Threat Intel answers 413
    for more. Unknown ids come back as stubs with no score.

Errors are mapped to two exceptions so callers can tell "Threat Intel is down"
(`ThreatIntelUnavailable`) from "Threat Intel did not like the request"
(`ThreatIntelRequestRejected`).

Always get the client through `get_threat_intel_client()`. The tests swap it for one
wired to an in-process Threat Intel; `make dev` points it at the one on :8001.
"""

from collections.abc import Iterable
from dataclasses import dataclass

import httpx
from django.conf import settings


class ThreatIntelError(Exception):
    """Base class for anything that goes wrong talking to Threat Intel."""


class ThreatIntelUnavailable(ThreatIntelError):
    """Threat Intel could not be reached, timed out, or answered 5xx."""


class ThreatIntelRequestRejected(ThreatIntelError):
    """Threat Intel answered 4xx: the request itself is wrong (bad key, batch too large...)."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f'{status_code}: {detail}')
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class CveDetails:
    """A CVE as the Platform API needs it. `cvss_base` is None when Threat Intel has no score for it."""

    cve: str
    summary: str
    cvss_base: float | None
    cvss_severity: str
    is_weaponized: bool
    published: str | None


def _flatten_cve_document(document: dict) -> CveDetails:
    """Threat Intel serves the legacy NVD 1.1 layout; pull out the handful of fields we keep."""
    descriptions = document.get('cve-data', {}).get('description', {}).get('description_data', [])
    cvss = document.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})

    return CveDetails(
        cve=document['cve'],
        summary=next((item['value'] for item in descriptions if item.get('lang') == 'en'), ''),
        cvss_base=cvss.get('baseScore'),
        cvss_severity=cvss.get('baseSeverity', ''),
        is_weaponized=bool(document.get('is_weaponized', False)),
        published=document.get('publishedDate'),
    )


class ThreatIntelClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._http = httpx.Client(
            base_url=base_url,
            headers={'X-API-Key': api_key},
            timeout=timeout,
            transport=transport,
        )

    def _request(self, method: str, path: str, json: dict | None = None) -> httpx.Response:
        try:
            response = self._http.request(method, path, json=json)
        except httpx.HTTPError as error:
            raise ThreatIntelUnavailable(f'{method} {path}: {error.__class__.__name__}') from error

        if response.status_code >= 500:
            raise ThreatIntelUnavailable(f'{method} {path}: HTTP {response.status_code}')
        if response.status_code >= 400:
            try:
                detail = response.json().get('detail', response.text)
            except ValueError:
                detail = response.text
            raise ThreatIntelRequestRejected(response.status_code, str(detail))

        return response

    def health(self) -> dict:
        return self._request('GET', '/api/_health/test-auth/').json()

    def vulnerability_mapping(self, payload: dict, os_family: str = 'linux') -> dict:
        """Map a device's OS and applications to CPEs and CVE ids.

        `payload` is `{"os": {...} | None, "applications": [{...}]}` where each
        item is `{"id": int, "product_type": "os" | "application",
        "product_name": str, "product_version": str}`.

        Returns the same structure with `cpe` (str or None) and `cve_list`
        (list of CVE ids) added to every item. Match them back by `id`.
        """
        return self._request('POST', f'/api/{os_family}/vulnerability-mapping/', json=payload).json()

    def cve_list_details(self, cve_ids: Iterable[str]) -> list[CveDetails]:
        """Details for a batch of CVE ids. The batch must not exceed
        `settings.THREAT_INTEL_MAX_CVE_BATCH_SIZE`; chunking is the caller's job."""
        documents = self._request('POST', '/api/search/cve-list-details/', json={'cve_list': list(cve_ids)}).json()
        return [_flatten_cve_document(document) for document in documents]


def get_threat_intel_client() -> ThreatIntelClient:
    """The client for the Threat Intel this deployment talks to."""
    return ThreatIntelClient(
        base_url=settings.THREAT_INTEL_URL,
        api_key=settings.THREAT_INTEL_API_KEY,
        timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS,
    )
