"""An in-process Threat Intel for the tests of Exercise 4.

It is the real simulated Threat Intel (`threat-intel/threat_intel`) running inside the test
process behind an httpx transport, with a small, explicit catalogue so every
test can read which CVE affects which version. On top of that the transport:

  * records every request, so a test can check what was sent;
  * can play dead (`down = True`) or die after N requests (`fail_after = N`);
  * shuffles the order of mapped applications; Threat Intel does not promise to keep
    the order it was given, so neither does this.
"""

import json
from dataclasses import dataclass, field

import anyio.from_thread
import httpx

from threat_intel.catalogue import AffectedRange, Catalogue, Cve, Product
from threat_intel.main import create_app
from inventory.threat_intel_client import ThreatIntelClient

API_KEY = 'test-threat-intel-key'

# The catalogue, spelled out. "<" and ">=" below read as NVD ranges.
CATALOGUE = Catalogue(
    products=[
        Product(name='nginx', vendor='nginx'),
        Product(name='openssh', vendor='openbsd', aliases=('sshd',)),
        Product(name='redis', vendor='redis', aliases=('redis-server',)),
        Product(name='rabbitmq', vendor='vmware'),
        # A product with far more CVEs than fit in one details request.
        Product(name='bulky', vendor='acme'),
    ],
    cves=[
        # nginx
        Cve('CVE-2021-23017', 'nginx resolver overflow', '2021-06-01T13:15Z', 7.7, 'HIGH',
            affected=(AffectedRange('nginx', version_end_excluding='1.20.1'),)),
        Cve('CVE-2022-41741', 'nginx mp4 memory corruption', '2022-10-19T22:15Z', 7.8, 'HIGH',
            affected=(AffectedRange('nginx', version_start_including='1.1.3', version_end_excluding='1.23.2'),)),
        # openssh
        Cve('CVE-2024-6387', 'regreSSHion', '2024-07-01T13:15Z', 8.1, 'HIGH', is_weaponized=True,
            affected=(AffectedRange('openssh', version_start_including='8.5p1', version_end_excluding='9.8p1'),)),
        Cve('CVE-2023-48795', 'Terrapin', '2023-12-18T16:15Z', 5.9, 'MEDIUM',
            affected=(AffectedRange('openssh', version_end_excluding='9.6p1'),)),
        # redis
        Cve('CVE-2025-49844', 'Redis Lua use-after-free', '2025-10-03T18:15Z', 10.0, 'CRITICAL', is_weaponized=True,
            affected=(AffectedRange('redis', version_end_excluding='8.2.2'),)),
        Cve('CVE-2023-28425', 'Redis MSETNX crash', '2023-03-20T22:15Z', 6.5, 'MEDIUM',
            affected=(AffectedRange('redis', version_start_including='7.0.8', version_end_excluding='7.0.10'),)),
        # rabbitmq
        Cve('CVE-2025-30219', 'RabbitMQ management XSS', '2025-04-01T21:15Z', 4.8, 'MEDIUM',
            affected=(AffectedRange('rabbitmq', version_end_excluding='4.0.3'),)),
        # bulky: 150 low-severity CVEs, every version affected
        *[
            Cve(f'CVE-2030-{index:04d}', f'bulky issue {index}', '2030-01-01T00:00Z', 3.0, 'LOW',
                affected=(AffectedRange('bulky'),))
            for index in range(1, 151)
        ],
    ],
)

# Expected mappings, for reference:
#   nginx 1.18.0     -> CVE-2021-23017, CVE-2022-41741      (max 7.8  -> high)
#   nginx 1.22.1     -> CVE-2022-41741                      (max 7.8  -> high)
#   nginx 1.26.1     -> nothing                             (          -> none)
#   sshd 9.5p1       -> CVE-2024-6387, CVE-2023-48795       (max 8.1  -> high)
#   sshd 9.9p1       -> nothing
#   redis-server 7.0.9 -> CVE-2025-49844, CVE-2023-28425    (max 10.0 -> critical)
#   rabbitmq 3.13.0  -> CVE-2025-30219                      (max 4.8  -> medium)
#   bulky 1.0        -> CVE-2030-0001 .. CVE-2030-0150      (max 3.0  -> low)


@dataclass
class RecordedRequest:
    method: str
    path: str
    body: dict | None


@dataclass
class FakeThreatIntel:
    """Handle on the in-process Threat Intel: the client to inject, and what it saw."""

    client: ThreatIntelClient
    requests: list[RecordedRequest] = field(default_factory=list)
    down: bool = False
    fail_after: int | None = None

    @property
    def mapping_requests(self) -> list[dict]:
        return [request.body or {} for request in self.requests if 'vulnerability-mapping' in request.path]

    @property
    def detail_requests(self) -> list[list[str]]:
        return [(request.body or {})['cve_list'] for request in self.requests if 'cve-list-details' in request.path]


class _RecordingAsgiTransport(httpx.BaseTransport):
    """Runs the ASGI app synchronously for `httpx.Client`, recording as it goes."""

    def __init__(self, app, state: FakeThreatIntel) -> None:
        self._asgi = httpx.ASGITransport(app=app)
        self._state = state

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self._state.requests.append(RecordedRequest(request.method, request.url.path, body))

        if self._state.down or (self._state.fail_after is not None and len(self._state.requests) > self._state.fail_after):
            raise httpx.ConnectError('Threat Intel is down', request=request)

        with anyio.from_thread.start_blocking_portal() as portal:
            response = portal.call(self._asgi.handle_async_request, request)
            content = portal.call(response.aread)

        if 'vulnerability-mapping' in request.url.path and response.status_code == 200:
            payload = json.loads(content)
            payload['applications'].reverse()
            content = json.dumps(payload).encode()

        return httpx.Response(status_code=response.status_code, headers=response.headers, content=content)


def make_fake_threat_intel() -> FakeThreatIntel:
    state = FakeThreatIntel(client=None)  # type: ignore[arg-type]
    transport = _RecordingAsgiTransport(create_app(catalogue=CATALOGUE, api_key=API_KEY, latency_ms=0), state)
    state.client = ThreatIntelClient(base_url='http://threat_intel.test', api_key=API_KEY, transport=transport)
    return state
