Two services, both simulated and both small:

- **Platform API** (`api/`) - the Django REST API that knows about tenants, their
  devices and the applications running on them. SQLite, no auth, no Celery.
- **Threat Intel** (`threat-intel/`) - the FastAPI vulnerability intelligence service. It
  turns "nginx 1.18.0" into a CPE and a list of CVEs, and serves CVE details.
  A JSON file stands in for Elasticsearch.

The exercises live on the Platform API side. Threat Intel is given; you talk to it.

The tests check behaviour and, where it matters, query counts. They never check
how you got there: plain Python over a queryset is as valid as any ORM feature,
so use what you know rather than what you think is expected.

## Setup

Requirements: **Python 3.10+**. That's it - everything is installed into the
repo (`.venv`).

```bash
make setup     # venv + pip install + migrate + seed
make dev       # Platform API on :8000, Threat Intel on :8001
```

To run the two servers separately, e.g. in two terminals:

```bash
make dev-api            # Platform API only, on :8000
make dev-threat-intel   # simulated Threat Intel only, on :8001
```

Using VS Code or another Pylance/pyright editor? Pick `.venv/bin/python` as the
interpreter; `pyrightconfig.json` already points the language server at `api/`
and `threat-intel/` and the venv ships Django and DRF type stubs, so imports resolve
and hover shows real types.

No `make`? The same thing by hand:

```bash
python3 -m venv .venv && .venv/bin/pip install -r api/requirements.txt -r threat-intel/requirements.txt
cd api && ../.venv/bin/python manage.py migrate && ../.venv/bin/python manage.py seed
../.venv/bin/python manage.py runserver 8000
# in a second terminal
cd threat-intel && ../.venv/bin/uvicorn threat_intel.main:app --port 8001
```

On Windows, `make` doesn't exist and the virtualenv puts its executables in
`.venv\Scripts\` rather than `.venv/bin/`. Run the commands above with that
path, or use WSL / Git Bash if you already have one set up.

The database is a gitignored `api/db.sqlite3` file, populated by a seed command:

```bash
make seed        # wipe and re-create the demo data (migrates first if needed)
make reset-db    # delete the database file and rebuild it from scratch
```

Tenancy: there is no login. Send `X-Tenant-Id: 1` (Acme, 2400 devices) or
`X-Tenant-Id: 2` (Globex, 5 devices). The API must never leak across that line.

## Knowing when you're done

```bash
make test        # everything
make test-api           # the Platform API suite - the exercises' spec
make test-threat-intel  # Threat Intel's own sanity tests - green as given, not an exercise
```

Every exercise endpoint can also be poked from a shell while `make dev` runs;
each exercise below shows how. Both servers publish interactive docs too, with
every route, its parameters and a ready-to-send example:

- Platform API: http://localhost:8000/api/docs/ - click **Authorize** once to set
  `X-Tenant-Id`, then *Try it out* on any route.
- Threat Intel: http://localhost:8001/api/docs - the API key is `interview-threat-intel-key`.

Prefer Postman, Insomnia or Bruno? Import the OpenAPI documents straight from
http://localhost:8000/api/schema/ and http://localhost:8001/api/openapi.json.

---

## Exercise 1 - Applications listing

The applications page needs a server-driven table: pagination, filtering, search
and sorting all happen in the API, not in the browser.

|          |                                                                                              |
| -------- | -------------------------------------------------------------------------------------------- |
| Work in  | [api/inventory/applications_view.py](api/inventory/applications_view.py)                     |
| Given    | `models.py`, `filters.py`, `tenant.py`                                                       |
| Spec     | [api/inventory/tests/test_applications_api.py](api/inventory/tests/test_applications_api.py) |
| Contract | `GET /api/applications/?page=1&size=25&name=&search=&ordering=-discovered_on` → `{items, page, total_pages, total_count}` |

`GET /api/applications/` currently returns `{"items": []}`. Make it return a
real page of applications for the request's tenant. The TODOs in
`applications_view.py` list what's expected.

```bash
curl -s 'localhost:8000/api/applications/?search=web&ordering=hostname&size=5' -H 'X-Tenant-Id: 1'
```

## Exercise 2 - Devices listing (performance)

The devices listing is functionally correct and embarrassingly slow. The
response tells you exactly how slow.

|         |                                                                                                                                     |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Work in | [api/inventory/devices_view.py](api/inventory/devices_view.py)                                                                      |
| Given   | `models.py`, the seed data                                                                                                          |
| Spec    | [api/inventory/tests/test_devices_api.py](api/inventory/tests/test_devices_api.py) - every test caps the whole listing at 3 queries |

1. Reproduce it: `make seed`, then hit the endpoint and read `elapsed_ms`.

```bash
curl -s localhost:8000/api/devices/ -H 'X-Tenant-Id: 1' | python3 -c 'import sys,json; print(json.load(sys.stdin)["elapsed_ms"], "ms")'
```

## Exercise 3 - Agent check-in

The agent runs on customer machines and posts its full inventory on
every check-in: hostname, OS, every package installed. The Platform API has to turn
that into devices and applications - and keep doing it correctly when the same
agent reports again ten minutes later with three packages upgraded and one
removed.

|         |                                                                                                  |
| ------- | ------------------------------------------------------------------------------------------------ |
| Work in | [api/inventory/agent_checkin_view.py](api/inventory/agent_checkin_view.py)                       |
| Given   | the payload serializer (shape is fixed), `models.py`                                             |
| Spec    | [api/inventory/tests/test_agent_checkin_api.py](api/inventory/tests/test_agent_checkin_api.py)   |
| Route   | `POST /api/agent/<agent_guid>/checkin/`                                                          |

`POST /api/agent/<guid>/checkin/` currently answers 501. The TODOs in
`agent_checkin_view.py` list what's expected, in priority order; the tests are
in the same order.

```bash
curl -s -X POST localhost:8000/api/agent/demo-agent-1/checkin/ -H 'X-Tenant-Id: 1' -H 'Content-Type: application/json' -d '{
  "reported_at": "2026-10-15T10:00:00Z", "hostname": "demo-lt-01", "ip_address": "10.9.9.9",
  "os": {"name": "Ubuntu", "version": "22.04"},
  "applications": [{"name": "nginx", "version": "1.18.0"}, {"name": "sshd", "version": "8.9p1"}]
}'
# ...then post again with a later reported_at and a different package list.
```

## Exercise 4 - Vulnerability scan through Threat Intel

Knowing what runs on a device is half the job; the other half is knowing what
is vulnerable. That is Threat Intel's job: the Platform API sends it the device's software,
Threat Intel answers with CPEs and CVE ids, the Platform API fetches the details it does not
already have and stores the lot.

|         |                                                                                                              |
| ------- | ------------------------------------------------------------------------------------------------------------ |
| Work in | [api/inventory/vulnerability_scan_view.py](api/inventory/vulnerability_scan_view.py)                         |
| Given   | [api/inventory/threat_intel_client.py](api/inventory/threat_intel_client.py) (read it), `models.py`, the running Threat Intel |
| Spec    | [api/inventory/tests/test_vulnerability_scan_api.py](api/inventory/tests/test_vulnerability_scan_api.py)     |
| Route   | `POST /api/devices/<device_id>/vulnerability-scan/`                                                          |

`POST /api/devices/<id>/vulnerability-scan/` currently answers 501. The TODOs
in `vulnerability_scan_view.py` list what's expected, in priority order.

Things worth knowing about Threat Intel, all of which the tests exercise:

- It answers one mapping request per device and matches items back by `id`,
  not by position.
- It refuses CVE detail batches above 100 ids (HTTP 413).
- The Platform API caches CVE details for 12 hours; don't ask Threat Intel for what you
  already know.
- It goes down. A real one sits behind a network policy and a search
  cluster; this one goes down when you Ctrl-C it. The Platform API must stay
  consistent either way.

The tests run against the simulated Threat Intel in-process, with a small catalogue
spelled out in
[api/inventory/tests/fake_threat_intel.py](api/inventory/tests/fake_threat_intel.py). With
`make dev` running, the same endpoint talks to the Threat Intel on :8001 and its
bigger catalogue:

```bash
curl -s -X POST localhost:8000/api/devices/1/vulnerability-scan/ -H 'X-Tenant-Id: 1'
curl -s 'localhost:8000/api/applications/?device_id=1' -H 'X-Tenant-Id: 1'   # once exercise 1 works
```

Threat Intel itself is documented at http://localhost:8001/api/docs.

---

## Repo map

```
api/
  interview_api/            Django project (settings, urls)
  inventory/
    models.py               Tenant, Device, Application, Vulnerability, ApplicationVulnerability - given
    filters.py              ApplicationFilter - given
    tenant.py               X-Tenant-Id -> tenant id - given
    threat_intel_client.py        HTTP client for Threat Intel - given
    openapi.py              what /api/docs/ shows per endpoint - given, docs only
    applications_view.py    <- exercise 1 (view + serializer)
    devices_view.py         <- exercise 2
    agent_checkin_view.py   <- exercise 3 (view; serializer given)
    vulnerability_scan_view.py <- exercise 4
    tests/                  the spec; fake_threat_intel.py is the in-process Threat Intel
threat-intel/
  threat_intel/               the simulated Threat Intel (FastAPI) - given
    main.py                 routes
    catalogue.py            products, CVEs, version ranges
    versions.py             version comparison, OpenSSH-style versions included
  data/                     the catalogue it serves
  tests/                    its own sanity tests
```
