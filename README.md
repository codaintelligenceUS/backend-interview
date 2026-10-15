Two services, both simulated and both small:

- **Platform API** (`api/`): a Django REST API that knows about tenants, their
  devices and the applications running on them. SQLite, no auth, no task queue.
- **Threat Intel** (`threat-intel/`): a FastAPI vulnerability intelligence
  service. It turns "nginx 1.18.0" into a CPE and a list of CVEs, and serves
  CVE details. A JSON file stands in for its database.

All four exercises are on the Platform API side. Threat Intel is given; you
only talk to it.

The tests check behaviour and, where it matters, query counts. They never
check how you got there: plain Python over a queryset is as valid as any ORM
feature. Use what you know.

## Setup

Requirements: **Python 3.10+**. Everything else is installed into the repo
(`.venv`).

```bash
make setup     # venv + pip install + migrate + seed
make dev       # Platform API on :8000, Threat Intel on :8001
```

To run the two servers separately, in two terminals:

```bash
make dev-api            # Platform API only, on :8000
make dev-threat-intel   # Threat Intel only, on :8001
```

VS Code or another Pylance/pyright editor: pick `.venv/bin/python` as the
interpreter. `pyrightconfig.json` points the language server at `api/` and
`threat-intel/`, and the venv includes Django and DRF type stubs, so imports
resolve and hover shows real types.

No `make`? The same thing by hand:

```bash
python3 -m venv .venv && .venv/bin/pip install -r api/requirements.txt -r threat-intel/requirements.txt
cd api && ../.venv/bin/python manage.py migrate && ../.venv/bin/python manage.py seed
../.venv/bin/python manage.py runserver 8000
# in a second terminal
cd threat-intel && ../.venv/bin/uvicorn threat_intel.main:app --port 8001
```

On Windows there is no `make`, and the virtualenv puts its executables in
`.venv\Scripts\` instead of `.venv/bin/`. Run the commands above with that
path, or use WSL or Git Bash.

The database is a gitignored `api/db.sqlite3` file filled by a seed command:

```bash
make seed        # wipe and re-create the demo data (migrates first if needed)
make reset-db    # delete the database file and rebuild it from scratch
```

## Tenants

A tenant is one customer. Every device and application belongs to exactly one
tenant, and so does the record of which CVE affects which application. Only
the CVE catalogue itself is shared, since a CVE means the same thing for
everyone. A customer must only ever see their own data. The seed creates two
tenants: Acme (id 1, 2400 devices) and Globex (id 2, 5 devices).

Authentication is out of scope for these exercises. There is no login.
Instead, every request names the tenant it acts for through a header:

```
X-Tenant-Id: 1
```

`get_tenant_id(request)` in `api/inventory/tenant.py` reads that header
(and falls back to tenant 1 when it is missing). Every exercise must scope its
queries to that tenant. Each test file includes a test that sends the other
tenant's id and expects to see nothing that is not theirs.

## Tests

```bash
make test               # everything
make test-api           # the Platform API suite: the exercises' specification
make test-threat-intel  # Threat Intel's own sanity tests: green as given, not an exercise
```

The Platform API tests are the specification. They fail against the stubs you
start from, and an exercise is done when its tests pass. Each stub's docstring
lists the steps in the order the tests check them.

## Calling the endpoints by hand

While `make dev` runs, both servers publish interactive docs with every route,
its parameters and a ready-to-send example:

- Platform API: http://localhost:8000/api/docs/. Click **Authorize** once to
  set `X-Tenant-Id`, then *Try it out* on any route.
- Threat Intel: http://localhost:8001/api/docs. The API key is
  `interview-threat-intel-key`.

Postman, Insomnia or Bruno can import the OpenAPI documents from
http://localhost:8000/api/schema/ and http://localhost:8001/api/openapi.json.
Each exercise below also has a `curl` example.

---

## Exercise 1: Applications listing

A server-driven table of applications: pagination, filtering, search and
sorting all happen in the API.

|          |                                                                                              |
| -------- | -------------------------------------------------------------------------------------------- |
| Work in  | [api/inventory/applications_view.py](api/inventory/applications_view.py)                     |
| Given    | `models.py`, `filters.py`, `tenant.py`                                                       |
| Spec     | [api/inventory/tests/test_applications_api.py](api/inventory/tests/test_applications_api.py) |
| Route    | `GET /api/applications/?page=1&size=25&name=&status=&search=&ordering=-discovered_on`        |
| Response | `{items, page, total_pages, total_count}`                                                    |

The endpoint currently returns `{"items": []}`. Make it return a page of the
request tenant's applications. The docstring in `applications_view.py` lists
the steps.

```bash
curl -s 'localhost:8000/api/applications/?search=web&ordering=hostname&size=5' -H 'X-Tenant-Id: 1'
```

## Exercise 2: Devices listing (performance)

The devices listing returns the right data and is very slow. Each response
reports its own `elapsed_ms`.

|         |                                                                                                              |
| ------- | ------------------------------------------------------------------------------------------------------------ |
| Work in | [api/inventory/devices_view.py](api/inventory/devices_view.py)                                               |
| Given   | `models.py`, the seed data                                                                                   |
| Spec    | [api/inventory/tests/test_devices_api.py](api/inventory/tests/test_devices_api.py)                           |
| Route   | `GET /api/devices/`                                                                                          |

Make the tests pass without changing the response shape. Every test caps the
whole listing at 3 queries, however many devices there are. Read `elapsed_ms`
before and after:

```bash
curl -s localhost:8000/api/devices/ -H 'X-Tenant-Id: 1' | python3 -c 'import sys,json; print(json.load(sys.stdin)["elapsed_ms"], "ms")'
```

## Exercise 3: Agent check-in

An agent on each customer machine posts its full inventory on every check-in:
hostname, OS and every installed package. Turn that into Device and
Application rows, and keep it correct when the same agent reports again with
packages upgraded or removed.

|         |                                                                                                  |
| ------- | ------------------------------------------------------------------------------------------------ |
| Work in | [api/inventory/agent_checkin_view.py](api/inventory/agent_checkin_view.py)                       |
| Given   | the payload serializer (the shape is fixed), `models.py`                                         |
| Spec    | [api/inventory/tests/test_agent_checkin_api.py](api/inventory/tests/test_agent_checkin_api.py)   |
| Route   | `POST /api/agent/<agent_guid>/checkin/`                                                          |

The endpoint currently answers 501. The docstring in `agent_checkin_view.py`
lists the steps in priority order; the tests are in the same order.

```bash
curl -s -X POST localhost:8000/api/agent/demo-agent-1/checkin/ -H 'X-Tenant-Id: 1' -H 'Content-Type: application/json' -d '{
  "reported_at": "2026-10-15T10:00:00Z", "hostname": "demo-lt-01", "ip_address": "10.9.9.9",
  "os": {"name": "Ubuntu", "version": "22.04"},
  "applications": [{"name": "nginx", "version": "1.18.0"}, {"name": "sshd", "version": "8.9p1"}]
}'
# then post again with a later reported_at and a different package list
```

## Exercise 4: Vulnerability scan through Threat Intel

Knowing what runs on a device is half the job. The other half is asking Threat
Intel what is vulnerable: send it the device's software, get back CPEs and CVE
ids, fetch the CVE details you do not have yet, and store everything.

|         |                                                                                                              |
| ------- | ------------------------------------------------------------------------------------------------------------ |
| Work in | [api/inventory/vulnerability_scan_view.py](api/inventory/vulnerability_scan_view.py)                         |
| Given   | [api/inventory/threat_intel_client.py](api/inventory/threat_intel_client.py) (read it), `models.py`          |
| Spec    | [api/inventory/tests/test_vulnerability_scan_api.py](api/inventory/tests/test_vulnerability_scan_api.py)     |
| Route   | `POST /api/devices/<device_id>/vulnerability-scan/`                                                          |

The endpoint currently answers 501. The docstring in
`vulnerability_scan_view.py` lists the steps in priority order.

What to know about Threat Intel (each point has a test):

- One mapping request covers a whole device. Results are matched by `id`, not
  by position.
- CVE detail batches above 100 ids are refused with HTTP 413.
- CVE details are cached for 12 hours. Do not ask for what you already have.
- It goes down. A half-stored scan is worse than no scan.

The tests run against a simulated Threat Intel inside the test process, with
the small catalogue listed in
[api/inventory/tests/fake_threat_intel.py](api/inventory/tests/fake_threat_intel.py).
With `make dev` running, the same endpoint talks to the Threat Intel on :8001
and its bigger catalogue:

```bash
curl -s -X POST localhost:8000/api/devices/1/vulnerability-scan/ -H 'X-Tenant-Id: 1'
curl -s 'localhost:8000/api/applications/?device_id=1' -H 'X-Tenant-Id: 1'   # once exercise 1 works
```

---

## Repo map

```
api/
  interview_api/              Django project (settings, urls)
  inventory/
    models.py                 Tenant, Device, Application, Vulnerability, ApplicationVulnerability (given)
    filters.py                ApplicationFilter (given)
    tenant.py                 X-Tenant-Id to tenant id (given)
    threat_intel_client.py    HTTP client for Threat Intel (given)
    openapi.py                what /api/docs/ shows per endpoint (given, docs only)
    applications_view.py      <- exercise 1 (view + serializer)
    devices_view.py           <- exercise 2
    agent_checkin_view.py     <- exercise 3 (view; serializer given)
    vulnerability_scan_view.py <- exercise 4
    tests/                    the specification; fake_threat_intel.py is the in-process Threat Intel
threat-intel/
  threat_intel/               the simulated Threat Intel, FastAPI (given)
    main.py                   routes
    catalogue.py              products, CVEs, version ranges
    versions.py               version comparison, OpenSSH-style versions included
  data/                       the catalogue it serves
  tests/                      its own sanity tests
```
