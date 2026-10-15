"""OpenAPI descriptions for the exercise endpoints, served at http://localhost:8000/api/docs/

Documentation only: nothing here changes how a view behaves and no test looks
at it. Each view applies one of these decorators to its handler so the Swagger
page shows the route, its parameters and an example you can send with
"Try it out". Set the tenant once with the "Authorize" button.
"""

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiExample, OpenApiParameter, OpenApiResponse, extend_schema

from inventory.models import Application


def _choices(choices) -> str:
    return ', '.join(choices.values)


applications_list = extend_schema(
    operation_id='applications_list',
    summary='Exercise 1: applications listing',
    description=(
        'Server-driven table: pagination, filtering, free-text search and sorting all happen here. '
        'Lists the applications of the request tenant.'
    ),
    parameters=[
        OpenApiParameter('page', int, description='1-based page number. Default 1.'),
        OpenApiParameter('size', int, description='Page size. Default settings.API_PAGE_SIZE, capped at settings.API_MAX_PAGE_SIZE.'),
        OpenApiParameter('search', str, description='Free text over application name and device hostname.'),
        OpenApiParameter('ordering', str, description="Sort field, prefix with '-' for descending. Default '-discovered_on'."),
        OpenApiParameter('name', str, description='Case-insensitive contains.'),
        OpenApiParameter('status', str, description=f'Comma-separated. One of: {_choices(Application.StatusType)}.'),
    ],
    responses={200: OpenApiTypes.OBJECT},
    examples=[
        OpenApiExample(
            'A page',
            response_only=True,
            value={
                'items': [
                    {
                        'id': 1, 'name': 'nginx', 'version': '1.18.0', 'hostname': 'acme-web-01',
                        'device_id': 1, 'status': 'online', 'risk_level': 'high',
                        'discovered_on': '2026-10-01T09:00:00Z', 'last_seen': '2026-10-15T09:00:00Z',
                        'last_scanned': None,
                    }
                ],
                'page': 1, 'total_pages': 4, 'total_count': 93,
            },
        )
    ],
)

devices_list = extend_schema(
    operation_id='devices_list',
    summary='Exercise 2: devices listing (performance)',
    description=(
        'Every device of the request tenant with its application counts, sorted by hostname. '
        'Functionally correct and slow.'
    ),
    responses={200: OpenApiTypes.OBJECT},
    examples=[
        OpenApiExample(
            'The listing',
            response_only=True,
            value={
                'items': [
                    {
                        'id': 1, 'hostname': 'acme-web-01', 'ip_address': '10.1.0.10', 'tenant_name': 'Acme Industries',
                        'application_count': 12, 'online_count': 11, 'application_names': ['nginx', 'sshd'],
                    }
                ],
                'total_count': 20,
            },
        )
    ],
)

agent_checkin = extend_schema(
    operation_id='agent_checkin',
    summary='Exercise 3: agent check-in',
    description=(
        'The agent installed on a device posts its full inventory on every check-in. '
        'The Platform API resolves the device by `agent_guid` within the tenant, creates it if needed, and diffs '
        'the reported applications against what it already knows. Post twice with a later `reported_at` '
        'and a different package list to see the diff; post with an older one to see the 409.'
    ),
    request=OpenApiTypes.OBJECT,
    responses={
        201: OpenApiResponse(OpenApiTypes.OBJECT, description='Device created'),
        200: OpenApiResponse(OpenApiTypes.OBJECT, description='Device already existed and was updated'),
        400: OpenApiResponse(description='Malformed payload'),
        409: OpenApiResponse(description='`reported_at` is older than the device\'s last check-in'),
    },
    examples=[
        OpenApiExample(
            'A check-in',
            request_only=True,
            value={
                'reported_at': '2026-10-15T10:00:00Z',
                'hostname': 'demo-lt-01',
                'ip_address': '10.9.9.9',
                'os': {'name': 'Ubuntu', 'version': '22.04'},
                'applications': [{'name': 'nginx', 'version': '1.18.0'}, {'name': 'sshd', 'version': '8.9p1'}],
            },
        ),
        OpenApiExample(
            'The outcome',
            response_only=True,
            status_codes=['200', '201'],
            value={'device_id': 21, 'created': True, 'applications': {'added': 2, 'seen': 0, 'offline': 0}},
        ),
    ],
)

vulnerability_scan = extend_schema(
    operation_id='vulnerability_scan',
    summary='Exercise 4: vulnerability scan through Threat Intel',
    description=(
        'Sends the device\'s OS and applications to Threat Intel, stores the CVEs it names, fetches the '
        'details the Platform API does not already have, reconciles open/fixed and recomputes each application\'s '
        '`risk_level` and `last_scanned`. Needs the simulated Threat Intel running on :8001 (`make dev` or `make dev-threat-intel`).'
    ),
    request=None,
    responses={
        200: OpenApiResponse(OpenApiTypes.OBJECT, description='Scan stored'),
        404: OpenApiResponse(description='No such device in this tenant'),
        503: OpenApiResponse(description='Threat Intel unreachable; nothing was stored'),
    },
    examples=[
        OpenApiExample(
            'The outcome',
            response_only=True,
            status_codes=['200'],
            value={'device_id': 1, 'applications_scanned': 12, 'vulnerabilities_open': 9, 'vulnerabilities_fixed': 1},
        )
    ],
)
