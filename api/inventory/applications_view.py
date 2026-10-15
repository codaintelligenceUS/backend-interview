from rest_framework import serializers
from rest_framework.generics import GenericAPIView
from rest_framework.request import Request
from rest_framework.response import Response

from inventory import openapi
from inventory.tenant import get_tenant_id

# Imports you will probably need:
# from inventory.filters import ApplicationFilter
# from inventory.models import Application


class ApplicationListSerializer(serializers.Serializer):
    """The shape of one item in the listing:

        id, name, version, hostname, device_id, status, risk_level,
        discovered_on, last_seen, last_scanned, scan_type

    `status` and `risk_level` are the human-readable labels, not the
    stored values. `hostname` is the device's hostname. `scan_type` is
    'Scanned' when `is_scanned` is true, otherwise 'Discovered'.
    """


class ApplicationListView(GenericAPIView):
    """Exercise 1, applications listing: `GET /api/applications/`

    Spec: `api/inventory/tests/test_applications_api.py`.

    Steps, in the order the tests check them:

    1. Envelope: {'items': [...], 'page': int, 'total_pages': int, 'total_count': int}.
       Paginate with `page` and `size`. `size` defaults to settings.API_PAGE_SIZE
       and is capped at settings.API_MAX_PAGE_SIZE.
    2. Scope: only the request's tenant (`get_tenant_id(request)`).
    3. Filters: `name` (contains, case-insensitive), `status` (comma-separated
       list), `search` (matches name or device hostname) and `ordering` (a field
       name, `-` prefix for descending; `hostname` sorts by the device's
       hostname). Default ordering: newest `discovered_on` first.
       `ApplicationFilter` in filters.py is there if you want django-filter;
       plain queryset filters are just as good.
    4. Items: the shape described in `ApplicationListSerializer` above. Use that
       serializer or build the dicts yourself.
    5. Cost: the device hostname lives on another table. Do not run one query
       per row. The tests allow 4 queries for a page of 20.
    """

    @openapi.applications_list
    def get(self, request: Request, *args, **kwargs) -> Response:
        tenant_id = get_tenant_id(request)

        return Response({'items': []})
