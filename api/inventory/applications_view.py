from rest_framework import serializers
from rest_framework.generics import GenericAPIView
from rest_framework.request import Request
from rest_framework.response import Response

from inventory import openapi
from inventory.tenant import get_tenant_id

# Everything you need is already here - it is just not wired up:
# from inventory.filters import ApplicationFilter
# from inventory.models import Application


class ApplicationListSerializer(serializers.Serializer):
    """Applications listing serializer.

    Exercise 1 - the response shape. Each item must expose:

        id, name, version, type, hostname, device_id, status, risk_level,
        discovered_on, last_seen, last_scanned, scan_type

    Rules the tests check:
      * `type`, `status` and `risk_level` are the human readable labels, not
        the raw DB values.
      * `hostname` is the related device's hostname.
      * `scan_type` is 'Scanned' when the application was scanned, else 'Discovered'.
    """


class ApplicationListView(GenericAPIView):
    """Applications listing view.

    Exercise 1. Implement the listing this endpoint is supposed to serve.
    `api/inventory/tests/test_applications_api.py` is the spec.

    TODO(1): Return the envelope the tests expect:
             {'items': [...], 'page': int, 'total_pages': int, 'total_count': int}
    TODO(2): Scope every query to the tenant from `get_tenant_id(request)`, and
             list only applications running on billable devices.
    TODO(3): Paginate with `page` / `size`. Cap `size` at settings.API_MAX_PAGE_SIZE
             and default it to settings.API_PAGE_SIZE.
    TODO(4): Support filtering (`ApplicationFilter` exists if you want
             django-filter; plain queryset filters are just as good), free-text
             `search` over name + device hostname, and `ordering`.
             Default ordering: newest discovered first.
    TODO(5): Serialize (the serializer above, or a dict per row - your call)
             and do not run one query per row - the device hostname is on a
             related table.
    """

    @openapi.applications_list
    def get(self, request: Request, *args, **kwargs) -> Response:
        # Rename once you actually use it.
        _tenant_id = get_tenant_id(request)

        return Response({'items': []})
