from rest_framework import serializers
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from inventory import openapi
from inventory.tenant import get_tenant_id

# Imports you will probably need:
# from django.db import transaction
# from inventory.models import Application, Device


class ReportedApplicationSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    version = serializers.CharField(max_length=64, allow_blank=True, default='')


class ReportedOsSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=64)
    version = serializers.CharField(max_length=64, allow_blank=True, default='')


class AgentCheckinSerializer(serializers.Serializer):
    """What the agent sends on every check-in. Given; the shape is fixed."""

    reported_at = serializers.DateTimeField()
    hostname = serializers.CharField(max_length=255)
    ip_address = serializers.CharField(max_length=45)
    os = ReportedOsSerializer()
    applications = ReportedApplicationSerializer(many=True)


class AgentCheckinView(APIView):
    """Exercise 3, agent check-in: `POST /api/agent/<agent_guid>/checkin/`

    Spec: `api/inventory/tests/test_agent_checkin_api.py`. The payload is
    already validated by `AgentCheckinSerializer` above; its shape is fixed.

    Steps, in priority order. The tests are in the same order:

    1. Device. Find the device with this `agent_guid` in the request's tenant,
       or create it. Either way store hostname, ip_address, os name and version,
       and `last_checkin = reported_at`. Answer 201 when created, 200 when it
       already existed, with:
           {'device_id': int, 'created': bool,
            'applications': {'added': int, 'seen': int, 'offline': int}}
    2. Applications. An application is identified by (name, version). Compare
       the reported list with the device's stored applications:
           reported, not stored   -> create it: status=online,
                                     discovered_on = last_seen = reported_at
           reported and stored    -> status=online, last_seen = reported_at
           stored, not reported   -> status=offline, nothing else changes
       A new version of a stored application is a new application.
    3. Stale payloads. If `reported_at` is older than the device's
       `last_checkin`, answer 409 and change nothing. Agents retry and
       networks reorder.
    4. Tenants. The same `agent_guid` in another tenant is another device.
    5. Cost and atomicity. Hundreds of packages per check-in are normal: the
       number of queries must not grow with the number of applications. And a
       check-in is one unit of work: all of it is stored, or none of it.
    """

    @openapi.agent_checkin
    def post(self, request: Request, agent_guid: str) -> Response:
        serializer = AgentCheckinSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tenant_id = get_tenant_id(request)
        payload = serializer.validated_data

        return Response({'detail': 'Not implemented'}, status=501)
