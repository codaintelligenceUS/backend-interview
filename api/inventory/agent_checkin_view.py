from rest_framework import serializers
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from inventory import openapi
from inventory.tenant import get_tenant_id

# Everything you need is already here - it is just not wired up:
# from django.db import transaction
# from inventory.models import Application, Device


class ReportedApplicationSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    version = serializers.CharField(max_length=64, allow_blank=True, default='')


class ReportedOsSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=64)
    version = serializers.CharField(max_length=64, allow_blank=True, default='')


class AgentCheckinSerializer(serializers.Serializer):
    """What the agent sends on every check-in. Given - the shape is fixed."""

    reported_at = serializers.DateTimeField()
    hostname = serializers.CharField(max_length=255)
    ip_address = serializers.CharField(max_length=45)
    os = ReportedOsSerializer()
    applications = ReportedApplicationSerializer(many=True)


class AgentCheckinView(APIView):
    """Agent check-in. `POST /api/agent/<agent_guid>/checkin/`

    Exercise 3. The agent installed on a device posts its full inventory on
    every check-in. Turn that payload into Device and Application rows.
    `api/inventory/tests/test_agent_checkin_api.py` is the spec.

    TODO(1): Find the device for `agent_guid` within the request's tenant, or
             create it. Either way, store hostname, ip_address, os name and
             version, and `last_checkin = reported_at`.
             Answer 201 when the device was created, 200 when it already existed.
    TODO(2): Reject a payload whose `reported_at` is older than the device's
             `last_checkin` with 409 - agents retry and the network reorders.
    TODO(3): Diff the reported applications against the device's stored ones.
             An application is identified by (name, version):
               - not stored yet          -> create it: status=online,
                                            discovered_on and last_seen = reported_at
               - stored and reported     -> status=online, last_seen = reported_at
               - stored but not reported -> status=offline, nothing else changes
    TODO(4): Respond with
             {'device_id': int, 'created': bool,
              'applications': {'added': int, 'seen': int, 'offline': int}}
    TODO(5): A check-in is one unit of work: all of it is stored or none of it.
             And an agent may report hundreds of packages - the number of
             queries must not grow with the number of applications.
    """

    @openapi.agent_checkin
    def post(self, request: Request, agent_guid: str) -> Response:
        serializer = AgentCheckinSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Rename once you actually use them.
        _tenant_id = get_tenant_id(request)
        _payload = serializer.validated_data

        return Response({'detail': 'Not implemented'}, status=501)
