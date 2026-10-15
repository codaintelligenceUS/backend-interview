import time

from rest_framework import serializers
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from inventory import openapi
from inventory.models import Application, Device
from inventory.tenant import get_tenant_id


class DeviceListSerializer(serializers.ModelSerializer):
    tenant_name = serializers.CharField(source='tenant.name')
    application_count = serializers.SerializerMethodField()
    online_count = serializers.SerializerMethodField()
    application_names = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = [
            'id',
            'hostname',
            'ip_address',
            'tenant_name',
            'application_count',
            'online_count',
            'application_names',
        ]

    def get_application_count(self, device: Device) -> int:
        return len(list(device.applications.all()))

    def get_online_count(self, device: Device) -> int:
        return Application.objects.filter(device=device, status=Application.StatusType.ONLINE).count()

    def get_application_names(self, device: Device) -> list[str]:
        return [application.name for application in list(device.applications.all())]


class DeviceListView(APIView):
    """
    Devices listing view.

    Exercise 2 - make this view as fast as possible. It is functionally correct:
    it returns the right devices, with the right counts, in the right order. It
    is also slow, and it gets slower with every row - every test in
    `api/inventory/tests/test_devices_api.py` caps the whole listing at 3
    queries, and none of them passes today.

    How you get there is your call: ORM annotations, or a couple of plain
    queries and a dict. The tests only count queries and check the shape.

    The response shape is fixed: `items`, `total_count` and `elapsed_ms` must
    keep looking exactly like they do now. Hit the endpoint and read
    `elapsed_ms` before and after.
    """

    @openapi.devices_list
    def get(self, request: Request) -> Response:
        started = time.perf_counter()

        tenant_id = get_tenant_id(request)
        devices = sorted(
            list(Device.objects.filter(tenant_id=tenant_id)), key=lambda device: device.hostname
        )

        items = DeviceListSerializer(devices, many=True).data
        elapsed_ms = round((time.perf_counter() - started) * 1000)

        return Response({'items': items, 'total_count': len(items), 'elapsed_ms': elapsed_ms})
