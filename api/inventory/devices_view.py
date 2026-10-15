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
        return Application.objects.filter(device=device).count()

    def get_online_count(self, device: Device) -> int:
        return Application.objects.filter(device=device, status=Application.StatusType.ONLINE).count()

    def get_application_names(self, device: Device) -> list[str]:
        return [application.name for application in Application.objects.filter(device=device)]


class DeviceListView(APIView):
    """Exercise 2, devices listing: `GET /api/devices/`

    Spec: `api/inventory/tests/test_devices_api.py`.

    This view is correct and slow. It returns the right devices, counts and
    order, and it gets slower with every device. Every test caps the whole
    listing at 3 queries, however many devices there are, and all of them fail
    today.

    Make them pass without changing the response: `items`, `total_count` and
    `elapsed_ms` must keep the exact shape they have now. How you get there is
    your call. Read `elapsed_ms` before and after.
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
