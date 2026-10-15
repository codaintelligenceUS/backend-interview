from django.urls import path

from inventory.agent_checkin_view import AgentCheckinView
from inventory.applications_view import ApplicationListView
from inventory.devices_view import DeviceListView
from inventory.vulnerability_scan_view import VulnerabilityScanView

urlpatterns = [
    path('applications/', ApplicationListView.as_view(), name='applications-list'),
    path('devices/', DeviceListView.as_view(), name='devices-list'),
    path('devices/<int:device_id>/vulnerability-scan/', VulnerabilityScanView.as_view(), name='device-scan'),
    path('agent/<str:agent_guid>/checkin/', AgentCheckinView.as_view(), name='agent-checkin'),
]
