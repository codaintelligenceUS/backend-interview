from django_filters import rest_framework as filters
from django_filters.widgets import CSVWidget

from inventory.models import Application


class ApplicationFilter(filters.FilterSet):
    """Applications filter"""

    name = filters.CharFilter(lookup_expr='icontains')
    hostname = filters.CharFilter(lookup_expr='icontains')
    device_id = filters.NumberFilter(field_name='device_id')
    discovered_on = filters.DateTimeFromToRangeFilter()
    last_seen = filters.DateTimeFromToRangeFilter()
    status = filters.MultipleChoiceFilter(choices=Application.StatusType.choices, widget=CSVWidget, distinct=False)
    risk_level = filters.MultipleChoiceFilter(
        choices=Application.RiskLevelType.choices, widget=CSVWidget, distinct=False
    )

    class Meta:
        model = Application
        fields = [
            'name',
            'hostname',
            'device_id',
            'status',
            'risk_level',
            'discovered_on',
            'last_seen',
            'is_scanned',
        ]
