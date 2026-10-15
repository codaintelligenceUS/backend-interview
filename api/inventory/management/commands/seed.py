from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from inventory.models import Application, Device, Tenant

# name, versions. Versions are picked per device so that some installs
# are vulnerable according to the simulated Threat Intel and some are not.
APP_NAMES = [
    ('nginx', ['1.18.0', '1.22.1', '1.26.1']),
    ('apache2', ['2.4.49', '2.4.57', '2.4.62']),
    ('postgresql', ['14.2', '16.4', '17.4']),
    ('mysqld', ['8.0.30', '8.0.35', '8.4.0']),
    ('redis-server', ['6.2.6', '7.0.9', '8.2.2']),
    ('sshd', ['8.9p1', '9.6p1', '9.9p1']),
    ('rabbitmq', ['3.11.10', '3.13.0', '4.0.5']),
    ('elasticsearch', ['1.4.2', '7.17.10', '8.15.0']),
    ('grafana', ['8.2.0', '11.1.0', '11.3.0']),
    ('legacy-crm', ['2.0']),
]

OS_VERSIONS = [('Ubuntu', '22.04'), ('Ubuntu', '24.04'), ('Debian', '12')]

STATUSES = Application.StatusType.values
RISK_LEVELS = Application.RiskLevelType.values


class Command(BaseCommand):
    """Seed the database with deterministic demo data."""

    help = 'Reset and seed tenants, devices and applications. Vulnerabilities come from scanning.'

    def handle(self, *args, **options) -> None:
        Tenant.objects.all().delete()

        acme = Tenant.objects.create(id=1, name='Acme Industries')
        globex = Tenant.objects.create(id=2, name='Globex')

        # Acme is deliberately large: exercise 2 needs enough rows for a query
        # per device to show up in `elapsed_ms`, not just in a profiler.
        self._seed_tenant(tenant=acme, devices_count=2400, hostname_prefix='acme')
        self._seed_tenant(tenant=globex, devices_count=5, hostname_prefix='globex')

        self.stdout.write(
            self.style.SUCCESS(
                f'Seeded {Tenant.objects.count()} tenants, '
                f'{Device.objects.count()} devices, '
                f'{Application.objects.count()} applications.'
            )
        )

    def _seed_tenant(self, tenant: Tenant, devices_count: int, hostname_prefix: str) -> None:
        """Create devices and their applications for a tenant."""
        now = timezone.now()

        devices = Device.objects.bulk_create(
            Device(
                tenant=tenant,
                hostname=f'{hostname_prefix}-srv-{device_index + 1:03d}',
                ip_address=f'10.{device_index // 250}.{device_index % 250}.10',
                # Every other device has an agent installed; the rest were found by network scans.
                agent_guid=f'{hostname_prefix}-agent-{device_index + 1:04d}' if device_index % 2 == 0 else None,
                os_name=OS_VERSIONS[device_index % len(OS_VERSIONS)][0],
                os_version=OS_VERSIONS[device_index % len(OS_VERSIONS)][1],
                last_checkin=now - timedelta(minutes=device_index) if device_index % 2 == 0 else None,
            )
            for device_index in range(devices_count)
        )

        applications = []
        for device_index, device in enumerate(devices):
            for app_index, (name, versions) in enumerate(APP_NAMES):
                offset = device_index * len(APP_NAMES) + app_index
                is_scanned = offset % 3 != 0

                applications.append(
                    Application(
                        tenant=tenant,
                        device=device,
                        name=name,
                        version=versions[(device_index + app_index) % len(versions)],
                        status=STATUSES[offset % len(STATUSES)],
                        risk_level=RISK_LEVELS[offset % len(RISK_LEVELS)],
                        is_scanned=is_scanned,
                        discovered_on=now - timedelta(hours=offset * 2, minutes=17),
                        last_seen=now - timedelta(minutes=offset * 7),
                        last_scanned=now - timedelta(minutes=offset * 7) if is_scanned else None,
                    )
                )

        Application.objects.bulk_create(applications, batch_size=500)
