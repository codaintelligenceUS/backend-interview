"""The CVE catalogue: products, CVEs and the version ranges that connect them.

The real thing is NVD's `configurations` block in a search index. Here a
CVE lists the products and version ranges it affects, straight from JSON.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from threat_intel.versions import version_in_range

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / 'data'


@dataclass(frozen=True)
class Product:
    """Something Threat Intel knows how to turn into a CPE."""

    name: str
    vendor: str
    part: str = 'a'  # 'a' application, 'o' operating system
    aliases: tuple[str, ...] = ()

    def cpe(self, version: str) -> str:
        return f'cpe:2.3:{self.part}:{self.vendor}:{self.name}:{version}:*:*:*:*:*:*:*'


@dataclass(frozen=True)
class AffectedRange:
    """One NVD `cpe_match` row: a product plus an optional version interval."""

    product: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    def contains(self, version: str) -> bool:
        return version_in_range(
            version,
            start_including=self.version_start_including,
            start_excluding=self.version_start_excluding,
            end_including=self.version_end_including,
            end_excluding=self.version_end_excluding,
        )


@dataclass(frozen=True)
class Cve:
    cve: str
    summary: str
    published: str
    cvss_base: float | None
    cvss_severity: str
    vector: str = ''
    is_weaponized: bool = False
    affected: tuple[AffectedRange, ...] = field(default_factory=tuple)

    def document(self) -> dict:
        """The CVE as Threat Intel serves it: the legacy NVD 1.1 JSON layout."""
        impact = {}
        if self.cvss_base is not None:
            impact['baseMetricV3'] = {
                'cvssV3': {
                    'baseScore': self.cvss_base,
                    'baseSeverity': self.cvss_severity,
                    'vectorString': self.vector,
                }
            }

        return {
            'cve': self.cve,
            'publishedDate': self.published,
            'lastModifiedDate': self.published,
            'source': 'nist',
            'state': 'normal',
            'is_weaponized': self.is_weaponized,
            'cve-data': {
                'CVE_data_meta': {'ID': self.cve},
                'description': {'description_data': [{'lang': 'en', 'value': self.summary}]},
                'references': {
                    'reference_data': [{'url': f'https://nvd.nist.gov/vuln/detail/{self.cve}', 'name': 'NVD'}]
                },
            },
            'impact': impact,
        }


def stub_document(cve_id: str) -> dict:
    """What Threat Intel returns for a CVE it has never heard of: a shell, not an error."""
    return {
        'cve': cve_id,
        'source': 'unknown',
        'state': 'reserved',
        'is_weaponized': False,
        'cve-data': {
            'CVE_data_meta': {'ID': cve_id},
            'description': {'description_data': []},
            'references': {'reference_data': [{'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}', 'name': 'NVD'}]},
        },
        'impact': {},
    }


class Catalogue:
    def __init__(self, products: list[Product], cves: list[Cve]) -> None:
        self._products_by_alias: dict[str, Product] = {}
        for product in products:
            for alias in (product.name, *product.aliases):
                self._products_by_alias[alias.lower()] = product

        self._cves: dict[str, Cve] = {cve.cve: cve for cve in cves}
        self._cves_by_product: dict[str, list[Cve]] = {}
        for cve in cves:
            for affected in cve.affected:
                self._cves_by_product.setdefault(affected.product, []).append(cve)

    @classmethod
    def load(cls, data_dir: Path = DEFAULT_DATA_DIR) -> 'Catalogue':
        products = [
            Product(
                name=item['name'],
                vendor=item['vendor'],
                part=item.get('part', 'a'),
                aliases=tuple(item.get('aliases', [])),
            )
            for item in json.loads((data_dir / 'products.json').read_text())
        ]
        cves = [
            Cve(
                cve=item['cve'],
                summary=item['summary'],
                published=item['published'],
                cvss_base=item.get('cvss_base'),
                cvss_severity=item.get('cvss_severity', ''),
                vector=item.get('vector', ''),
                is_weaponized=item.get('is_weaponized', False),
                affected=tuple(AffectedRange(**affected) for affected in item['affected']),
            )
            for item in json.loads((data_dir / 'cves.json').read_text())
        ]
        return cls(products=products, cves=cves)

    def resolve_product(self, product_name: str) -> Product | None:
        return self._products_by_alias.get(product_name.strip().lower())

    def map_product(self, product_name: str, version: str) -> tuple[str | None, list[str]]:
        """Return `(cpe, cve_ids)` for a reported name + version.

        Unknown products and empty versions map to nothing; Threat Intel would rather
        say nothing than guess.
        """
        product = self.resolve_product(product_name)
        version = (version or '').strip()
        if product is None or not version:
            return None, []

        cve_ids = {
            cve.cve
            for cve in self._cves_by_product.get(product.name, [])
            if any(affected.product == product.name and affected.contains(version) for affected in cve.affected)
        }
        return product.cpe(version), sorted(cve_ids)

    def get_cve(self, cve_id: str) -> Cve | None:
        return self._cves.get(cve_id.strip().upper())

    def __len__(self) -> int:
        return len(self._cves)
