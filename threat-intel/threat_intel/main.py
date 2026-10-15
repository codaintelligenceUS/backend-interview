"""The simulated Threat Intel API.

Routes mirror the ones the Platform API actually calls. Prefix is `/api`, every path
ends in a slash, and every route except the plain health check wants the
`X-API-Key` header.

    GET  /api/_health/
    GET  /api/_health/test-auth/
    POST /api/{linux|windows|macos}/vulnerability-mapping/
    POST /api/search/cve-list-details/
    GET  /api/search/cve-details/{cve_id}/

Configuration is by environment variable:

    THREAT_INTEL_API_KEY      the key clients must send (default: interview-threat-intel-key)
    THREAT_INTEL_DATA_DIR     where products.json / cves.json live (default: ./data)
    THREAT_INTEL_LATENCY_MS   artificial delay per request, to make timeouts feel real
"""

import asyncio
import os
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from threat_intel.catalogue import DEFAULT_DATA_DIR, Catalogue, stub_document

DEFAULT_API_KEY = 'interview-threat-intel-key'
MAX_CVE_BATCH_SIZE = 100


# --------------------------------------------------------------------------- #
# Schemas. The field names are the real ones.
# --------------------------------------------------------------------------- #


class ProductInfo(BaseModel):
    """One product as reported by an agent: an id to match results back by, a name and a version."""

    id: int
    product_type: Literal['os', 'application', 'web_runtime', 'jar'] = 'application'
    product_name: str
    product_version: str = ''
    vendor: str | None = None
    extra: dict = Field(default_factory=dict)


class MappedProduct(ProductInfo):
    cpe: str | None = None
    cve_list: list[str] = Field(default_factory=list)


class VulnerabilityMappingRequest(BaseModel):
    os: ProductInfo | None = None
    applications: list[ProductInfo] = Field(default_factory=list)


class VulnerabilityMappingResponse(BaseModel):
    os: MappedProduct | None = None
    applications: list[MappedProduct] = Field(default_factory=list)


class CveListRequest(BaseModel):
    cve_list: list[str]


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #


def create_app(catalogue: Catalogue | None = None, api_key: str | None = None, latency_ms: int | None = None) -> FastAPI:
    catalogue = catalogue or Catalogue.load(Path(os.environ.get('THREAT_INTEL_DATA_DIR', DEFAULT_DATA_DIR)))
    api_key = api_key or os.environ.get('THREAT_INTEL_API_KEY', DEFAULT_API_KEY)
    latency_ms = int(os.environ.get('THREAT_INTEL_LATENCY_MS', '0')) if latency_ms is None else latency_ms

    app = FastAPI(title='Threat Intel (simulated)', version='0.1.0', docs_url='/api/docs', openapi_url='/api/openapi.json')
    app.state.catalogue = catalogue
    app.state.api_key = api_key
    app.state.latency_ms = latency_ms

    async def require_api_key(request: Request, x_api_key: str | None = Header(default=None)) -> None:
        if not x_api_key:
            raise HTTPException(status_code=401, detail='API key is missing')
        if x_api_key != request.app.state.api_key:
            raise HTTPException(status_code=401, detail='Invalid or inactive API key')

    async def simulate_latency(request: Request) -> None:
        if request.app.state.latency_ms:
            await asyncio.sleep(request.app.state.latency_ms / 1000)

    @app.get('/api/_health/')
    async def health() -> dict:
        return {'status': 'ok', 'cves': len(catalogue)}

    @app.get('/api/_health/test-auth/', dependencies=[Depends(require_api_key)])
    async def test_auth() -> dict:
        return {'status': 'ok', 'auth': 'ok'}

    @app.post(
        '/api/{os_family}/vulnerability-mapping/',
        response_model=VulnerabilityMappingResponse,
        dependencies=[Depends(require_api_key), Depends(simulate_latency)],
    )
    async def vulnerability_mapping(
        os_family: Literal['linux', 'windows', 'macos'], payload: VulnerabilityMappingRequest
    ) -> VulnerabilityMappingResponse:
        """Resolve every reported product to a CPE and the CVEs affecting that exact version.

        Items are echoed back with their `id`, so the caller can match results to
        what it sent. Unknown products come back with `cpe: null` and no CVEs.
        """

        def map_item(item: ProductInfo) -> MappedProduct:
            cpe, cve_list = catalogue.map_product(item.product_name, item.product_version)
            return MappedProduct(**item.model_dump(), cpe=cpe, cve_list=cve_list)

        return VulnerabilityMappingResponse(
            os=map_item(payload.os) if payload.os else None,
            applications=[map_item(item) for item in payload.applications],
        )

    @app.post('/api/search/cve-list-details/', dependencies=[Depends(require_api_key), Depends(simulate_latency)])
    async def cve_list_details(payload: CveListRequest) -> list[dict]:
        """Full documents for a batch of CVE ids.

        At most `MAX_CVE_BATCH_SIZE` ids per request (413 otherwise). Ids are
        de-duplicated and the response is sorted by id, not request order.
        Unknown ids get a stub document rather than being dropped.
        """
        if len(payload.cve_list) > MAX_CVE_BATCH_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f'cve_list has {len(payload.cve_list)} ids; the maximum is {MAX_CVE_BATCH_SIZE}',
            )

        documents = []
        for cve_id in sorted({cve_id.strip().upper() for cve_id in payload.cve_list}):
            cve = catalogue.get_cve(cve_id)
            documents.append(cve.document() if cve else stub_document(cve_id))
        return documents

    @app.get('/api/search/cve-details/{cve_id}/', dependencies=[Depends(require_api_key), Depends(simulate_latency)])
    async def cve_details(cve_id: str) -> dict:
        """One CVE. Unknown ids return `{}` with a 200, like the real one."""
        cve = catalogue.get_cve(cve_id)
        return cve.document() if cve else {}

    return app


app = create_app()
