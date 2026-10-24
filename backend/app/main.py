"""Doppel FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.api.console_routes import router as console_router
from app.api.gateway_routes import router as gateway_router
from app.api.scenario_routes import router as scenario_router
from app.stream import router as stream_router
from app.config import get_settings
from app.contracts.loader import load_contracts, verify_contract
from app.engine.baseline import init_baseline
from app.store import get_store
from app.world.files import init_world_files, list_files
from app.world.tools import list_tools, pin_hashes

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager: initialize world, load contracts, and pin tool hashes."""
    logger.info("Initializing Doppel Gateway foundation...")
    settings = get_settings()

    # 1. Initialize simulated files world
    init_world_files(settings.SCENARIO_SEED)

    # 2. Pin tool schema hashes in the store
    store = get_store()
    pin_hashes(store)

    # 3. Load and verify cryptographic signatures on role contracts
    try:
        contracts = load_contracts()
        for contract in contracts.values():
            store.save_contract(contract)
        logger.info("Loaded %d verified role contracts into store", len(contracts))
    except Exception as exc:
        logger.error("Failed to load contracts on startup: %s", exc)
        raise exc

    # 4. Initialize behavioral baseline with benign sessions
    init_baseline(settings.SCENARIO_SEED)

    yield


app = FastAPI(
    title="Doppel Security Gateway",
    description="Identity drift detection and security gateway for autonomous AI agents",
    version="0.1.0",
    lifespan=lifespan,
)

# Configure CORS
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Gateway, Console, Stream, and Scenario Routers
app.include_router(gateway_router)
app.include_router(console_router)
app.include_router(stream_router)
app.include_router(scenario_router)


@app.get("/health")
def health() -> dict[str, Any]:
    """Healthcheck endpoint returning system status and loaded assets counts."""
    store = get_store()
    contracts_loaded = len(store.list_contracts())
    tools_pinned = len(store.get_all_pinned_tool_hashes())
    return {
        "status": "ok",
        "contracts_loaded": contracts_loaded,
        "tools_pinned": tools_pinned,
    }


@app.get("/v1/agents")
def list_agents() -> list[dict[str, Any]]:
    """List registered agents with validated role contracts."""
    store = get_store()
    contracts = store.list_contracts()
    return [
        {
            "agent_id": c.agent_id,
            "role": c.role,
            "purpose": c.purpose,
            "contract_version": c.version,
            "signature_valid": True,
        }
        for c in contracts
    ]


@app.get("/v1/agents/{id}/contract")
def get_agent_contract(id: str) -> dict[str, Any]:
    """Return active contract fields without signature so UI can quote clauses."""
    store = get_store()
    c = store.get_contract(id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Contract for agent '{id}' not found")
    return c.model_dump(exclude={"signature"})


@app.get("/v1/world/files")
def get_world_files() -> list[dict[str, Any]]:
    """Console view of registered virtual files.

    Includes is_decoy and has_watermark, NEVER the watermark value itself.
    """
    files = list_files()
    return [
        {
            "path": f.path,
            "data_class": f.data_class,
            "trust": f.trust.value,
            "is_decoy": f.is_decoy,
            "has_watermark": bool(f.watermark),
        }
        for f in files
    ]


@app.get("/v1/world/tools")
def get_world_tools() -> list[dict[str, Any]]:
    """Console view of registered tools and their pinned schema hashes."""
    tools = list_tools()
    return [
        {
            "name": t.name,
            "description": t.description,
            "params": t.params,
            "effect": t.effect.value,
            "data_class": t.data_class,
            "is_decoy": t.is_decoy,
            "schema_hash": t.schema_hash,
        }
        for t in tools
    ]
