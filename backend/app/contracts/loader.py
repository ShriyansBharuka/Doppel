"""Contract loader and HMAC-SHA256 verification module."""

import hashlib
import hmac
import json
import logging
from pathlib import Path
from typing import Any, Optional
import yaml

from app.config import get_settings
from app.models import Contract

logger = logging.getLogger(__name__)


def canonical_contract_json(data: dict[str, Any]) -> str:
    """Return canonical JSON representation of contract dict excluding signature.

    Key ordering is alphabetical (sort_keys=True) and no whitespace (separators=(',', ':')).
    """
    filtered = {k: v for k, v in data.items() if k != "signature"}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"))


def compute_contract_signature(data: dict[str, Any], secret: str) -> str:
    """Compute HMAC-SHA256 signature over canonical contract JSON."""
    canonical_bytes = canonical_contract_json(data).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()


def verify_contract_dict(data: dict[str, Any], secret: str) -> bool:
    """Verify that a contract dictionary contains a valid HMAC-SHA256 signature."""
    signature = data.get("signature")
    if not signature or not isinstance(signature, str):
        return False
    expected_sig = compute_contract_signature(data, secret)
    return hmac.compare_digest(expected_sig, signature)


def verify_contract(contract: Contract, secret: Optional[str] = None) -> bool:
    """Verify an instantiated Contract model's signature."""
    secret = secret or get_settings().DOPPEL_SECRET
    return verify_contract_dict(contract.model_dump(), secret)


def load_contracts(
    contracts_dir: Optional[Path | str] = None,
    secret: Optional[str] = None,
) -> dict[str, Contract]:
    """Load and cryptographically verify all contracts from directory.

    Refuses (logs error and raises ValueError) any unsigned or tampered contracts.
    Returns a dict mapping agent_id -> latest Contract by version.
    """
    secret = secret or get_settings().DOPPEL_SECRET
    if not secret:
        raise ValueError("No DOPPEL_SECRET available for contract verification")

    base_dir = Path(contracts_dir) if contracts_dir else Path(__file__).parent
    contracts_by_agent: dict[str, Contract] = {}

    yaml_files = sorted(list(base_dir.glob("*.yaml")) + list(base_dir.glob("*.yml")))

    for file_path in yaml_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as exc:
            logger.error("Failed to read contract YAML at %s: %s", file_path, exc)
            raise ValueError(f"Failed to read contract YAML {file_path.name}: {exc}") from exc

        if not isinstance(data, dict) or "agent_id" not in data:
            continue

        if not verify_contract_dict(data, secret):
            logger.error("Contract signature verification failed for %s", file_path)
            raise ValueError(
                f"Contract verification failed for {file_path.name}: unsigned or tampered"
            )

        contract = Contract(**data)
        agent_id = contract.agent_id

        # Keep the latest contract by version
        if agent_id in contracts_by_agent:
            if contract.version > contracts_by_agent[agent_id].version:
                contracts_by_agent[agent_id] = contract
        else:
            contracts_by_agent[agent_id] = contract

    logger.info("Successfully loaded and verified %d contracts", len(contracts_by_agent))
    return contracts_by_agent
