"""CLI tool to sign contract YAML files with HMAC-SHA256 (key DOPPEL_SECRET)."""

import logging
from pathlib import Path
from typing import Optional
import yaml

from app.config import get_settings
from app.contracts.loader import compute_contract_signature

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def sign_contract_file(file_path: Path, secret: str) -> str:
    """Sign an individual contract YAML file in place."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"File {file_path} does not contain a valid YAML dictionary")

    sig = compute_contract_signature(data, secret)
    data["signature"] = sig

    with open(file_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)

    return sig


def sign_all_contracts(
    contracts_dir: Optional[Path | str] = None,
    secret: Optional[str] = None,
) -> int:
    """Sign all contract YAML files in contracts_dir."""
    settings = get_settings()
    signing_secret = secret or settings.DOPPEL_SECRET
    if not signing_secret:
        raise ValueError("DOPPEL_SECRET is empty. Set it in .env or pass as argument.")

    base_dir = Path(contracts_dir) if contracts_dir else Path(__file__).parent
    yaml_files = sorted(list(base_dir.glob("*.yaml")) + list(base_dir.glob("*.yml")))

    count = 0
    for file_path in yaml_files:
        sig = sign_contract_file(file_path, signing_secret)
        logger.info("Signed %s with HMAC-SHA256: %s...", file_path.name, sig[:12])
        count += 1

    return count


if __name__ == "__main__":
    sign_all_contracts()
