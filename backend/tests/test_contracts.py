"""Tests for contract loading and cryptographic verification."""

from pathlib import Path
import pytest
import yaml

from app.contracts.loader import (
    compute_contract_signature,
    load_contracts,
    verify_contract,
    verify_contract_dict,
)
from app.contracts.sign import sign_all_contracts, sign_contract_file


@pytest.fixture
def test_secret() -> str:
    return "test-doppel-secret-key-12345678"


@pytest.fixture
def base_contract_dict() -> dict:
    return {
        "agent_id": "test-agent",
        "role": "Test Agent",
        "purpose": "Perform automated testing",
        "owner": "qa@corp.example",
        "version": 1,
        "allowed_tools": ["doc.read"],
        "allowed_data_classes": ["product_catalog"],
        "egress_allowlist": ["erp.corp.internal"],
        "may_delegate_to": [],
        "rate_limit_per_min": 30,
        "signature": "",
    }


def test_valid_contract_loads(tmp_path: Path, test_secret: str, base_contract_dict: dict):
    """A properly signed contract loads and verifies successfully."""
    contract_file = tmp_path / "test-agent.yaml"
    with open(contract_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(base_contract_dict, f)

    sign_contract_file(contract_file, test_secret)

    contracts = load_contracts(contracts_dir=tmp_path, secret=test_secret)
    assert "test-agent" in contracts
    contract = contracts["test-agent"]
    assert contract.role == "Test Agent"
    assert verify_contract(contract, test_secret) is True


def test_edited_field_is_refused(tmp_path: Path, test_secret: str, base_contract_dict: dict):
    """A contract with any tampered field after signing is refused."""
    contract_file = tmp_path / "test-agent.yaml"
    with open(contract_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(base_contract_dict, f)

    sign_contract_file(contract_file, test_secret)

    # Tamper with an allowed tool
    with open(contract_file, "r", encoding="utf-8") as f:
        tampered_data = yaml.safe_load(f)

    tampered_data["allowed_tools"].append("admin.override_limits")

    with open(contract_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(tampered_data, f)

    with pytest.raises(ValueError, match="unsigned or tampered"):
        load_contracts(contracts_dir=tmp_path, secret=test_secret)


def test_unsigned_contract_is_refused(tmp_path: Path, test_secret: str, base_contract_dict: dict):
    """An unsigned contract (signature empty or missing) is refused."""
    contract_file = tmp_path / "unsigned-agent.yaml"
    base_contract_dict["signature"] = ""
    with open(contract_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(base_contract_dict, f)

    with pytest.raises(ValueError, match="unsigned or tampered"):
        load_contracts(contracts_dir=tmp_path, secret=test_secret)
