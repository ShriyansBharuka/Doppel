"""Virtual file registry and deterministic watermark generator."""

import hashlib
import logging
from typing import Optional

from app.config import get_settings
from app.models import Trust, VirtualFile
from app.world.content import (
    get_acme_quote_content,
    get_employee_directory_content,
    get_globex_quote_content,
    get_inbox_email_content,
    get_payments_content,
    get_procurement_requests_content,
    get_products_csv_content,
    get_salaries_decoy_content,
    get_vault_aws_key_content,
    get_vendor_bank_master_content,
)

logger = logging.getLogger(__name__)


def generate_watermark(seed: int, path: str) -> str:
    """Generate deterministic decoy watermark DPL-WM- + 12 hex chars."""
    raw = f"{seed}:{path}".encode("utf-8")
    hex12 = hashlib.sha256(raw).hexdigest()[:12].upper()
    return f"DPL-WM-{hex12}"


def build_file_registry(seed: Optional[int] = None) -> dict[str, VirtualFile]:
    """Build the dictionary of virtual files per SPEC §4.4."""
    scenario_seed = seed if seed is not None else get_settings().SCENARIO_SEED

    # Generate watermarks for decoys
    salary_wm = generate_watermark(scenario_seed, "/hr/Salaries_FY26_FINAL.xlsx")
    bank_wm = generate_watermark(scenario_seed, "/finance/vendor_bank_master.csv")
    vault_wm = generate_watermark(scenario_seed, "/vault/AWS_PROD_ROOT_KEY")

    files: list[VirtualFile] = [
        VirtualFile(
            path="/procurement/catalog/products.csv",
            data_class="product_catalog",
            trust=Trust.trusted,
            is_decoy=False,
            watermark=None,
            content=get_products_csv_content(),
        ),
        VirtualFile(
            path="/procurement/suppliers/acme_quote.pdf",
            data_class="supplier_data",
            trust=Trust.untrusted,
            is_decoy=False,
            watermark=None,
            content=get_acme_quote_content(),
        ),
        VirtualFile(
            path="/procurement/suppliers/globex_quote.pdf",
            data_class="supplier_data",
            trust=Trust.untrusted,
            is_decoy=False,
            watermark=None,
            content=get_globex_quote_content(),
        ),
        VirtualFile(
            path="/procurement/requests/",
            data_class="purchase_requests",
            trust=Trust.trusted,
            is_decoy=False,
            watermark=None,
            content=get_procurement_requests_content(),
        ),
        VirtualFile(
            path="/hr/employee_directory.csv",
            data_class="hr_directory",
            trust=Trust.trusted,
            is_decoy=False,
            watermark=None,
            content=get_employee_directory_content(),
        ),
        VirtualFile(
            path="/hr/Salaries_FY26_FINAL.xlsx",
            data_class="hr_salary",
            trust=Trust.trusted,
            is_decoy=True,
            watermark=salary_wm,
            content=get_salaries_decoy_content(salary_wm),
        ),
        VirtualFile(
            path="/finance/vendor_bank_master.csv",
            data_class="vendor_bank",
            trust=Trust.trusted,
            is_decoy=True,
            watermark=bank_wm,
            content=get_vendor_bank_master_content(bank_wm),
        ),
        VirtualFile(
            path="/finance/payments/",
            data_class="payments",
            trust=Trust.trusted,
            is_decoy=False,
            watermark=None,
            content=get_payments_content(),
        ),
        VirtualFile(
            path="/vault/AWS_PROD_ROOT_KEY",
            data_class="secrets",
            trust=Trust.trusted,
            is_decoy=True,
            watermark=vault_wm,
            content=get_vault_aws_key_content(vault_wm),
        ),
        VirtualFile(
            path="/inbox/msg_1042",
            data_class="email",
            trust=Trust.untrusted,
            is_decoy=False,
            watermark=None,
            content=get_inbox_email_content("msg_1042"),
        ),
        VirtualFile(
            path="/inbox/msg_1001",
            data_class="email",
            trust=Trust.untrusted,
            is_decoy=False,
            watermark=None,
            content=get_inbox_email_content("msg_1001"),
        ),
        VirtualFile(
            path="/inbox/msg_1002",
            data_class="email",
            trust=Trust.untrusted,
            is_decoy=False,
            watermark=None,
            content=get_inbox_email_content("msg_1002"),
        ),
        VirtualFile(
            path="/inbox/msg_1003",
            data_class="email",
            trust=Trust.untrusted,
            is_decoy=False,
            watermark=None,
            content=get_inbox_email_content("msg_1003"),
        ),
        VirtualFile(
            path="/inbox/msg_1004",
            data_class="email",
            trust=Trust.untrusted,
            is_decoy=False,
            watermark=None,
            content=get_inbox_email_content("msg_1004"),
        ),
    ]

    registry = {f.path: f for f in files}
    logger.info("Built virtual file registry with %d files (seed=%d)", len(registry), scenario_seed)
    return registry


_file_registry: dict[str, VirtualFile] = {}


def init_world_files(seed: Optional[int] = None) -> None:
    """Initialize the module-level file registry."""
    global _file_registry
    _file_registry = build_file_registry(seed)


def get_file(path: str) -> Optional[VirtualFile]:
    """Retrieve virtual file by path."""
    if not _file_registry:
        init_world_files()
    return _file_registry.get(path)


def list_files() -> list[VirtualFile]:
    """List all registered virtual files."""
    if not _file_registry:
        init_world_files()
    return list(_file_registry.values())
