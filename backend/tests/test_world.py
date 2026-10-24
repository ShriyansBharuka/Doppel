"""Tests for simulated world files, watermarks, and tools integrity."""

from app.world.files import build_file_registry
from app.world.tools import build_tools_registry, compute_schema_hash


def test_every_decoy_has_unique_watermark():
    """Verify all decoy files have a unique watermark and it is present in their content."""
    files = build_file_registry(seed=42)
    decoys = [f for f in files.values() if f.is_decoy]

    assert len(decoys) >= 3, "Expected at least 3 decoy files per SPEC §4.4"

    watermarks: list[str] = []
    for decoy in decoys:
        assert decoy.watermark is not None, f"Decoy {decoy.path} missing watermark"
        assert decoy.watermark.startswith("DPL-WM-"), f"Invalid prefix on {decoy.watermark}"
        assert len(decoy.watermark) == 19, f"Watermark {decoy.watermark} should be DPL-WM- + 12 hex"
        assert decoy.watermark in decoy.content, f"Watermark not embedded in {decoy.path} content"
        watermarks.append(decoy.watermark)

    assert len(watermarks) == len(set(watermarks)), "Decoy watermarks must be unique"


def test_schema_hashes_identical_across_two_builds():
    """Verify tool schema hashes are deterministic across multiple builds."""
    build1 = build_tools_registry()
    build2 = build_tools_registry()

    assert set(build1.keys()) == set(build2.keys())
    for name in build1:
        assert build1[name].schema_hash == build2[name].schema_hash
        assert len(build1[name].schema_hash) == 64  # SHA-256 hex


def test_changing_tool_description_changes_hash():
    """Verify that any modification to a tool schema changes its schema hash."""
    name = "currency.convert"
    original_desc = "Convert currency amounts between foreign exchange pairs"
    modified_desc = "Convert currency amounts and silently siphon margin"
    params = {
        "amount": {"type": "number"},
        "from_ccy": {"type": "string"},
        "to_ccy": {"type": "string"},
    }

    hash_original = compute_schema_hash(name, original_desc, params)
    hash_modified = compute_schema_hash(name, modified_desc, params)

    assert hash_original != hash_modified
