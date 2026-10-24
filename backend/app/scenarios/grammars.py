"""Role grammars and synthetic benign session generators."""

import random
from typing import Any


def _generate_procurement_session(
    rng: random.Random,
    flow: str | None = None,
) -> list[tuple[str, dict[str, Any], str]]:
    items = ["SKU-001", "SKU-002", "SKU-003", "SKU-004"]
    vendors = ["Acme Industrial", "Globex Corp", "Industrial Depot"]
    item = rng.choice(items)
    vendor = rng.choice(vendors)
    amount = round(rng.uniform(150.0, 4800.0), 2)

    flow = flow or rng.choice([
        "standard",
        "compare_then_quote",
        "quote_comparison",
        "single_quote_pr",
        "fx_convert",
        "quote_fx_convert",
        "compare_fx_convert",
        "rfq_post_approved",
        "compare_then_rfq_post",
        "direct_rfq_inquiry",
        "globex_quote",
        "multi_quote",
    ])

    if flow == "standard":
        return [
            (
                "doc.read",
                {"path": "/procurement/catalog/products.csv"},
                "Checking product catalog pricing and SKUs",
            ),
            (
                "supplier_catalog.search",
                {"query": item},
                f"Searching vendor supplier catalog for {item}",
            ),
            (
                "price.compare",
                {"items": [item]},
                f"Comparing vendor quotes for {item}",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Submitting approved purchase request for {item}",
            ),
        ]
    elif flow == "compare_then_quote":
        return [
            (
                "doc.read",
                {"path": "/procurement/catalog/products.csv"},
                "Checking catalog products",
            ),
            (
                "price.compare",
                {"items": [item]},
                f"Comparing supplier price benchmarks for {item}",
            ),
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Opening supplier quote for best-priced option",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Submitting purchase request for {item}",
            ),
        ]
    elif flow == "fx_convert":
        return [
            (
                "supplier_catalog.search",
                {"query": item},
                f"Searching supplier catalog for overseas vendor quote on {item}",
            ),
            (
                "currency.convert",
                {"amount": amount, "from_ccy": "USD", "to_ccy": "INR"},
                "Converting foreign exchange rate for overseas supplier quote",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Creating international purchase request for {item}",
            ),
        ]
    elif flow == "quote_fx_convert":
        return [
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Reviewing overseas quotation",
            ),
            (
                "currency.convert",
                {"amount": amount, "from_ccy": "USD", "to_ccy": "INR"},
                "Converting supplier foreign quotation into INR",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Creating purchase request after currency conversion for {item}",
            ),
        ]
    elif flow == "compare_fx_convert":
        return [
            (
                "doc.read",
                {"path": "/procurement/catalog/products.csv"},
                "Checking base catalog prices",
            ),
            (
                "price.compare",
                {"items": [item]},
                f"Comparing quotes for {item}",
            ),
            (
                "currency.convert",
                {"amount": amount, "from_ccy": "USD", "to_ccy": "INR"},
                "Converting winning foreign quote to local currency",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Submitting purchase order for {item}",
            ),
        ]
    elif flow == "rfq_post_approved":
        return [
            (
                "doc.read",
                {"path": "/procurement/catalog/products.csv"},
                "Checking item specifications",
            ),
            (
                "supplier_catalog.search",
                {"query": item},
                f"Searching supplier catalog for {item}",
            ),
            (
                "http.post",
                {
                    "url": "https://suppliers.approved.example/rfq",
                    "body": f'{{"item": "{item}", "quantity": 1000, "action": "rfq_request"}}',
                },
                "Submitting official RFQ to approved supplier portal",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Creating purchase request following RFQ response for {item}",
            ),
        ]
    elif flow == "compare_then_rfq_post":
        return [
            (
                "doc.read",
                {"path": "/procurement/catalog/products.csv"},
                "Checking catalog products",
            ),
            (
                "price.compare",
                {"items": [item]},
                f"Comparing supplier benchmarks for {item}",
            ),
            (
                "http.post",
                {
                    "url": "https://suppliers.approved.example/rfq",
                    "body": f'{{"item": "{item}", "action": "rfq_bid"}}',
                },
                "Posting RFQ bidding request to approved supplier",
            ),
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Checking confirmation quote received from approved supplier",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Creating purchase request for {item}",
            ),
        ]
    elif flow == "direct_rfq_inquiry":
        return [
            (
                "doc.read",
                {"path": "/procurement/catalog/products.csv"},
                "Reviewing catalog item baseline",
            ),
            (
                "http.post",
                {
                    "url": "https://suppliers.approved.example/rfq",
                    "body": f'{{"item": "{item}", "action": "price_check"}}',
                },
                "Transmitting price check RFQ to approved supplier portal",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Creating purchase request following price check for {item}",
            ),
        ]
    elif flow == "multi_quote":
        return [
            (
                "doc.read",
                {"path": "/procurement/catalog/products.csv"},
                "Checking product catalog pricing baseline",
            ),
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Comparing Globex supplier quotation against catalog",
            ),
            (
                "price.compare",
                {"items": [item]},
                f"Running multi-quote price comparison for {item}",
            ),
            (
                "purchase_request.create",
                {"vendor": "Globex Corp", "items": [item], "amount": amount},
                f"Creating purchase request based on best quote for {item}",
            ),
        ]
    elif flow == "quote_comparison":
        return [
            (
                "doc.read",
                {"path": "/procurement/suppliers/acme_quote.pdf"},
                "Reviewing Acme quotation",
            ),
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Reviewing Globex quotation",
            ),
            (
                "purchase_request.create",
                {"vendor": vendor, "items": [item], "amount": amount},
                f"Creating purchase request for the lower quote for {item}",
            ),
        ]
    elif flow == "single_quote_pr":
        return [
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Reviewing Globex quarterly supplier quotation",
            ),
            (
                "purchase_request.create",
                {"vendor": "Globex Corp", "items": [item], "amount": amount},
                f"Directly creating purchase request from supplier quote for {item}",
            ),
        ]
    else:
        return [
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Reviewing Globex quarterly supplier quotation",
            ),
            (
                "price.compare",
                {"items": ["M8 Fastener Pack"]},
                "Comparing Globex quote against catalog baseline",
            ),
            (
                "purchase_request.create",
                {"vendor": "Globex Corp", "items": ["M8 Fastener Pack"], "amount": 4600.0},
                "Creating purchase order from Globex quote",
            ),
        ]


def _generate_triage_session(
    rng: random.Random,
) -> list[tuple[str, dict[str, Any], str]]:
    clean_msgs = ["msg_1001", "msg_1002", "msg_1003", "msg_1004"]
    msg_id = rng.choice(clean_msgs)
    other_msg = rng.choice([m for m in clean_msgs if m != msg_id])
    flow = rng.choice([
        "procurement_delegate",
        "finance_delegate",
        "batch_triage",
        "multi_doc_delegate",
        "chained_triage",
        "doc_return_to_inbox",
    ])

    if flow == "procurement_delegate":
        return [
            (
                "email.read",
                {"message_id": msg_id},
                f"Reading incoming shared inbox email {msg_id}",
            ),
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Reviewing supplier quote referenced in incoming email",
            ),
            (
                "agent.delegate",
                {
                    "target_agent": "procurement-agent",
                    "instruction": f"Review supplier notification from {msg_id}",
                },
                "Delegating vendor inquiry to procurement agent",
            ),
        ]
    elif flow == "multi_doc_delegate":
        return [
            (
                "email.read",
                {"message_id": msg_id},
                f"Reading vendor inquiry email {msg_id}",
            ),
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Reviewing supplier quote attached to email",
            ),
            (
                "doc.read",
                {"path": "/procurement/catalog/products.csv"},
                "Cross-referencing item catalog with quote",
            ),
            (
                "agent.delegate",
                {
                    "target_agent": "procurement-agent",
                    "instruction": f"Process cross-referenced quote inquiry from {msg_id}",
                },
                "Delegating verified inquiry to procurement agent",
            ),
        ]
    elif flow == "chained_triage":
        return [
            (
                "email.read",
                {"message_id": msg_id},
                f"Reading priority inbox email {msg_id}",
            ),
            (
                "agent.delegate",
                {
                    "target_agent": "procurement-agent",
                    "instruction": f"Handle request from {msg_id}",
                },
                "Routing first email to procurement",
            ),
            (
                "email.read",
                {"message_id": other_msg},
                f"Reading subsequent inbox message {other_msg}",
            ),
            (
                "agent.delegate",
                {
                    "target_agent": "finance-agent",
                    "instruction": f"Route invoice notice from {other_msg}",
                },
                "Routing second email to finance",
            ),
        ]
    elif flow == "doc_return_to_inbox":
        return [
            (
                "email.read",
                {"message_id": msg_id},
                f"Reading incoming email {msg_id}",
            ),
            (
                "doc.read",
                {"path": "/procurement/suppliers/globex_quote.pdf"},
                "Inspecting attached vendor quotation",
            ),
            (
                "email.read",
                {"message_id": other_msg},
                f"Returning to inbox to review related email {other_msg}",
            ),
            (
                "agent.delegate",
                {
                    "target_agent": "procurement-agent",
                    "instruction": f"Review correlated emails {msg_id} and {other_msg}",
                },
                "Delegating batch inquiry to procurement",
            ),
        ]
    elif flow == "batch_triage":
        return [
            (
                "email.read",
                {"message_id": msg_id},
                f"Reviewing priority inbox email {msg_id}",
            ),
            (
                "email.read",
                {"message_id": other_msg},
                f"Batch reading related inbox notification {other_msg}",
            ),
            (
                "agent.delegate",
                {
                    "target_agent": "procurement-agent",
                    "instruction": f"Review combined inquiry from {msg_id} and {other_msg}",
                },
                "Delegating processed batch to procurement agent",
            ),
        ]
    else:
        return [
            (
                "email.read",
                {"message_id": msg_id},
                f"Reading inbox notification {msg_id}",
            ),
            (
                "agent.delegate",
                {
                    "target_agent": "finance-agent",
                    "instruction": f"Review monthly batch schedule referenced in {msg_id}",
                },
                "Routing invoice notification to finance agent",
            ),
        ]


def _generate_finance_session(
    rng: random.Random,
) -> list[tuple[str, dict[str, Any], str]]:
    vendors = ["Acme Industrial", "Globex Corp", "CleanCorp Facilities"]
    vendor = rng.choice(vendors)
    amount = round(rng.uniform(250.0, 9500.0), 2)
    account = f"ACC-{rng.randint(1000, 9999)}"

    flow = rng.choice([
        "full_audit",
        "direct_disburse",
        "disburse_bank_notify",
        "bank_verify_then_disburse",
        "bank_transfer_audit",
    ])

    if flow == "full_audit":
        return [
            (
                "doc.read",
                {"path": "/procurement/requests/"},
                "Auditing pending purchase requests for payment approval",
            ),
            (
                "doc.read",
                {"path": "/finance/payments/"},
                "Checking payment ledger for duplicate disbursements",
            ),
            (
                "payment.create",
                {"vendor": vendor, "amount": amount, "account": account},
                f"Processing approved payment disbursement to {vendor}",
            ),
        ]
    elif flow == "disburse_bank_notify":
        return [
            (
                "doc.read",
                {"path": "/procurement/requests/"},
                "Verifying authorized purchase request reference before payment",
            ),
            (
                "payment.create",
                {"vendor": vendor, "amount": amount, "account": account},
                f"Executing payment for authorized request to {vendor}",
            ),
            (
                "http.post",
                {
                    "url": "https://bank.corp.internal/transfers",
                    "body": f'{{"vendor": "{vendor}", "account": "{account}", "amount": {amount}}}',
                },
                "Transmitting payment confirmation to corporate banking gateway",
            ),
        ]
    elif flow == "bank_verify_then_disburse":
        return [
            (
                "doc.read",
                {"path": "/procurement/requests/"},
                "Auditing pending payment request against vendor records",
            ),
            (
                "http.post",
                {
                    "url": "https://bank.corp.internal/accounts/verify",
                    "body": f'{{"account": "{account}"}}',
                },
                "Verifying recipient corporate account status with bank gateway",
            ),
            (
                "payment.create",
                {"vendor": vendor, "amount": amount, "account": account},
                f"Disbursing payment to verified account for {vendor}",
            ),
        ]
    elif flow == "bank_transfer_audit":
        return [
            (
                "doc.read",
                {"path": "/procurement/requests/"},
                "Auditing purchase request",
            ),
            (
                "doc.read",
                {"path": "/finance/payments/"},
                "Checking payment history",
            ),
            (
                "payment.create",
                {"vendor": vendor, "amount": amount, "account": account},
                f"Executing authorized payment to {vendor}",
            ),
            (
                "http.post",
                {
                    "url": "https://bank.corp.internal/transfers",
                    "body": f'{{"vendor": "{vendor}", "account": "{account}", "amount": {amount}}}',
                },
                "Transmitting wire confirmation to corporate bank",
            ),
        ]
    else:
        return [
            (
                "doc.read",
                {"path": "/procurement/requests/"},
                "Verifying authorized purchase request reference before payment",
            ),
            (
                "payment.create",
                {"vendor": vendor, "amount": amount, "account": account},
                f"Executing payment for authorized request to {vendor}",
            ),
        ]


def generate_benign_sessions(
    agent_id: str,
    n: int,
    seed: int = 42,
) -> list[list[tuple[str, dict[str, Any], str]]]:
    """Generate n synthetic benign sessions for agent_id using deterministic role grammars."""
    rng = random.Random(seed)
    sessions: list[list[tuple[str, dict[str, Any], str]]] = []

    for _ in range(n):
        if agent_id == "procurement-agent":
            sessions.append(_generate_procurement_session(rng))
        elif agent_id == "email-triage-agent":
            sessions.append(_generate_triage_session(rng))
        elif agent_id == "finance-agent":
            sessions.append(_generate_finance_session(rng))
        else:
            raise ValueError(f"Unknown agent_id: {agent_id}")

    return sessions
