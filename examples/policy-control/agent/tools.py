"""Tool calls used by the Policy Control demo agent."""

from __future__ import annotations

import http.client
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse


DEFAULT_PROXY = "http://127.0.0.1:18180"
DEFAULT_SESSION_ID = "policy-control-session"
DEFAULT_TARGET = "http://127.0.0.1:19090"
DEFAULT_TIMEOUT = 5.0


@dataclass(frozen=True)
class AgentConfig:
    """Runtime connection settings for demo-agent tool calls."""

    proxy: str = DEFAULT_PROXY
    target: str = DEFAULT_TARGET
    session_id: str = DEFAULT_SESSION_ID
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AgentConfig":
        """Build connection settings from the process environment."""

        source = os.environ if env is None else env
        timeout = source.get("POLICY_CONTROL_TIMEOUT", str(DEFAULT_TIMEOUT))
        try:
            parsed_timeout = float(timeout)
        except ValueError as error:
            raise ValueError(f"invalid POLICY_CONTROL_TIMEOUT: {timeout}") from error
        if parsed_timeout <= 0:
            raise ValueError("POLICY_CONTROL_TIMEOUT must be greater than 0")

        return cls(
            proxy=source.get("PROXY", DEFAULT_PROXY),
            target=source.get("POLICY_CONTROL_TARGET", DEFAULT_TARGET),
            session_id=source.get("FIRMA_SESSION_ID", DEFAULT_SESSION_ID),
            timeout=parsed_timeout,
        )


@dataclass(frozen=True)
class ToolCall:
    """Description of one deterministic agent tool call."""

    name: str
    label: str
    method: str
    path: str
    body: dict[str, Any] | None = None


@dataclass(frozen=True)
class ToolResult:
    """Observed HTTP result for one tool call."""

    call: ToolCall
    status: int | None
    error: str | None


ToolRow = tuple[str, str, str, str]

TOOL_ROWS: tuple[ToolRow, ...] = (
    ("check_service_health", "GET", "checking service health", "/healthz"),
    ("read_public_docs", "GET", "reading public docs", "/public/readme"),
    ("read_secret_material", "GET", "reading secret material", "/secrets"),
    ("open_pull_request", "POST", "opening pull request", "/pull-request"),
    ("transfer_payment", "POST", "transferring payment", "/payments/transfer"),
    ("message_vendor", "POST", "messaging vendor", "/messages/external"),
    ("read_admin_dashboard", "GET", "reading admin dashboard", "/admin/dashboard"),
    ("export_customer_profiles", "GET", "exporting customer profiles", "/customers/profiles/export"),
    ("export_customer_emails", "GET", "exporting customer emails", "/customers/emails/export"),
    ("download_billing_report", "GET", "downloading billing report", "/billing/reports/download"),
    ("export_invoices", "GET", "exporting invoices", "/invoices/bulk-export"),
    ("refund_payment", "POST", "refunding payment", "/payments/refunds"),
    ("send_vendor_payout", "POST", "sending vendor payout", "/vendors/payouts"),
    ("read_secret_manager", "GET", "reading secret manager", "/secrets/manager"),
    ("read_production_env", "GET", "reading production environment", "/env/production"),
    ("read_database_snapshots", "GET", "reading database snapshots", "/database/snapshots"),
    ("merge_pull_request", "POST", "merging pull request", "/repositories/pull-requests/merge"),
    ("deploy_production", "POST", "deploying production", "/deployments/production"),
    ("change_branch_protection", "POST", "changing branch protection", "/repositories/branch-protection"),
    ("message_external_customer", "POST", "messaging external customer", "/messages/customers/external"),
    ("reply_support_ticket", "POST", "replying to support ticket", "/support/tickets/reply"),
    ("send_bulk_email_campaign", "POST", "sending bulk email campaign", "/messages/email/campaigns"),
    ("export_training_data", "GET", "exporting training data", "/ml/training-data/export"),
    ("download_model_weights", "GET", "downloading model weights", "/ml/model-weights/download"),
    ("export_vector_index", "GET", "exporting vector index", "/ml/vector-index/export"),
    ("query_data_warehouse", "GET", "querying data warehouse", "/warehouse/query"),
    ("download_api_keys", "GET", "downloading API keys", "/credentials/api-keys/download"),
    ("grant_privileged_role", "POST", "granting privileged role", "/identity/roles/grant"),
    ("delete_audit_logs", "POST", "deleting audit logs", "/audit/logs/delete"),
    ("change_data_retention", "POST", "changing data retention", "/governance/data-retention"),
)


def _tool_from_row(row: ToolRow) -> ToolCall:
    name, method, label, path = row
    body = {"operation": name} if method == "POST" else None
    return ToolCall(name=name, label=label, method=method, path=path, body=body)


TOOLS = {row[0]: _tool_from_row(row) for row in TOOL_ROWS}


def validate_tools() -> None:
    """Validate the bundled Policy Control demo-agent tool catalog."""

    errors: list[str] = []

    duplicate_names = _duplicates(row[0] for row in TOOL_ROWS)
    if duplicate_names:
        errors.append(f"duplicate tool name(s): {', '.join(duplicate_names)}")

    duplicate_paths = _duplicates(row[3] for row in TOOL_ROWS)
    if duplicate_paths:
        errors.append(f"duplicate tool path(s): {', '.join(duplicate_paths)}")

    mismatched_names = sorted(name for name, call in TOOLS.items() if name != call.name)
    if mismatched_names:
        errors.append(f"tool map key mismatch(es): {', '.join(mismatched_names)}")

    if errors:
        raise ValueError("; ".join(errors))


def run_tool(name: str, config: AgentConfig) -> ToolResult:
    """Run one named tool through the local sidecar proxy."""

    call = TOOLS[name]
    try:
        status = _request_through_proxy(call, config)
    except (OSError, http.client.HTTPException) as error:
        message = str(error) or error.__class__.__name__
        return ToolResult(call=call, status=None, error=message)
    return ToolResult(call=call, status=status, error=None)


def _request_through_proxy(call: ToolCall, config: AgentConfig) -> int:
    proxy = urlparse(config.proxy)
    url = urljoin(config.target, call.path)
    conn: http.client.HTTPConnection | None = None

    body = None
    headers = {
        "x-firma-session-id": config.session_id,
    }
    if call.body is not None:
        body = json.dumps(call.body).encode()
        headers["content-type"] = "application/json"
        headers["content-length"] = str(len(body))

    try:
        conn = http.client.HTTPConnection(
            proxy.hostname or "127.0.0.1",
            proxy.port or 80,
            timeout=config.timeout,
        )
        conn.request(call.method, url, body=body, headers=headers)
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        if conn is not None:
            conn.close()


def _duplicates(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        else:
            seen.add(value)
    return sorted(duplicates)
