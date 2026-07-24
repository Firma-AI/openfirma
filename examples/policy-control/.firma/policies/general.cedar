// Additional Policy Control example policies.
//
// Each @id(...) rule maps to one local operation so Policy Control can manage
// it separately.

@id("block_admin_dashboard_reads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/admin/dashboard"
};

@id("block_customer_profile_exports")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/customers/profiles/export"
};

@id("block_customer_email_exports")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/customers/emails/export"
};

@id("block_billing_report_downloads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/billing/reports/download"
};

@id("block_invoice_bulk_exports")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/invoices/bulk-export"
};

@id("block_payment_refunds")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"payment.transfer",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/payments/refunds"
};

@id("block_vendor_payouts")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"payment.transfer",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/vendors/payouts"
};

@id("block_secret_manager_reads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"credential.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/secrets/manager"
};

@id("block_production_env_reads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"credential.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/env/production"
};

@id("block_database_snapshot_reads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/database/snapshots"
};

@id("block_pull_request_merges")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.write",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/repositories/pull-requests/merge"
};

@id("block_production_deployments")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.write",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/deployments/production"
};

@id("block_branch_protection_changes")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.write",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/repositories/branch-protection"
};

@id("block_external_customer_messages")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/messages/customers/external"
};

@id("block_support_ticket_replies")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/support/tickets/reply"
};

@id("block_bulk_email_campaigns")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/messages/email/campaigns"
};

@id("block_training_data_exports")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/ml/training-data/export"
};

@id("block_model_weight_downloads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/ml/model-weights/download"
};

@id("block_vector_index_exports")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/ml/vector-index/export"
};

@id("block_data_warehouse_queries")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/warehouse/query"
};

@id("block_api_key_downloads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"credential.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/credentials/api-keys/download"
};

@id("block_privileged_role_grants")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.write",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/identity/roles/grant"
};

@id("block_audit_log_deletions")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.write",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/audit/logs/delete"
};

@id("block_data_retention_changes")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.write",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/governance/data-retention"
};
