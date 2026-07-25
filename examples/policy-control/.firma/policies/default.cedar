// Policy Control example policy.
//
// The baseline permit lets the demo agent call mapped local endpoints through
// the Sidecar proxy. Specific @id(...) forbids below make each operation
// manageable by Policy Control.

permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action in [
        Firma::Action::"filesystem.read",
        Firma::Action::"credential.read",
        Firma::Action::"code.write",
        Firma::Action::"payment.transfer",
        Firma::Action::"communication.external.send"
    ],
    resource
);

@id("block_health_checks")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/healthz"
};

@id("block_public_readme_reads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/public/readme"
};

@id("block_secret_reads")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"credential.read",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/secrets"
};

@id("block_code_writes")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.write",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/pull-request"
};

@id("block_payment_transfers")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"payment.transfer",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/payments/transfer"
};

@id("block_external_messages")
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"127.0.0.1:19090/messages/external"
};
