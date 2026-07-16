// Issuance policy for the local Mini Authority in the FIR-411 spike.
// Permissive: the spike issues whatever capability the agent profile requests.
permit (
    principal,
    action,
    resource
);
