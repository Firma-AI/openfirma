// Host-rule bundle for `firma policy test` parity coverage: permit-all with a
// forbid keyed on the resource `host` attribute (the cloud-metadata-endpoint
// block). Exercises that `resource.host` rules evaluate offline exactly as they
// do on the Sidecar hot path.
permit(principal, action, resource);

forbid (
    principal,
    action,
    resource
) when {
    resource has host && resource.host == "169.254.169.254"
};
