// Valid Firma Cedar policy: references a real schema action (`code.read`)
// and only schema-declared context attributes (none here). Passes strict
// validation against `firma-core/firma.cedarschema`.
permit(
    principal,
    action == Firma::Action::"code.read",
    resource
);
