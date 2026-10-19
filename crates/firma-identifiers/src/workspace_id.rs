firma_type_id!(
    /// A Firma-generated identifier for one Workspace.
    ///
    /// Its canonical representation is a `wsp` `TypeID` backed by an RFC 9562
    /// UUID v7, the same wire form the Firma Authority uses.
    WorkspaceId,
    WorkspaceIdType,
    WorkspaceIdParseError,
    "wsp",
    "workspace id",
    SortRand,
    type_safe_id::TypeSafeId::new()
);
