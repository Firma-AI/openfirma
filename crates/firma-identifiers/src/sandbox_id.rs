firma_type_id!(
    /// A Firma-generated identifier for one sandbox execution.
    ///
    /// A sandbox ID is not a credential. Parsing proves only that the value is
    /// a canonical `sbx` `TypeID` backed by an RFC 9562 UUID v7.
    SandboxId,
    SandboxIdType,
    SandboxIdParseError,
    "sbx",
    "sandbox id",
    SortRand,
    type_safe_id::TypeSafeId::new()
);
