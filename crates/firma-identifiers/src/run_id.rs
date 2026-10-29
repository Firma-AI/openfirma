firma_type_id!(
    /// A Firma Team identifier for one authorized Agent run.
    ///
    /// Its canonical representation is a `run` `TypeID` backed by an RFC 9562
    /// UUID v7. Managed requests use this value as their runtime session;
    /// standalone [`crate::SessionId`] generation remains independent.
    /// Team intentionally retains a separate identifier with UUID-storage and
    /// convenience APIs; this external-interface type shares its wire format,
    /// not those private persistence APIs.
    RunId,
    RunIdType,
    RunIdParseError,
    "run",
    "run id",
    SortRand,
    type_safe_id::TypeSafeId::new()
);
