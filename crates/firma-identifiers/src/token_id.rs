firma_type_id!(
    /// A Firma-generated identifier for one capability token.
    ///
    /// Its canonical representation is a `ctok` `TypeID` backed by an RFC 9562
    /// UUID v7.
    TokenId,
    TokenIdType,
    TokenIdParseError,
    "ctok",
    "capability token id",
    SortRand,
    type_safe_id::TypeSafeId::new()
);
