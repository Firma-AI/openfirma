firma_type_id!(
    /// A Firma-generated identifier for one Authority-registered agent.
    ///
    /// Its canonical representation is an `agt` `TypeID` backed by an RFC 9562
    /// UUID v7.
    AgentId,
    AgentIdType,
    AgentIdParseError,
    "agt",
    "agent id",
    SortRand,
    type_safe_id::TypeSafeId::new()
);
