//! Serde helpers specific to schema fields.

pub mod byte_size {
    use bytesize::ByteSize;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ByteSize, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.parse::<u64>().is_ok() {
            return Err(serde::de::Error::custom("byte size must include a unit"));
        }
        value.parse().map_err(serde::de::Error::custom)
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "Serde's `with` module requires this serializer signature"
    )]
    pub fn serialize<S>(value: &ByteSize, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("{} B", value.as_u64()).serialize(serializer)
    }
}
