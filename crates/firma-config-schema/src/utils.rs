//! Serde helpers shared by configuration fields.

pub mod byte_size {
    use bytesize::ByteSize;
    use serde::{Deserialize as _, Deserializer};

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
}
