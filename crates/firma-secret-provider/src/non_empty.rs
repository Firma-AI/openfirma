//! Non-empty wrapper types.
//!
//! [`NonEmptyStr`] and [`NonEmptyVec`] push "at least one element/character"
//! invariants into the type system, so callers and [`serde`] deserialization
//! can't construct an empty value and downstream matching logic never has to
//! re-check for it.

mod str;
mod vec;

pub use str::NonEmptyStr;
pub use vec::NonEmptyVec;
pub(crate) use vec::non_empty_vec;
