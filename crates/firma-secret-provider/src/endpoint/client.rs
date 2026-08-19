use std::{fmt::Display, str::FromStr};

use crate::endpoint::error::EndpointParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEndpoint(super::EndpointInner);

impl ClientEndpoint {
    #[must_use]
    pub fn as_inner(&self) -> &super::EndpointInner {
        &self.0
    }
}

impl FromStr for ClientEndpoint {
    type Err = EndpointParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(super::EndpointInner::parse_client(s)?))
    }
}

impl Display for ClientEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
