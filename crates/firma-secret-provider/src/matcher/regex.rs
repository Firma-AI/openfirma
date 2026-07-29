use either::Either;
use http::uri::Authority;
use regex::{Captures, Regex};

use super::{MatcherError, domain::parse_authority};
use crate::{NonEmptyStr, Secret};

const NAME: &str = "name";
const VALUE: &str = "value";
const DOMAIN: &str = "domain";

/// Compiled regex with `value` and `name` named groups.
#[derive(Debug)]
pub struct CompiledRegexMatcher {
    /// The compiled pattern.
    pub pattern: Regex,
}

impl CompiledRegexMatcher {
    pub(super) fn compile(pattern: &str) -> Result<Self, MatcherError> {
        let matcher = Self {
            pattern: Regex::new(pattern).map_err(MatcherError::Regex)?,
        };
        let groups = matcher.groups(None);
        if !groups.contains(&VALUE) {
            return Err(MatcherError::MissingGroup {
                missing: VALUE,
                found: groups.join(", "),
            });
        }
        if !groups.contains(&NAME) {
            return Err(MatcherError::MissingGroup {
                missing: NAME,
                found: groups.join(", "),
            });
        }
        Ok(matcher)
    }

    pub(super) fn rewrite(
        &self,
        output: &[u8],
        mint: &mut impl FnMut(&str, Secret, Option<&Authority>, Option<&str>) -> String,
    ) -> Result<Vec<u8>, MatcherError> {
        enum Item<'a> {
            Str(&'a str),
            // Regex matchers are for flat KV stores; item is always absent.
            Mint {
                name: String,
                secret: String,
                domain: Option<Authority>,
            },
        }

        let text = std::str::from_utf8(output).map_err(|_| MatcherError::NotUtf8)?;
        let has_domain = self
            .pattern
            .capture_names()
            .any(|name| name.is_some_and(|name| name == DOMAIN));
        let mut items = Vec::new();
        let mut last = 0usize;
        for caps in self.pattern.captures_iter(text) {
            let value = caps.name(VALUE).ok_or_else(|| MatcherError::MissingGroup {
                missing: VALUE,
                found: self.groups(Some(&caps)).join(", "),
            })?;
            let name = caps
                .name(NAME)
                .map(|name| NonEmptyStr::new(name.as_str()))
                .ok_or_else(|| MatcherError::MissingGroup {
                    missing: NAME,
                    found: self.groups(Some(&caps)).join(", "),
                })?
                .map_err(|_| MatcherError::EmptyGroup(NAME))?;
            let domain = match caps.name(DOMAIN) {
                Some(m) => Some(parse_authority(m.as_str())?),
                None if has_domain => {
                    return Err(MatcherError::NoDomainMatched);
                }
                None => None,
            };

            items.push(Item::Str(&text[last..value.start()]));
            items.push(Item::Mint {
                name: name.to_owned(),
                secret: value.as_str().to_owned(),
                domain,
            });
            last = value.end();
        }
        if last == 0 {
            return Err(MatcherError::NoMatches);
        }
        items.push(Item::Str(&text[last..]));

        Ok(items
            .into_iter()
            .flat_map(|item| match item {
                Item::Str(str) => Either::Left(str.as_bytes().iter().copied()),
                Item::Mint {
                    name,
                    secret,
                    domain,
                } => Either::Right(
                    mint(&name, Secret::new(&secret), domain.as_ref(), None)
                        .into_bytes()
                        .into_iter(),
                ),
            })
            .collect())
    }

    fn groups<'a>(&'a self, caps: Option<&Captures<'_>>) -> Vec<&'a str> {
        let iter = self.pattern.capture_names().flatten();
        if let Some(caps) = caps {
            iter.filter(|name| {
                caps.name(name)
                    .is_some_and(|cap| !cap.as_str().trim().is_empty())
            })
            .collect()
        } else {
            iter.collect()
        }
    }
}
