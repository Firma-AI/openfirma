use crate::config;
use crate::setup::ScenarioSetup;

// ── PolicyBuilder ─────────────────────────────────────────────────────────────

/// Entry point for building Cedar policy rules programmatically.
///
/// ```ignore
/// ctx.policy()
///     .forbid("communication.external.send")
///     .when(|w| w.resource_like("paste.rs*"))
///     .add()?;
/// ```
pub struct PolicyBuilder<'a> {
    ctx: &'a ScenarioSetup,
    name: Option<&'static str>,
}

impl<'a> PolicyBuilder<'a> {
    pub(crate) fn new(ctx: &'a ScenarioSetup) -> Self {
        Self { ctx, name: None }
    }

    /// Attach an annotation comment to the generated Cedar rule.
    #[must_use]
    pub fn named(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    /// Start a `forbid` rule for a single action class.
    #[must_use]
    pub fn forbid(self, action: &'static str) -> RuleBuilder<'a> {
        self.into_rule("forbid", Effect::Single(action))
    }

    /// Start a `permit` rule for a single action class.
    #[must_use]
    pub fn permit(self, action: &'static str) -> RuleBuilder<'a> {
        self.into_rule("permit", Effect::Single(action))
    }

    /// Start a `forbid` rule covering multiple action classes.
    #[must_use]
    pub fn forbid_in(self, actions: &'static [&'static str]) -> RuleBuilder<'a> {
        self.into_rule("forbid", Effect::Set(actions))
    }

    /// Start a `permit` rule covering multiple action classes.
    #[must_use]
    pub fn permit_in(self, actions: &'static [&'static str]) -> RuleBuilder<'a> {
        self.into_rule("permit", Effect::Set(actions))
    }

    fn into_rule(self, effect: &'static str, action: Effect) -> RuleBuilder<'a> {
        RuleBuilder {
            ctx: self.ctx,
            name: self.name,
            effect,
            action,
            resource: None,
            when: None,
        }
    }
}

enum Effect {
    Single(&'static str),
    Set(&'static [&'static str]),
}

/// A Cedar rule under construction — created by [`PolicyBuilder`].
pub struct RuleBuilder<'a> {
    ctx: &'a ScenarioSetup,
    name: Option<&'static str>,
    effect: &'static str,
    action: Effect,
    resource: Option<String>,
    when: Option<String>,
}

impl RuleBuilder<'_> {
    /// Scope the rule to a specific resource entity UID (host + path).
    #[must_use]
    pub fn resource_uid(mut self, uid: impl Into<String>) -> Self {
        self.resource = Some(uid.into());
        self
    }

    /// Add a `when` clause to the rule.
    #[must_use]
    pub fn when<F>(mut self, f: F) -> Self
    where
        F: FnOnce(WhenBuilder) -> WhenBuilder,
    {
        let wb = WhenBuilder::new();
        self.when = Some(f(wb).build());
        self
    }

    /// Format the Cedar rule and write it to `policies/dev.cedar`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or written.
    pub fn add(self) -> Result<(), anyhow::Error> {
        let config_dir = self.ctx.config_dir.clone();
        let rule = self.render();
        config::append_policy_rule(&config_dir, "dev", &rule)
    }

    fn render(self) -> String {
        let mut s = String::new();
        if let Some(name) = self.name {
            s.push_str("// ");
            s.push_str(name);
            s.push('\n');
        }
        s.push_str(self.effect);
        s.push_str("(\n    principal,\n    ");
        let resource_head = self.resource.as_deref().map_or_else(
            || "resource".to_string(),
            |uid| format!("resource == Firma::Resource::\"{uid}\""),
        );
        match self.action {
            Effect::Single(a) => {
                s.push_str("action == Firma::Action::\"");
                s.push_str(a);
                s.push_str("\",\n    ");
                s.push_str(&resource_head);
                s.push_str("\n)");
            }
            Effect::Set(actions) => {
                s.push_str("action in [");
                for (i, a) in actions.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    s.push_str("Firma::Action::\"");
                    s.push_str(a);
                    s.push('"');
                }
                s.push_str("],\n    ");
                s.push_str(&resource_head);
                s.push_str("\n)");
            }
        }
        if let Some(when_clause) = self.when {
            s.push_str("\nwhen { ");
            s.push_str(&when_clause);
            s.push_str(" }");
        }
        s.push(';');
        s
    }
}

// ── WhenBuilder ───────────────────────────────────────────────────────────────

/// Accumulates `when` clause conditions via a fluent API.
pub struct WhenBuilder {
    parts: Vec<String>,
}

impl WhenBuilder {
    pub(crate) fn new() -> Self {
        Self { parts: Vec::new() }
    }

    /// `resource.id like "<pattern>"`
    #[must_use]
    pub fn resource_like(mut self, pattern: impl std::fmt::Display) -> Self {
        self.parts.push(format!("resource.id like \"{pattern}\""));
        self
    }

    /// Start a context attribute comparison.
    #[must_use]
    pub fn context(self, name: &str) -> ContextMatcher {
        ContextMatcher {
            parts: self.parts,
            name: name.to_string(),
        }
    }

    /// Chain another condition with `&&`.
    #[must_use]
    pub fn and(mut self) -> Self {
        self.parts.push("&&".to_string());
        self
    }

    fn build(self) -> String {
        self.parts.join(" ")
    }
}

// ── ContextMatcher ────────────────────────────────────────────────────────────

/// In-progress context attribute comparison — created by [`WhenBuilder::context`].
pub struct ContextMatcher {
    parts: Vec<String>,
    name: String,
}

impl ContextMatcher {
    /// `context.<name> > <value>`
    #[must_use]
    pub fn greater_than(mut self, value: impl std::fmt::Display) -> WhenBuilder {
        self.parts.push(format!("context.{} > {value}", self.name));
        WhenBuilder { parts: self.parts }
    }

    /// `context.<name> < <value>`
    #[must_use]
    pub fn less_than(mut self, value: impl std::fmt::Display) -> WhenBuilder {
        self.parts.push(format!("context.{} < {value}", self.name));
        WhenBuilder { parts: self.parts }
    }

    /// `context.<name> == <value>`
    #[must_use]
    pub fn equals(mut self, value: impl std::fmt::Display) -> WhenBuilder {
        self.parts.push(format!("context.{} == {value}", self.name));
        WhenBuilder { parts: self.parts }
    }
}
