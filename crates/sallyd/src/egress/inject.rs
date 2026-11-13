//! Credential injection inside intercepted tunnels (Task 9a-3; AMENDMENTS-01 §4, maintainer
//! decision 5, architect Q27 and D7–D13).
//!
//! [`Credentials`] is the only holder of secret values in the proxy, and it cannot exist without
//! the response redaction of exactly those values (Q27: one constructor, no `Default`). Each
//! grant's header value is rendered once from its format and kept as a [`Secret`]; a
//! `HeaderValue` (whose bytes cannot be wiped) is built per request, marked sensitive, and
//! dropped with the request (architect D8). Everything here is wiped when the session's proxy
//! drops. The audit path sees grant names only ([`Prepared::names`] gives `secret:NAME`).

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use hyper::http::header::{HeaderMap, HeaderName, HeaderValue};
use sally_core::audit::{SessionForms, basic_credential};
use sally_core::manifest::{ValidatedManifest, parse_hostname};
use sally_core::secrets::{Secret, SecretStore, SecretsError};

use super::redact::{Redaction, RedactionError, TooLong};

/// The placeholder for the secret itself.
const VALUE: &str = "{value}";
/// The placeholder for `base64(basic_user:secret)` (Task 9b, AMENDMENTS-01 §4 schemes).
const BASIC: &str = "{basic}";

/// Where a session's secret values come from (architect D7): a constructor argument of the
/// starter, like the trust roots. Production reads the 0600 store ([`StoreFile`]).
pub trait SecretSource: Send + Sync + fmt::Debug {
    /// The values of `names` that exist, and only those. A name the source lacks is left out;
    /// [`Credentials::new`] refuses it by name.
    ///
    /// # Errors
    /// The store could not be read; the error carries no value.
    fn load(&self, names: &[String]) -> Result<Vec<(String, Secret<String>)>, SecretsError>;
}

/// The secrets store file. Each load opens and parses the whole file, copies the named values
/// and drops (wipes) the rest before it returns (decision 5).
#[derive(Debug, Clone)]
pub struct StoreFile {
    /// The store's path.
    pub path: PathBuf,
}

impl SecretSource for StoreFile {
    fn load(&self, names: &[String]) -> Result<Vec<(String, Secret<String>)>, SecretsError> {
        let store = SecretStore::open(&self.path)?;
        Ok(names
            .iter()
            .filter_map(|n| {
                store
                    .get(n)
                    .map(|v| (n.clone(), Secret::new(v.expose().clone())))
            })
            .collect())
    }
}

/// One secret grant as the proxy needs it: names and text only, no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// The secret's name in the store.
    pub name: String,
    /// The injection host, normalized as the egress policy normalizes it.
    pub host: String,
    /// The header the value goes into.
    pub header: String,
    /// The header value's template.
    pub format: String,
    /// The user of a `{basic}` format; `None` with `{value}`.
    pub basic_user: Option<String>,
}

impl Spec {
    /// The grants of a validated manifest, in manifest order. A host the policy cannot
    /// normalize is left out, as [`super::policy::Policy::from_manifest`] leaves it out: such a
    /// host is never intercepted.
    #[must_use]
    pub fn from_manifest(v: &ValidatedManifest) -> Vec<Self> {
        v.manifest()
            .secrets
            .iter()
            .filter_map(|s| {
                parse_hostname(&s.inject.host).ok().map(|host| Self {
                    name: s.name.clone(),
                    host,
                    header: s.inject.header.clone(),
                    format: s.inject.format.clone(),
                    basic_user: s.inject.basic_user.clone(),
                })
            })
            .collect()
    }
}

/// Why credentials could not be built. Messages name secrets, hosts and headers, never a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialsError {
    /// A grant's secret is not among the values given.
    #[error("secret {0}: not in the secrets store")]
    Missing(String),
    /// A grant's format does not hold exactly one placeholder, or its `basic_user` does not pair
    /// with it (architect ruling A2: the validator's rule, checked again).
    #[error(
        "secret {0}: the format must hold exactly one {{value}}, or one {{basic}} with a \
         basic_user that is not empty and holds no ':'"
    )]
    Format(String),
    /// Two grants inject the same header (case-insensitively) on the same host.
    #[error("host {host}: header {header} is injected twice")]
    Duplicate {
        /// The host.
        host: String,
        /// The header, lower-cased.
        header: String,
    },
    /// The header name is no header name, or the rendered value no header value.
    #[error("secret {0}: the header name or the rendered value is not valid in a header")]
    Header(String),
    /// A form of the secret is too long to redact.
    #[error(transparent)]
    TooLong(#[from] TooLong),
    /// Every redaction filler candidate occurs in a form of the session's secrets (architect
    /// Q8). Names no secret: it is a property of them all.
    #[error("no redaction filler: every candidate occurs in a secret form")]
    NoFiller,
}

/// One grant's injection.
struct Injection {
    host: String,
    header: HeaderName,
    secret: String,
    value: Secret<String>,
}

/// The session's credentials and the redaction of every form of them.
pub struct Credentials {
    injections: Vec<Injection>,
    redaction: Arc<Redaction>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let grants: Vec<(&str, &str, &str)> = self
            .injections
            .iter()
            .map(|i| (i.host.as_str(), i.header.as_str(), i.secret.as_str()))
            .collect();
        f.debug_struct("Credentials")
            .field("grants", &grants)
            .field("redaction", &self.redaction)
            .finish()
    }
}

impl Credentials {
    /// Renders each grant's header value from its secret in `values` and builds the redaction
    /// of every form of every secret plus each rendered value. Values not named by a grant are
    /// dropped (wiped) here.
    ///
    /// # Errors
    /// [`CredentialsError`], in grant order.
    pub fn new(
        specs: &[Spec],
        values: Vec<(String, Secret<String>)>,
    ) -> Result<Self, CredentialsError> {
        Self::build(specs, values)
    }

    /// [`Self::new`]'s work, in a function cargo-mutants mutates (it leaves `new` alone).
    fn build(
        specs: &[Spec],
        values: Vec<(String, Secret<String>)>,
    ) -> Result<Self, CredentialsError> {
        let mut injections: Vec<Injection> = Vec::with_capacity(specs.len());
        let mut extras: Vec<Vec<Secret<String>>> = Vec::with_capacity(specs.len());
        for s in specs {
            let value = values
                .iter()
                .find(|(n, _)| *n == s.name)
                .map(|(_, v)| v)
                .ok_or_else(|| CredentialsError::Missing(s.name.clone()))?;
            let header = HeaderName::from_bytes(s.header.as_bytes())
                .map_err(|_| CredentialsError::Header(s.name.clone()))?;
            if injections
                .iter()
                .any(|i| i.host == s.host && i.header == header)
            {
                return Err(CredentialsError::Duplicate {
                    host: s.host.clone(),
                    header: header.as_str().to_owned(),
                });
            }
            let Rendered {
                value: rendered,
                forms,
            } = render(s, value)?;
            if HeaderValue::from_str(rendered.expose()).is_err() {
                return Err(CredentialsError::Header(s.name.clone()));
            }
            injections.push(Injection {
                host: s.host.clone(),
                header,
                secret: s.name.clone(),
                value: rendered,
            });
            extras.push(forms);
        }
        let redaction = Arc::new(redaction(&injections, extras, &values)?);
        Ok(Self {
            injections,
            redaction,
        })
    }

    /// The hosts credentials are injected on, each once, in grant order.
    #[must_use]
    pub fn hosts(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for i in &self.injections {
            if !out.contains(&i.host.as_str()) {
                out.push(&i.host);
            }
        }
        out
    }

    /// The redaction every intercepted response goes through (architect D4: every secret of the
    /// session, on every grant host).
    #[must_use]
    pub fn redaction(&self) -> &Arc<Redaction> {
        &self.redaction
    }

    /// The grant headers of one request to `host`: built before its `egress.request` entry (whose
    /// `injected` is [`Prepared::names`]) and set by [`Prepared::apply`] once that entry is
    /// written (architect D13, ruling Q4). A failed append drops it unused.
    #[must_use]
    pub fn prepare(&self, host: &str) -> Prepared {
        let mut names = Vec::new();
        let mut pairs = Vec::new();
        for i in self.injections.iter().filter(|i| i.host == host) {
            // Cannot fail: `new` refused a value that is no header value. Skipping is fail-safe:
            // nothing is sent and nothing is reported as injected.
            if let Ok(mut v) = HeaderValue::from_str(i.value.expose()) {
                v.set_sensitive(true);
                names.push(format!("secret:{}", i.secret));
                pairs.push((i.header.clone(), v));
            }
        }
        Prepared { names, pairs }
    }
}

/// One request's grant headers, sensitive values built for it alone (architect D8). Consumed by
/// [`Prepared::apply`]; no `Clone`, no `Default`; `Debug` prints the names only.
pub struct Prepared {
    names: Vec<String>,
    pairs: Vec<(HeaderName, HeaderValue)>,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("names", &self.names)
            .finish_non_exhaustive()
    }
}

impl Prepared {
    /// The `injected` list of `egress.request`: `secret:NAME` for each header this sets, in order.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Sets each header in `headers`, replacing every value there (the client's copies were
    /// dropped already: architect Q40; this is the second guard).
    pub fn apply(self, headers: &mut HeaderMap) {
        for (name, value) in self.pairs {
            headers.insert(name, value);
        }
    }
}

/// A grant's header value, and the forms of it its redaction adds to the secret's own.
struct Rendered {
    value: Secret<String>,
    forms: Vec<Secret<String>>,
}

/// The grant's header value: its format with its one placeholder replaced, by splitting at the
/// placeholder (architect D11), never by a replace that could recurse. `{value}` takes the
/// secret; `{basic}` takes [`basic_credential`] of `basic_user` and the secret, and adds that
/// blob, padded and unpadded, to the forms (AMENDMENTS-02 B1). The pairing of placeholder and
/// user is checked again here (architect ruling A2).
fn render(s: &Spec, secret: &Secret<String>) -> Result<Rendered, CredentialsError> {
    let refused = || CredentialsError::Format(s.name.clone());
    let placeholders = (
        s.format.matches(VALUE).count(),
        s.format.matches(BASIC).count(),
    );
    let (placeholder, blob) = match (placeholders, s.basic_user.as_deref()) {
        ((1, 0), None) => (VALUE, None),
        ((0, 1), Some(user)) if !user.is_empty() && !user.contains(':') => {
            (BASIC, Some(basic_credential(user, secret.expose())))
        }
        _ => return Err(refused()),
    };
    let (prefix, suffix) = s.format.split_once(placeholder).ok_or_else(refused)?;
    let middle = blob.as_ref().map_or(secret.expose(), Secret::expose);
    let mut out = String::with_capacity(prefix.len() + middle.len() + suffix.len());
    out.push_str(prefix);
    out.push_str(middle);
    out.push_str(suffix);
    let value = Secret::new(out);
    let mut forms = vec![Secret::new(value.expose().clone())];
    if let Some(blob) = blob {
        forms.push(Secret::new(blob.expose().trim_end_matches('=').to_owned()));
        forms.push(blob);
    }
    Ok(Rendered { value, forms })
}

/// The session's forms, one secret per grant name in grant order: sally-core's forms of its
/// value (architect D3) and each grant's [`Rendered::forms`] (its rendered header value, and a
/// `{basic}` blob), built once and read in place by the redaction (architect Q11). Each
/// injection keeps its own copy of its rendered value, a [`Secret`] wiped on drop like the forms.
fn redaction(
    injections: &[Injection],
    extras: Vec<Vec<Secret<String>>>,
    values: &[(String, Secret<String>)],
) -> Result<Redaction, CredentialsError> {
    let entries = injections.iter().zip(extras).filter_map(|(i, forms)| {
        values
            .iter()
            .find(|(n, _)| *n == i.secret)
            .map(|(_, v)| (i.secret.as_str(), v, forms))
    });
    Redaction::of(SessionForms::build(entries)).map_err(|e| match e {
        RedactionError::TooLong(t) => CredentialsError::TooLong(t),
        RedactionError::NoFiller => CredentialsError::NoFiller,
    })
}

#[cfg(test)]
#[path = "inject_tests.rs"]
mod tests;

/// Credentials and a secrets source for the proxy's unit tests (never built outside tests).
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// The value test grant `i` holds, assembled at runtime (no credential-shaped literal).
    pub(crate) fn value(i: usize) -> String {
        format!("sp-test-{i}-{}", "k".repeat(24))
    }

    /// One `Authorization: Bearer {value}` grant per host, grant `i` named `T{i}` with
    /// [`value`]`(i)`.
    pub(crate) fn credentials(hosts: &[&str]) -> Credentials {
        let specs: Vec<Spec> = hosts
            .iter()
            .enumerate()
            .map(|(i, h)| Spec {
                name: format!("T{i}"),
                host: (*h).to_owned(),
                header: "Authorization".into(),
                format: "Bearer {value}".into(),
                basic_user: None,
            })
            .collect();
        let values = (0..hosts.len())
            .map(|i| (format!("T{i}"), Secret::new(value(i))))
            .collect();
        Credentials::new(&specs, values).expect("test grants are valid")
    }

    /// A source over fixed values.
    #[derive(Debug, Default)]
    pub(crate) struct Fixed(pub Vec<(String, String)>);

    impl SecretSource for Fixed {
        fn load(&self, names: &[String]) -> Result<Vec<(String, Secret<String>)>, SecretsError> {
            Ok(self
                .0
                .iter()
                .filter(|(n, _)| names.contains(n))
                .map(|(n, v)| (n.clone(), Secret::new(v.clone())))
                .collect())
        }
    }
}
