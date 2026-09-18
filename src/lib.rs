#![forbid(unsafe_code)]

//! The opa authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: a decision fetched from an Open Policy
//! Agent (ADR-0050 section 5). The agent is asked over its REST data API —
//! `POST /v1/data/<path>` with the record and the attempt as [`input`] — and
//! answers `{"result": true}` or `{"result": false}`, or a `result` object
//! carrying `allow` and, where the policy's author was kind, a `reason`.
//! The HTTP is a few lines of HTTP/1.1 over std TCP ([`client`]); there is
//! no client crate and no runtime behind it.
//!
//! **Offline is the default (ADR-0045).** The agent is asked only where the
//! configuration says the node is online, or where the agent is on loopback
//! and asking it leaves nothing. Otherwise this policy has no opinion, and
//! [`Opa::silence`] says why, so an operator reading a gate that OPA did not
//! speak at can tell a policy that abstained from one that was never asked.
//!
//! **Asked, it fails closed.** An agent that does not answer, answers with
//! anything but 200, answers what is not JSON, has no decision at the path
//! (Rego's undefined) or carries no `allow` is a denial naming this policy
//! and the reason, never a permit and never silence: the capability counts
//! a policy that abstains as consulted, so silence from a mistyped path
//! would open the gate it was configured to guard.

pub mod client;
pub mod input;

use authorize::{Attempt, AuthorizeError, Authorizer, Decision};
use context::IdentityFacts;
use serde_json::Value;
use std::time::Duration;
use xcore::Layer;

pub use client::Endpoint;
pub use input::input;

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "opa";

/// How long the agent has to answer where configuration does not say.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// One decision at one Open Policy Agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Opa {
    endpoint: Endpoint,
    path: String,
    online: bool,
    timeout: Duration,
    silence: Option<String>,
}

impl Opa {
    /// The decision at `path` — `xmip/authz/allow` — of the agent at
    /// `endpoint` — `http://127.0.0.1:8181`. The node is offline until
    /// [`Opa::online`] says otherwise.
    ///
    /// # Errors
    ///
    /// Refuses an endpoint [`Endpoint::parse`] refuses, and a path that is
    /// empty or carries anything but letters, digits, `_`, `-`, `.` and `/`.
    pub fn at(endpoint: &str, path: &str) -> Result<Self, AuthorizeError> {
        let endpoint = Endpoint::parse(endpoint)?;
        let path = path.trim_matches('/');
        let plain = |c: char| c.is_ascii_alphanumeric() || "_-./".contains(c);

        if path.is_empty() || !path.chars().all(plain) {
            return Err(AuthorizeError::new(format!(
                "the decision path '{path}' is not a data path: \
                 segments of letters, digits, '_', '-' and '.' between '/'"
            )));
        }

        Ok(Self {
            endpoint,
            path: path.to_string(),
            online: false,
            timeout: DEFAULT_TIMEOUT,
            silence: None,
        }
        .settled())
    }

    /// Whether the node's configuration says it is online.
    #[must_use]
    pub fn online(mut self, online: bool) -> Self {
        self.online = online;
        self.settled()
    }

    /// How long the agent has to answer.
    #[must_use]
    pub fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Why this policy has no opinion, where it has none: `None` where the
    /// agent is asked, and the reason where it is not.
    #[must_use]
    pub fn silence(&self) -> Option<&str> {
        self.silence.as_deref()
    }

    fn settled(mut self) -> Self {
        self.silence = (!self.online && !self.endpoint.is_loopback()).then(|| {
            format!(
                "the node is offline and the agent at '{}' is not on loopback, \
                 so it is not asked (ADR-0045)",
                self.endpoint.host()
            )
        });
        self
    }

    /// What the agent's answer means.
    fn read(&self, status: u16, body: &str) -> Result<(), String> {
        if status != 200 {
            return Err(format!("the agent answered {status}"));
        }

        let answer: Value = serde_json::from_str(body)
            .map_err(|refused| format!("the agent's answer is not JSON: {refused}"))?;
        let result = answer.get("result").ok_or_else(|| {
            format!(
                "the agent has no decision at '{}': the result is undefined",
                self.path
            )
        })?;
        let allow = match result {
            Value::Bool(allow) => Some(*allow),
            other => other.get("allow").and_then(Value::as_bool),
        };

        match allow {
            Some(true) => Ok(()),
            Some(false) => Err(result.get("reason").and_then(Value::as_str).map_or_else(
                || format!("the agent's decision at '{}' is false", self.path),
                |reason| format!("the agent's decision at '{}': {reason}", self.path),
            )),
            None => Err(format!(
                "the agent's result at '{}' is neither true, false nor an object with allow",
                self.path
            )),
        }
    }
}

impl Authorizer for Opa {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        if self.silence.is_some() {
            return None;
        }

        let body = input(identity, attempt).to_string();
        let answer = self
            .endpoint
            .post(&format!("/v1/data/{}", self.path), &body, self.timeout)
            .map_err(|refused| refused.message)
            .and_then(|(status, body)| self.read(status, &body));

        Some(match answer {
            Ok(()) => Decision::Allowed,
            Err(reason) => Decision::denied(NAME, reason),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use xcore::{Established, mechanism};

    /// An in-process agent: answers one request with `status` and `body`,
    /// and hands back the request it was sent.
    fn agent(status: &'static str, body: &'static str) -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("an address").to_string();

        let served = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];

            // Headers, then as much body as Content-Length says.
            loop {
                let read = stream.read(&mut buffer).expect("a request");
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request);

                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .and_then(|length| length.parse::<usize>().ok())
                        .expect("a Content-Length");
                    if body.len() >= length {
                        break;
                    }
                }
                assert!(read > 0, "the request ended early");
            }

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("answered");

            String::from_utf8_lossy(&request).into_owned()
        });

        (format!("http://{address}"), served)
    }

    fn alice() -> IdentityFacts {
        IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::jwt(),
                "sub=alice",
                Established::Passed,
                Verified::Proven,
            )
            .with_evidence("department", "billing"),
            None,
        )
    }

    fn sending() -> Attempt {
        Attempt::new(Action::Send, "Billing")
    }

    #[test]
    fn what_the_agent_allows_is_a_permit_and_it_was_asked_with_the_input() {
        let (endpoint, served) = agent("200 OK", r#"{"result": true}"#);
        let opa = Opa::at(&endpoint, "xmip/authz/allow").expect("configured");

        assert_eq!(opa.silence(), None, "loopback is asked, offline or not");
        assert_eq!(opa.decide(&alice(), &sending()), Some(Decision::Allowed));
        assert_eq!(opa.name(), "opa");
        assert_eq!(opa.layer(), Layer::Transport);

        let request = served.join().expect("served");
        let (head, body) = request.split_once("\r\n\r\n").expect("a request");
        let body: Value = serde_json::from_str(body).expect("a JSON input");

        assert!(
            head.starts_with("POST /v1/data/xmip/authz/allow HTTP/1.1\r\n"),
            "{head}"
        );
        assert_eq!(body["input"]["identity"]["value"], "sub=alice");
        assert_eq!(
            body["input"]["identity"]["evidence"]["department"],
            "billing"
        );
        assert_eq!(body["input"]["action"], "send");
        assert_eq!(body["input"]["artifact"], "Billing");
    }

    #[test]
    fn what_the_agent_refuses_is_a_denial_naming_this_policy_and_the_agents_reason() {
        let (endpoint, served) = agent(
            "200 OK",
            r#"{"result": {"allow": false, "reason": "billing sends on weekdays"}}"#,
        );
        let opa = Opa::at(&endpoint, "xmip/authz").expect("configured");

        let decision = opa.decide(&alice(), &sending()).expect("an opinion");
        served.join().expect("served");

        assert_eq!(
            decision.to_string(),
            "denied by opa: the agent's decision at 'xmip/authz': billing sends on weekdays"
        );

        let (endpoint, served) = agent("200 OK", r#"{"result": false}"#);
        let decision = Opa::at(&endpoint, "xmip/authz/allow")
            .expect("configured")
            .decide(&alice(), &sending())
            .expect("an opinion");
        served.join().expect("served");

        assert_eq!(
            decision.to_string(),
            "denied by opa: the agent's decision at 'xmip/authz/allow' is false"
        );
    }

    #[test]
    fn an_offline_node_does_not_ask_an_agent_elsewhere_and_says_why() {
        let elsewhere = Opa::at("http://opa.example:8181", "xmip/authz/allow").expect("configured");

        assert_eq!(elsewhere.decide(&alice(), &sending()), None);
        assert_eq!(
            elsewhere.silence(),
            Some(
                "the node is offline and the agent at 'opa.example' is not on loopback, \
                 so it is not asked (ADR-0045)"
            )
        );
        assert_eq!(
            elsewhere.online(true).silence(),
            None,
            "an online node asks"
        );
    }

    #[test]
    fn an_agent_that_does_not_answer_is_a_denial_and_never_a_permit() {
        // A port nothing listens on: bound, read, and let go.
        let gone = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a port");
        let opa = Opa::at(&format!("http://{gone}"), "xmip/authz/allow")
            .expect("configured")
            .timing_out_after(Duration::from_millis(500));

        let Some(Decision::Denied { by, reason }) = opa.decide(&alice(), &sending()) else {
            panic!("an agent that does not answer is a denial");
        };

        assert_eq!(by, "opa");
        assert!(
            reason.starts_with(&format!("the agent at 127.0.0.1:{} did not", gone.port())),
            "{reason}"
        );
    }

    #[test]
    fn an_answer_that_decides_nothing_is_a_denial_saying_what_came_back() {
        let denied = |status: &'static str, body: &'static str| {
            let (endpoint, served) = agent(status, body);
            let decision = Opa::at(&endpoint, "xmip/authz/allow")
                .expect("configured")
                .decide(&alice(), &sending())
                .expect("an opinion");
            served.join().expect("served");
            decision.to_string()
        };

        assert_eq!(
            denied("200 OK", "{}"),
            "denied by opa: the agent has no decision at 'xmip/authz/allow': \
             the result is undefined"
        );
        assert_eq!(
            denied("500 Internal Server Error", r#"{"code": "internal_error"}"#),
            "denied by opa: the agent answered 500"
        );
        assert!(denied("200 OK", "<html>").contains("is not JSON"));
        assert!(denied("200 OK", r#"{"result": {"roles": []}}"#).contains("neither true"));
    }

    #[test]
    fn a_configuration_that_names_no_agent_or_no_decision_is_refused() {
        let refused =
            |endpoint: &str, path: &str| Opa::at(endpoint, path).expect_err("refused").message;

        assert!(refused("https://opa.example", "xmip/authz").contains("is not http://"));
        assert!(refused("http://127.0.0.1:8181", "/").contains("is not a data path"));
        assert!(refused("http://127.0.0.1:8181", "xmip/authz allow").contains("not a data path"));
    }
}
