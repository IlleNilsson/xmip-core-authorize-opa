#![forbid(unsafe_code)]
//! Authorize by opa: decides by a decision fetched from an Open Policy Agent, proven against an
//! in-process one; a transport-layer policy.
//!
//! Declared and not yet written: `architecture.toml` carries the maturity. When it
//! is, it implements `Authorizer` (ADR-0050).
