//! Reusable endpoint and blind-relay primitives for SPEC-072.
//!
//! This crate is not approved for production use. The pinned CPace
//! construction and complete implementation still require independent review.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cbcl_protocol;
pub mod channel;
pub mod context;
pub mod cpace;
pub mod endpoint;
pub mod limiter;
pub mod mailbox;
pub mod observability;
pub mod profile;
pub mod relay;
pub mod storage;
pub mod wire;

/// Exact normative role-free bootstrap dialect source.
pub const BOOTSTRAP_DIALECT_SOURCE: &str =
    include_str!("../dialects/blind-pairing-bootstrap-v1.cbcl");

/// Exact normative projected session dialect source.
pub const SESSION_DIALECT_SOURCE: &str = include_str!("../dialects/blind-pairing-session-v1.cbcl");

/// Published SHA-256 of the exact bootstrap source bytes.
pub const BOOTSTRAP_SOURCE_SHA256: &str =
    "5607ca9c015767c433040e58e261828e6c29d427ec66ce1b76e2294cfecfa8c3";

/// Published SHA-256 of the exact session source bytes.
pub const SESSION_SOURCE_SHA256: &str =
    "f7908e42da5fe1a63e546f4d5e7619bb20f78d06c43273f8a839e82c459c9805";

/// Published canonical bootstrap dialect hash.
pub const BOOTSTRAP_DIALECT_HASH: &str =
    "sha256:534b42e5f15369a9329bcd655027e535277646f3680aa7beb14cc935723e1465";

/// Published canonical session dialect hash and required role-cast pin.
pub const SESSION_DIALECT_HASH: &str =
    "sha256:465e218843248ed867dfa385e498169607daf49c031fca7173891578e60fab3c";
