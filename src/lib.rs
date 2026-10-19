//! Library entry point for lapiwe.
//!
//! The crate currently exposes the [`container`] module, which implements the
//! byte-level `.lpw` container format (version 1, release 1.0.0) together with
//! its encoding and decoding engine. Each submodule documents the part of the
//! format it covers.

pub mod container;
