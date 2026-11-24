// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Examples of every way to build the ESDK client and to call encrypt and decrypt,
//! for the API examples dashboard.
//!
//! scripts/api-examples/surface.py lists the ways from the public API.
//! Each `// api-example:` block in these tests is a piece of a customer's call:
//!
//! - a frame: the start and end of the call, such as `esdk_client.encrypt()` and `.send().await?;`.
//! - a fragment: one setter line, plus the lines before the call that get its value.
//! - a left-out block: what happens when the call leaves an option out.
//!
//! The dashboard joins the pieces into whole calls.
//! CI also builds and runs every call that the dashboard can make, from the generated
//! `tests/api_example_combos.rs`, which combos.template describes.
//! aws-crypto-tools-commons' api-examples/build_api_examples.py reads the markers
//! and says what each one means.
//! The code around each block is setup and assertions, which the dashboard does not show.

mod client;
mod decrypt;
mod encrypt;
mod support;
