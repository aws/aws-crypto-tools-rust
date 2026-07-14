// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `test-vectors` CLI binary — thin shim over [`aws_crypto_test_vectors::cli`].
//!
//! Parses argv with clap, dispatches against the default project registry, and
//! translates any [`TestVectorError`] into a non-zero exit code with the error
//! printed to stderr.

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;

use aws_crypto_test_vectors::cli::{Cli, dispatch};
use aws_crypto_test_vectors::projects::Registry;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let registry = Registry::all();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    match dispatch(cli, &registry, &mut stdout) {
        Ok(()) => {
            stdout.flush().ok();
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(io::stderr(), "error: {err}");
            ExitCode::FAILURE
        }
    }
}
