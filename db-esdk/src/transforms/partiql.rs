// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The PartiQL operations' transforms: execute statement, batch execute statement,
//! and execute transaction.
//!
//! A PartiQL statement cannot be rewritten to work on encrypted attributes,
//! so a statement on a configured table is rejected before it is sent.
//! A statement on any other table passes through unchanged, and so does its response.

use aws_crypto_mpl::aws_sdk_dynamodb::operation::batch_execute_statement::{
    BatchExecuteStatementInput, BatchExecuteStatementOutput,
};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::execute_statement::{
    ExecuteStatementInput, ExecuteStatementOutput,
};
use aws_crypto_mpl::aws_sdk_dynamodb::operation::execute_transaction::{
    ExecuteTransactionInput, ExecuteTransactionOutput,
};

use super::Transforms;
use crate::error::{Error, val_err};

impl Transforms {
    /// Reject an ExecuteStatement request on a configured table;
    /// pass any other request through unchanged.
    ///
    /// # Errors
    ///
    /// A `Validation` error when the statement names a configured table,
    /// or when no table name can be read from it.
    pub async fn execute_statement_input(
        &self,
        input: ExecuteStatementInput,
    ) -> Result<ExecuteStatementInput, Error> {
        let table = table_from_statement(input.statement.as_deref().unwrap_or_default())?;
        if self.tables.contains_key(table) {
            return Err(val_err(
                "ExecuteStatement not Supported on encrypted tables.",
            ));
        }
        Ok(input)
    }

    /// An ExecuteStatement response needs no change, so it passes through unchanged.
    ///
    /// # Errors
    ///
    /// Never fails; the signature matches the other output transforms.
    pub async fn execute_statement_output(
        &self,
        output: ExecuteStatementOutput,
        _original_input: &ExecuteStatementInput,
    ) -> Result<ExecuteStatementOutput, Error> {
        Ok(output)
    }

    /// Reject a BatchExecuteStatement request when any statement names a configured table;
    /// pass any other request through unchanged.
    ///
    /// # Errors
    ///
    /// A `Validation` error when a statement names a configured table,
    /// or when no table name can be read from one.
    pub async fn batch_execute_statement_input(
        &self,
        input: BatchExecuteStatementInput,
    ) -> Result<BatchExecuteStatementInput, Error> {
        for request in input.statements.as_deref().unwrap_or_default() {
            let table = table_from_statement(&request.statement)?;
            if self.tables.contains_key(table) {
                return Err(val_err(
                    "BatchExecuteStatement not Supported on encrypted tables.",
                ));
            }
        }
        Ok(input)
    }

    /// A BatchExecuteStatement response needs no change, so it passes through unchanged.
    ///
    /// # Errors
    ///
    /// Never fails; the signature matches the other output transforms.
    pub async fn batch_execute_statement_output(
        &self,
        output: BatchExecuteStatementOutput,
        _original_input: &BatchExecuteStatementInput,
    ) -> Result<BatchExecuteStatementOutput, Error> {
        Ok(output)
    }

    /// Reject an ExecuteTransaction request when any statement names a configured table;
    /// pass any other request through unchanged.
    ///
    /// # Errors
    ///
    /// A `Validation` error when a statement names a configured table,
    /// or when no table name can be read from one.
    pub async fn execute_transaction_input(
        &self,
        input: ExecuteTransactionInput,
    ) -> Result<ExecuteTransactionInput, Error> {
        for statement in input.transact_statements.as_deref().unwrap_or_default() {
            let table = table_from_statement(&statement.statement)?;
            if self.tables.contains_key(table) {
                return Err(val_err(
                    "ExecuteTransaction not Supported on encrypted tables.",
                ));
            }
        }
        Ok(input)
    }

    /// An ExecuteTransaction response needs no change, so it passes through unchanged.
    ///
    /// # Errors
    ///
    /// Never fails; the signature matches the other output transforms.
    pub async fn execute_transaction_output(
        &self,
        output: ExecuteTransactionOutput,
        _original_input: &ExecuteTransactionInput,
    ) -> Result<ExecuteTransactionOutput, Error> {
        Ok(output)
    }
}

/// The table a PartiQL statement reads or writes.
///
/// Handles `SELECT`, `UPDATE`, `DELETE`, `INSERT`, and `EXISTS(SELECT ...)`,
/// as in the DynamoDB PartiQL reference. For `SELECT ... FROM "table"."index"`
/// it is the table.
fn table_from_statement(s: &str) -> Result<&str, Error> {
    table_from_statement_inner(s)
        .ok_or_else(|| val_err("Unable to extract table name from PartiQL statement."))
}

fn table_from_statement_inner(s: &str) -> Option<&str> {
    let s = strip_leading_whitespace(s);
    if s.len() > 6 && s.as_bytes()[..6].eq_ignore_ascii_case(b"exists") {
        return table_from_exists_statement(&s[6..]);
    }
    let len = find_token_len(s);
    let (cmd, rest) = s.split_at(len);
    if cmd.eq_ignore_ascii_case("select") {
        table_from_select_statement(rest)
    } else if cmd.eq_ignore_ascii_case("update") {
        table_from_update_statement(rest)
    } else if cmd.eq_ignore_ascii_case("delete") {
        table_from_keyword_target(rest, "from")
    } else if cmd.eq_ignore_ascii_case("insert") {
        table_from_keyword_target(rest, "into")
    } else {
        None
    }
}

/// The token after the first bare `from`: one that is not quoted
/// and not part of a longer token. Expressions never contain one.
fn table_from_select_statement_inner(mut s: &str) -> Option<&str> {
    loop {
        if s.is_empty() {
            return None;
        }
        let t = strip_leading_whitespace(s);
        let len = find_token_len(t);
        if t[..len].eq_ignore_ascii_case("from") {
            let t = strip_leading_whitespace(&t[len..]);
            return Some(&t[..find_token_len(t)]);
        }
        if len == 0 {
            return None;
        }
        s = &t[len..];
    }
}

/// `EXISTS(SELECT ...)`: the table of the inner select.
fn table_from_exists_statement(s: &str) -> Option<&str> {
    let s = strip_leading_whitespace(s);
    let s = strip_leading_whitespace(s.strip_prefix('(')?);
    let len = find_token_len(s);
    if s[..len].eq_ignore_ascii_case("select") {
        table_from_select_statement(&s[len..])
    } else {
        None
    }
}

/// The target of a select is `table` or `table.index`; either way, the table.
fn table_from_select_statement(s: &str) -> Option<&str> {
    let name = table_from_select_statement_inner(s)?;
    match name.split_once('.') {
        Some((table, _)) => table_name(table),
        None => table_name(name),
    }
}

/// `UPDATE table ...`.
fn table_from_update_statement(s: &str) -> Option<&str> {
    let s = strip_leading_whitespace(s);
    let len = find_token_len(s);
    if len == 0 {
        None
    } else {
        table_name(&s[..len])
    }
}

/// `DELETE FROM table ...` and `INSERT INTO table ...`.
fn table_from_keyword_target<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let s = strip_leading_whitespace(s);
    let len = find_token_len(s);
    if !s[..len].eq_ignore_ascii_case(keyword) {
        return None;
    }
    let s = strip_leading_whitespace(&s[len..]);
    let len = find_token_len(s);
    if len == 0 {
        None
    } else {
        table_name(&s[..len])
    }
}

/// `s` without its surrounding double quotes, if it is a valid table name.
fn table_name(s: &str) -> Option<&str> {
    let s = s.strip_prefix('"').unwrap_or(s);
    let s = s.strip_suffix('"').unwrap_or(s);
    (3..=255).contains(&s.encode_utf16().count()).then_some(s)
}

/// Every character from NUL through space is whitespace.
const fn is_whitespace(b: u8) -> bool {
    b <= b' '
}

fn strip_leading_whitespace(s: &str) -> &str {
    s.trim_start_matches(|c: char| c.is_ascii() && is_whitespace(c as u8))
}

/// The length in bytes of the token `s` starts with: through the closing quote when it
/// starts with a double quote, else up to the next whitespace.
fn find_token_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    match bytes.first() {
        None => 0,
        Some(&b) if is_whitespace(b) => 0,
        Some(b'"') => bytes[1..]
            .iter()
            .position(|&b| b == b'"')
            .map_or(bytes.len(), |i| i + 2),
        Some(_) => bytes
            .iter()
            .position(|&b| is_whitespace(b))
            .unwrap_or(bytes.len()),
    }
}
