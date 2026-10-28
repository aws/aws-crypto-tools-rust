// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The PartiQL transforms, ported from the Dafny `ExecuteStatementTransform.dfy`,
//! `BatchExecuteStatementTransform.dfy`, and `ExecuteTransactionTransform.dfy`.

mod transforms_support;

use aws_db_esdk::aws_sdk_dynamodb::operation::batch_execute_statement::{
    BatchExecuteStatementInput, BatchExecuteStatementOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::operation::execute_statement::{
    ExecuteStatementInput, ExecuteStatementOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::operation::execute_transaction::{
    ExecuteTransactionInput, ExecuteTransactionOutput,
};
use aws_db_esdk::aws_sdk_dynamodb::types::{BatchStatementRequest, ParameterizedStatement};
use transforms_support::{expect_validation, item, s, transforms};

fn execute_statement(statement: &str) -> ExecuteStatementInput {
    ExecuteStatementInput::builder()
        .statement(statement)
        .build()
        .unwrap()
}

fn batch_execute_statement(statements: &[&str]) -> BatchExecuteStatementInput {
    BatchExecuteStatementInput::builder()
        .set_statements(Some(
            statements
                .iter()
                .map(|st| {
                    BatchStatementRequest::builder()
                        .statement(*st)
                        .build()
                        .unwrap()
                })
                .collect(),
        ))
        .build()
        .unwrap()
}

fn execute_transaction(statements: &[&str]) -> ExecuteTransactionInput {
    ExecuteTransactionInput::builder()
        .set_transact_statements(Some(
            statements
                .iter()
                .map(|st| {
                    ParameterizedStatement::builder()
                        .statement(*st)
                        .build()
                        .unwrap()
                })
                .collect(),
        ))
        .build()
        .unwrap()
}

#[tokio::test]
async fn execute_statement_input_passthrough() {
    let input = execute_statement("update \"no_such_table\"");
    let out = transforms()
        .execute_statement_input(input.clone())
        .await
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executestatement
    //= type=test
    //# If no such Item Encryptor exists,
    //# there MUST NOT be any modification
    //# to the ExecuteStatement request.
    assert_eq!(out, input);
}

#[tokio::test]
async fn execute_statement_input_encrypted() {
    let result = transforms()
        .execute_statement_input(execute_statement("update \"foo\""))
        .await;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executestatement
    //= type=test
    //# The request MUST fail, and the client make no network call to DynamoDB,
    //# if there exists an Item Encryptor
    //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to table named in the request.
    expect_validation(
        result,
        "ExecuteStatement not Supported on encrypted tables.",
    );
}

#[tokio::test]
async fn execute_statement_input_no_table() {
    let result = transforms()
        .execute_statement_input(execute_statement("stuff junk"))
        .await;
    expect_validation(
        result,
        "Unable to extract table name from PartiQL statement.",
    );
}

#[tokio::test]
async fn execute_statement_output() {
    let output = ExecuteStatementOutput::builder()
        .items(item(&[("encrypt", s("not decrypted"))]))
        .build();
    let out = transforms()
        .execute_statement_output(output.clone(), &execute_statement("foo"))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn batch_execute_statement_input_passthrough() {
    let input = batch_execute_statement(&["update \"no_such_table\"", "update \"other\""]);
    let out = transforms()
        .batch_execute_statement_input(input.clone())
        .await
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-batchexecutestatement
    //= type=test
    //# If no such Item Encryptor exists,
    //# there MUST NOT be any modification
    //# to the BatchExecuteStatement request.
    assert_eq!(out, input);
}

#[tokio::test]
async fn batch_execute_statement_input_encrypted() {
    // The configured table is the second statement's: every statement is checked.
    let result = transforms()
        .batch_execute_statement_input(batch_execute_statement(&[
            "update \"no_such_table\"",
            "update \"foo\"",
        ]))
        .await;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-batchexecutestatement
    //= type=test
    //# The request MUST fail, and the client make no network call to DynamoDB,
    //# if there exists an Item Encryptor
    //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to table named in any of the `Statements` of the request.
    expect_validation(
        result,
        "BatchExecuteStatement not Supported on encrypted tables.",
    );
}

#[tokio::test]
async fn batch_execute_statement_input_no_table() {
    let result = transforms()
        .batch_execute_statement_input(batch_execute_statement(&["select"]))
        .await;
    expect_validation(
        result,
        "Unable to extract table name from PartiQL statement.",
    );
}

#[tokio::test]
async fn batch_execute_statement_output() {
    let output = BatchExecuteStatementOutput::builder().build();
    let out = transforms()
        .batch_execute_statement_output(output.clone(), &batch_execute_statement(&["foo"]))
        .await
        .unwrap();
    assert_eq!(out, output);
}

#[tokio::test]
async fn execute_transaction_input_passthrough() {
    let input = execute_transaction(&["update \"no_such_table\"", "update \"other\""]);
    let out = transforms()
        .execute_transaction_input(input.clone())
        .await
        .unwrap();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executetransaction
    //= type=test
    //# If no such Item Encryptor exists,
    //# there MUST NOT be any modification
    //# to the ExecuteTransaction request.
    assert_eq!(out, input);
}

#[tokio::test]
async fn execute_transaction_input() {
    let result = transforms()
        .execute_transaction_input(execute_transaction(&["update foo"]))
        .await;

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executetransaction
    //= type=test
    //# The request MUST fail, and the client make no network call to DynamoDB,
    //# if there exists an Item Encryptor
    //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to table named in any of the `TransactStatements` of the request.
    expect_validation(
        result,
        "ExecuteTransaction not Supported on encrypted tables.",
    );
}

#[tokio::test]
async fn execute_transaction_input_no_table() {
    let result = transforms()
        .execute_transaction_input(execute_transaction(&["delete from"]))
        .await;
    expect_validation(
        result,
        "Unable to extract table name from PartiQL statement.",
    );
}

#[tokio::test]
async fn execute_transaction_output() {
    let output = ExecuteTransactionOutput::builder().build();
    let out = transforms()
        .execute_transaction_output(output.clone(), &execute_transaction(&["foo"]))
        .await
        .unwrap();
    assert_eq!(out, output);
}
