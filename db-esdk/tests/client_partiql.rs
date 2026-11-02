// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Client` PartiQL operations end to end against an in-process fake DynamoDB:
//! the client rejects a statement on a configured table before sending anything,
//! and passes any other statement through.
//! Ported from `ExecuteStatementTransform.dfy`, `BatchExecuteStatementTransform.dfy`, and `ExecuteTransactionTransform.dfy`.

mod client_support;

use aws_db_esdk::Error;
use aws_db_esdk::aws_sdk_dynamodb::types::{BatchStatementRequest, ParameterizedStatement};
use client_support::{PLAIN_TABLE, full_item, setup};

fn batch_statement(statement: &str) -> BatchStatementRequest {
    BatchStatementRequest::builder()
        .statement(statement)
        .build()
        .unwrap()
}

fn parameterized(statement: &str) -> ParameterizedStatement {
    ParameterizedStatement::builder()
        .statement(statement)
        .build()
        .unwrap()
}

/// A fake and a client, with item `a/1` stored in [`PLAIN_TABLE`].
async fn populated() -> (client_support::FakeDdb, aws_db_esdk::Client) {
    let (fake, client) = setup();
    client
        .put_item()
        .table_name(PLAIN_TABLE)
        .set_item(Some(full_item("a", "1")))
        .send()
        .await
        .unwrap();
    (fake, client)
}

#[tokio::test]
async fn execute_statement_rejects_a_configured_table() {
    let (fake, client) = setup();

    let err = client
        .execute_statement()
        .statement("update \"foo\"")
        .send()
        .await
        .unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executestatement
    //= type=test
    //= reason=asserts the Validation error, then that the fake DynamoDB received no call
    //# The request MUST fail, and the client make no network call to DynamoDB,
    //# if there exists an Item Encryptor
    //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to table named in the request.
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "ExecuteStatement not Supported on encrypted tables."
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn execute_statement_rejects_a_statement_with_no_table() {
    let (fake, client) = setup();

    let err = client
        .execute_statement()
        .statement("stuff junk")
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "Unable to extract table name from PartiQL statement."
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn execute_statement_on_an_unconfigured_table_passes_through() {
    let (_fake, client) = populated().await;

    let out = client
        .execute_statement()
        .statement(format!("SELECT * FROM \"{PLAIN_TABLE}\""))
        .send()
        .await
        .unwrap();

    assert_eq!(out.items(), [full_item("a", "1")]);
}

#[tokio::test]
async fn batch_execute_statement_rejects_any_configured_table() {
    let (fake, client) = setup();

    let err = client
        .batch_execute_statement()
        .statements(batch_statement("update \"no_such_table\""))
        .statements(batch_statement("update \"foo\""))
        .send()
        .await
        .unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-batchexecutestatement
    //= type=test
    //= reason=the second statement names foo; asserts the Validation error, then no DynamoDB call
    //# The request MUST fail, and the client make no network call to DynamoDB,
    //# if there exists an Item Encryptor
    //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to table named in any of the `Statements` of the request.
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "BatchExecuteStatement not Supported on encrypted tables."
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn batch_execute_statement_on_unconfigured_tables_passes_through() {
    let (_fake, client) = populated().await;

    let out = client
        .batch_execute_statement()
        .statements(batch_statement(&format!("SELECT * FROM \"{PLAIN_TABLE}\"")))
        .send()
        .await
        .unwrap();

    let [response] = out.responses() else {
        panic!("one response per statement");
    };
    assert_eq!(response.table_name(), Some(PLAIN_TABLE));
    assert_eq!(response.item(), Some(&full_item("a", "1")));
}

#[tokio::test]
async fn execute_transaction_rejects_any_configured_table() {
    let (fake, client) = setup();

    let err = client
        .execute_transaction()
        .transact_statements(parameterized("update \"no_such_table\""))
        .transact_statements(parameterized("update foo"))
        .send()
        .await
        .unwrap_err();

    //= spec/dynamodb-encryption-client/ddb-sdk-integration.md#validate-before-executetransaction
    //= type=test
    //= reason=the second statement names foo; asserts the Validation error, then no DynamoDB call
    //# The request MUST fail, and the client make no network call to DynamoDB,
    //# if there exists an Item Encryptor
    //# specified within the [DynamoDB Encryption Client Config](#dynamodb-encryption-client-configuration)
    //# with a [DynamoDB Table Name](./ddb-item-encryptor.md#dynamodb-table-name)
    //# equal to table named in any of the `TransactStatements` of the request.
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert_eq!(
        err.message(),
        "ExecuteTransaction not Supported on encrypted tables."
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn execute_transaction_on_unconfigured_tables_passes_through() {
    let (_fake, client) = populated().await;

    let out = client
        .execute_transaction()
        .transact_statements(parameterized(&format!("SELECT * FROM \"{PLAIN_TABLE}\"")))
        .send()
        .await
        .unwrap();

    let items: Vec<_> = out.responses().iter().map(|r| r.item()).collect();
    assert_eq!(items, [Some(&full_item("a", "1"))]);
}
