// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A failed DynamoDB call of each `Client` operation keeps DynamoDB's own error,
//! the table it was about, and the request ID.

mod client_support;

use aws_db_esdk::aws_sdk_dynamodb::operation::{
    batch_execute_statement::BatchExecuteStatementError, batch_get_item::BatchGetItemError,
    batch_write_item::BatchWriteItemError, delete_item::DeleteItemError,
    execute_statement::ExecuteStatementError, execute_transaction::ExecuteTransactionError,
    get_item::GetItemError, put_item::PutItemError, query::QueryError, scan::ScanError,
    transact_get_items::TransactGetItemsError, transact_write_items::TransactWriteItemsError,
    update_item::UpdateItemError,
};
use aws_db_esdk::aws_sdk_dynamodb::types::{
    BatchStatementRequest, Get, KeysAndAttributes, ParameterizedStatement, Put, PutRequest,
    TransactGetItem, TransactWriteItem, WriteRequest,
};
use aws_db_esdk::error::{DynamoDbTable, Resource, RetryKind, Service};
use aws_db_esdk::{Client, Error};
use client_support::fake::REQUEST_ID;
use client_support::{TABLE, full_item, key, s, setup};

/// A table the fake does not have, and no configuration names.
const MISSING: &str = "missing";

/// Assert `err` is DynamoDB's `ResourceNotFoundException` about `table`, when known.
fn assert_not_found(err: &Error, table: Option<&str>) {
    assert!(matches!(err, Error::ResourceNotFound(_)), "{err:?}");
    assert_eq!(err.service(), Some(&Service::DynamoDb));
    assert_eq!(err.code(), Some("ResourceNotFoundException"));
    assert_eq!(err.request_id(), Some(REQUEST_ID));
    let expected = table.map(|t| Resource::DynamoDbTable(DynamoDbTable::new(t)));
    assert_eq!(err.resource(), expected.as_ref());
}

fn client() -> Client {
    setup().1
}

#[tokio::test]
async fn put_item() {
    let err = client()
        .put_item()
        .table_name(MISSING)
        .set_item(Some(full_item("a", "1")))
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, Some(MISSING));
    assert!(matches!(
        err.as_service_error::<PutItemError>(),
        Some(PutItemError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn get_item() {
    let err = client()
        .get_item()
        .table_name(MISSING)
        .set_key(Some(key("a", "1")))
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, Some(MISSING));
    assert!(matches!(
        err.as_service_error::<GetItemError>(),
        Some(GetItemError::ResourceNotFoundException(_))
    ));
    assert!(
        err.as_service_error::<PutItemError>().is_none(),
        "an error of another operation is not found"
    );
}

#[tokio::test]
async fn update_item() {
    let err = client()
        .update_item()
        .table_name(MISSING)
        .set_key(Some(key("a", "1")))
        .update_expression("SET plain = :p")
        .expression_attribute_values(":p", s("x"))
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, Some(MISSING));
    assert!(matches!(
        err.as_service_error::<UpdateItemError>(),
        Some(UpdateItemError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn delete_item() {
    let err = client()
        .delete_item()
        .table_name(MISSING)
        .set_key(Some(key("a", "1")))
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, Some(MISSING));
    assert!(matches!(
        err.as_service_error::<DeleteItemError>(),
        Some(DeleteItemError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn query() {
    let err = client()
        .query()
        .table_name(MISSING)
        .key_condition_expression("bar = :b")
        .expression_attribute_values(":b", s("a"))
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, Some(MISSING));
    assert!(matches!(
        err.as_service_error::<QueryError>(),
        Some(QueryError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn scan() {
    let err = client()
        .scan()
        .table_name(MISSING)
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, Some(MISSING));
    assert!(matches!(
        err.as_service_error::<ScanError>(),
        Some(ScanError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn batch_write_item() {
    let put = WriteRequest::builder()
        .put_request(
            PutRequest::builder()
                .set_item(Some(full_item("a", "1")))
                .build()
                .unwrap(),
        )
        .build();
    let err = client()
        .batch_write_item()
        .request_items(MISSING, vec![put])
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, None);
    assert!(matches!(
        err.as_service_error::<BatchWriteItemError>(),
        Some(BatchWriteItemError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn batch_get_item() {
    let keys = KeysAndAttributes::builder()
        .keys(key("a", "1"))
        .build()
        .unwrap();
    let err = client()
        .batch_get_item()
        .request_items(MISSING, keys)
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, None);
    assert!(matches!(
        err.as_service_error::<BatchGetItemError>(),
        Some(BatchGetItemError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn transact_write_items() {
    let put = Put::builder()
        .table_name(MISSING)
        .set_item(Some(full_item("a", "1")))
        .build()
        .unwrap();
    let err = client()
        .transact_write_items()
        .transact_items(TransactWriteItem::builder().put(put).build())
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, None);
    assert!(matches!(
        err.as_service_error::<TransactWriteItemsError>(),
        Some(TransactWriteItemsError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn transact_get_items() {
    let get = Get::builder()
        .table_name(MISSING)
        .set_key(Some(key("a", "1")))
        .build()
        .unwrap();
    let err = client()
        .transact_get_items()
        .transact_items(TransactGetItem::builder().get(get).build())
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, None);
    assert!(matches!(
        err.as_service_error::<TransactGetItemsError>(),
        Some(TransactGetItemsError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn execute_statement() {
    let err = client()
        .execute_statement()
        .statement(format!("SELECT * FROM \"{MISSING}\""))
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, None);
    assert!(matches!(
        err.as_service_error::<ExecuteStatementError>(),
        Some(ExecuteStatementError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn execute_transaction() {
    let statement = ParameterizedStatement::builder()
        .statement(format!("SELECT * FROM \"{MISSING}\""))
        .build()
        .unwrap();
    let err = client()
        .execute_transaction()
        .transact_statements(statement)
        .send()
        .await
        .unwrap_err();
    assert_not_found(&err, None);
    assert!(matches!(
        err.as_service_error::<ExecuteTransactionError>(),
        Some(ExecuteTransactionError::ResourceNotFoundException(_))
    ));
}

#[tokio::test]
async fn batch_execute_statement_internal_server_error_is_retryable() {
    let (fake, client) = setup();
    fake.fail_next("BatchExecuteStatement", 500, "InternalServerError");
    let statement = BatchStatementRequest::builder()
        .statement(format!("SELECT * FROM \"{MISSING}\""))
        .build()
        .unwrap();

    let err = client
        .batch_execute_statement()
        .statements(statement)
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Service(_)), "{err:?}");
    assert!(err.is_retryable());
    assert!(matches!(
        err.as_service_error::<BatchExecuteStatementError>(),
        Some(BatchExecuteStatementError::InternalServerError(_))
    ));
}

#[tokio::test]
async fn throttling_is_retryable() {
    let (fake, client) = setup();
    fake.fail_next("GetItem", 400, "ProvisionedThroughputExceededException");

    let err = client
        .get_item()
        .table_name(TABLE)
        .set_key(Some(key("a", "1")))
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Throttling(_)), "{err:?}");
    assert_eq!(err.retry_kind(), Some(RetryKind::Throttling));
    assert!(matches!(
        err.as_service_error::<GetItemError>(),
        Some(GetItemError::ProvisionedThroughputExceededException(_))
    ));
}
