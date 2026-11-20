// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runs the workshop's 23 query access patterns against the beacons.
//! They cover more kinds of beacon query than the other searchable encryption examples.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::operation::query::QueryOutput;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;

fn ss(s: &str) -> AttributeValue {
    AttributeValue::S(s.to_string())
}

fn entry(name: &str, value: &str) -> (String, AttributeValue) {
    (name.to_string(), ss(value))
}

/// Runs a query until it returns `expected` items, then returns them.
///
/// Queries read a global secondary index, which is eventually consistent.
/// So the first read may miss a beacon that was just written.
/// `retry_query` calls `build` on each attempt, because sending a query consumes its builder.
async fn retry_query<F, Fut>(
    expected: usize,
    build: F,
) -> Result<Vec<HashMap<String, AttributeValue>>, crate::BoxError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<QueryOutput, aws_db_esdk::Error>>,
{
    for attempt in 1..=10 {
        let items = build().await?.items().to_vec();
        if items.len() == expected {
            return Ok(items);
        }
        if attempt < 10 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    Err(format!("query did not return {expected} items after retries").into())
}

/// The partition key of each returned item, for assertions that don't depend on order.
fn pk_set(items: &[HashMap<String, AttributeValue>]) -> Vec<AttributeValue> {
    items
        .iter()
        .map(|item| item["partition_key"].clone())
        .collect()
}

pub async fn run_queries(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    run_query1(ddb).await?;
    run_query2(ddb).await?;
    run_query3(ddb).await?;
    run_query4(ddb).await?;
    run_query5(ddb).await?;
    run_query6(ddb).await?;
    run_query7(ddb).await?;
    run_query8(ddb).await?;
    run_query9(ddb).await?;
    run_query10(ddb).await?;
    run_query11(ddb).await?;
    run_query12(ddb).await?;
    run_query13(ddb).await?;
    run_query14(ddb).await?;
    run_query15(ddb).await?;
    run_query16(ddb).await?;
    run_query17(ddb).await?;
    run_query18(ddb).await?;
    run_query19(ddb).await?;
    run_query20(ddb).await?;
    run_query21(ddb).await?;
    run_query22(ddb).await?;
    run_query23(ddb).await?;
    Ok(())
}

async fn run_query1(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Meetings by email within a date range, duration > 0.
    let names = HashMap::from([("#duration".to_string(), "Duration".to_string())]); // reserved word
    let values = HashMap::from([
        entry(":e", "EE-able@gmail.com"),
        entry(":date1", "MS-2022-07-02"),
        entry(":date2", "MS-2022-07-08"),
        entry(":zero", "0"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_names(Some(names.clone()))
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :e AND SK1 BETWEEN :date1 AND :date2")
            .filter_expression("#duration > :zero AND contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("meeting1-rust"));
    assert_eq!(items[0]["Subject"], ss("Scan Beacons"));
    assert_eq!(
        items[0]["Location"]
            .as_m()
            .ok()
            .ok_or("Location not a map")?["Floor"],
        ss("12")
    );
    assert!(
        items[0]["Attendees"]
            .as_l()
            .ok()
            .ok_or("Attendees not a list")?
            .contains(&ss("zorro@gmail.com"))
    );
    Ok(())
}

async fn run_query2(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Meetings by employee ID within a date range, duration > 0.
    let names = HashMap::from([("#duration".to_string(), "Duration".to_string())]); // reserved word
    let values = HashMap::from([
        entry(":employee", "E-emp_001"),
        entry(":date1", "MS-2022-07-02"),
        entry(":date2", "MS-2022-07-08"),
        entry(":zero", "0"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_names(Some(names.clone()))
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK = :employee AND SK BETWEEN :date1 AND :date2")
            .filter_expression("#duration > :zero AND contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("meeting1-rust"));
    assert_eq!(items[0]["Subject"], ss("Scan Beacons"));
    assert_eq!(
        items[0]["Location"]
            .as_m()
            .ok()
            .ok_or("Location not a map")?["Floor"],
        ss("12")
    );
    assert!(
        items[0]["Attendees"]
            .as_l()
            .ok()
            .ok_or("Attendees not a list")?
            .contains(&ss("zorro@gmail.com"))
    );
    Ok(())
}

async fn run_query3(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Meetings by building/floor/room within a date range.
    // A filter expression can't use a primary key attribute,
    // so this query filters on the individual beacon attributes, unlike the workshop's version.
    let values = HashMap::from([
        entry(":buildingbeacon", "B-SEA33"),
        entry(":building", "SEA33"),
        entry(":floor", "12"),
        entry(":room", "403"),
        entry(":date1", "MS-2022-07-02"),
        entry(":date2", "MS-2022-07-08"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK = :buildingbeacon AND SK BETWEEN :date1 AND :date2")
            .filter_expression(
                "Building = :building AND Floor = :floor AND Room = :room \
                 AND contains(partition_key, :rustsuffix)",
            )
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("reservation1-rust"));
    assert_eq!(items[0]["Subject"], ss("Scan beacons"));
    assert_eq!(
        items[0]["Location"]
            .as_m()
            .ok()
            .ok_or("Location not a map")?["Building"],
        ss("SEA33")
    );
    assert!(
        items[0]["Attendees"]
            .as_l()
            .ok()
            .ok_or("Attendees not a list")?
            .contains(&ss("barney@gmail.com"))
    );
    Ok(())
}

async fn run_query4(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Employee data by email and employee ID.
    let values = HashMap::from([
        entry(":email", "EE-able@gmail.com"),
        entry(":employee", "E-emp_001"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :email AND SK1 = :employee")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("employee1-rust"));
    assert_eq!(items[0]["EmployeeID"], ss("emp_001"));
    assert_eq!(
        items[0]["Location"]
            .as_m()
            .ok()
            .ok_or("Location not a map")?["Desk"],
        ss("3")
    );
    Ok(())
}

async fn run_query5(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Meetings by email, up to 30 days ago.
    let values = HashMap::from([
        entry(":email", "EE-able@gmail.com"),
        entry(":thirtydaysago", "MS-2023-03-20"),
        entry(":prefix", "MS-"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :email AND SK1 BETWEEN :prefix AND :thirtydaysago")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("meeting1-rust"));
    assert_eq!(items[0]["Subject"], ss("Scan Beacons"));
    assert_eq!(
        items[0]["Location"]
            .as_m()
            .ok()
            .ok_or("Location not a map")?["Floor"],
        ss("12")
    );
    assert!(
        items[0]["Attendees"]
            .as_l()
            .ok()
            .ok_or("Attendees not a list")?
            .contains(&ss("zorro@gmail.com"))
    );
    Ok(())
}

async fn run_query6(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Tickets by creator email, older than 30 days.
    let values = HashMap::from([
        entry(":creatoremail", "CE-zorro@gmail.com"),
        entry(":thirtydaysago", "MS-2023-03-20"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(2, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :creatoremail AND SK1 < :thirtydaysago")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    let pks = pk_set(&items);
    assert!(pks.contains(&ss("ticket1-rust")));
    assert!(pks.contains(&ss("ticket3-rust")));
    Ok(())
}

async fn run_query7(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Reservations by organizer email, older than 30 days.
    let values = HashMap::from([
        entry(":organizeremail", "OE-able@gmail.com"),
        entry(":thirtydaysago", "MS-2023-03-20"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :organizeremail AND SK1 < :thirtydaysago")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("reservation1-rust"));
    assert_eq!(items[0]["Subject"], ss("Scan beacons"));
    assert_eq!(
        items[0]["Location"]
            .as_m()
            .ok()
            .ok_or("Location not a map")?["Floor"],
        ss("12")
    );
    assert!(
        items[0]["Attendees"]
            .as_l()
            .ok()
            .ok_or("Attendees not a list")?
            .contains(&ss("barney@gmail.com"))
    );
    Ok(())
}

async fn run_query8(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Time cards by employee email, within a date range.
    let values = HashMap::from([
        entry(":email", "EE-able@gmail.com"),
        entry(":prefix", "TC-"),
        entry(":thirtydaysago", "TC-2023-03-20"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :email AND SK1 BETWEEN :prefix AND :thirtydaysago")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("timecard1-rust"));
    assert_eq!(items[0]["ProjectName"], ss("project_002"));
    Ok(())
}

async fn run_query9(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Employee info by employee ID, sort key begins with "E-".
    let values = HashMap::from([
        entry(":employee", "E-emp_001"),
        entry(":prefix", "E-"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK = :employee AND begins_with(SK, :prefix)")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("employee1-rust"));
    assert_eq!(items[0]["EmployeeID"], ss("emp_001"));
    Ok(())
}

async fn run_query10(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Employee info by email, sort key begins with "E-".
    let values = HashMap::from([
        entry(":email", "EE-able@gmail.com"),
        entry(":prefix", "E-"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :email AND begins_with(SK1, :prefix)")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("employee1-rust"));
    assert_eq!(items[0]["EmployeeID"], ss("emp_001"));
    Ok(())
}

async fn run_query11(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Ticket history by ticket number.
    let values = HashMap::from([
        entry(":ticket", "T-ticket_001"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(2, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK = :ticket")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    let pks = pk_set(&items);
    assert!(pks.contains(&ss("ticket1-rust")));
    assert!(pks.contains(&ss("ticket2-rust")));
    Ok(())
}

async fn run_query12(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Ticket history by creator email, filtered to one ticket number.
    let values = HashMap::from([
        entry(":email", "CE-zorro@gmail.com"),
        entry(":ticket", "T-ticket_001"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :email")
            .filter_expression("PK = :ticket AND contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("ticket1-rust"));
    assert_eq!(items[0]["TicketNumber"], ss("ticket_001"));
    Ok(())
}

async fn run_query13(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Ticket history by assignee email, filtered to one ticket number.
    let values = HashMap::from([
        entry(":assigneeemail", "AE-able@gmail.com"),
        entry(":ticket", "T-ticket_001"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-2")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK2 = :assigneeemail")
            .filter_expression("PK = :ticket AND contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("ticket1-rust"));
    assert_eq!(items[0]["Subject"], ss("Bad bug"));
    Ok(())
}

async fn run_query14(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Employees by city, sort key begins with building.floor.desk.
    let values = HashMap::from([
        entry(":city", "C-Seattle"),
        entry(":location", "B-44~F-12~D-3"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-3")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK3 = :city AND begins_with(SK3, :location)")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("employee1-rust"));
    assert_eq!(items[0]["EmployeeID"], ss("emp_001"));
    assert_eq!(
        items[0]["Location"]
            .as_m()
            .ok()
            .ok_or("Location not a map")?["Desk"],
        ss("3")
    );
    Ok(())
}

async fn run_query15(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Employees by manager email.
    let values = HashMap::from([
        entry(":manageremail", "ME-zorro@gmail.com"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(4, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-2")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK2 = :manageremail")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    // Expected to be `employee1` through `employee4`; spot-check `employee1`.
    let employee1 = items
        .iter()
        .find(|item| item["partition_key"] == ss("employee1-rust"))
        .ok_or("employee1-rust not returned")?;
    assert_eq!(employee1["EmployeeID"], ss("emp_001"));
    assert_eq!(
        employee1["Location"]
            .as_m()
            .ok()
            .ok_or("Location not a map")?["Desk"],
        ss("3")
    );
    Ok(())
}

async fn run_query16(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Assigned tickets by assignee email.
    let values = HashMap::from([
        entry(":assigneeemail", "AE-able@gmail.com"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(2, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-2")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK2 = :assigneeemail")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    let pks = pk_set(&items);
    assert!(pks.contains(&ss("ticket1-rust")));
    assert!(pks.contains(&ss("ticket4-rust")));
    Ok(())
}

async fn run_query17(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Tickets updated within the last 24 hours, by severity.
    // Assumes "now" is 2022-10-08T09:30:00, so "24 hours ago" is 2022-10-07T09:30:00.
    let values = HashMap::from([
        entry(":severity", "S-3"),
        entry(":yesterday", "M-2022-10-07T09:30:00"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(3, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-3")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK3 = :severity AND SK3 > :yesterday")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    // Expected to be `ticket1`, `ticket2`, and `ticket4`; spot-check `ticket1`.
    let ticket1 = items
        .iter()
        .find(|item| item["partition_key"] == ss("ticket1-rust"))
        .ok_or("ticket1-rust not returned")?;
    assert_eq!(ticket1["TicketNumber"], ss("ticket_001"));
    Ok(())
}

async fn run_query18(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Projects by status and start date, target before a date.
    let values = HashMap::from([
        entry(":status", "PSts-Pending"),
        entry(":startdate", "PS-2022-01-01"),
        entry(":target", "2025-01-01"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-1")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK1 = :status AND SK1 > :startdate")
            .filter_expression("ProjectTarget < :target AND contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("project1-rust"));
    assert_eq!(items[0]["ProjectName"], ss("project_001"));
    Ok(())
}

async fn run_query19(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Projects by name.
    let values = HashMap::from([
        entry(":projectname", "P-project_001"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK = :projectname AND SK = :projectname")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("project1-rust"));
    assert_eq!(items[0]["ProjectName"], ss("project_001"));
    Ok(())
}

async fn run_query20(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Project history by name within a date range (against timecard records).
    let values = HashMap::from([
        entry(":projectname", "P-project_002"),
        entry(":date1", "TC-2022-01-01"),
        entry(":date2", "TC-2023-01-01"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(2, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK = :projectname AND SK BETWEEN :date1 AND :date2")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    let pks = pk_set(&items);
    assert!(pks.contains(&ss("timecard1-rust")));
    assert!(pks.contains(&ss("timecard2-rust")));
    Ok(())
}

async fn run_query21(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Project history by role.
    let names = HashMap::from([("#role".to_string(), "Role".to_string())]); // reserved word
    let values = HashMap::from([
        entry(":projectname", "P-project_002"),
        entry(":role", "SDE3"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(1, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_values(Some(values.clone()))
            .set_expression_attribute_names(Some(names.clone()))
            .key_condition_expression("PK = :projectname")
            .filter_expression("#role = :role AND contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    assert_eq!(items[0]["partition_key"], ss("timecard1-rust"));
    assert_eq!(items[0]["ProjectName"], ss("project_002"));
    Ok(())
}

async fn run_query22(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Reservations by building ID.
    let values = HashMap::from([entry(":building", "B-SEA33"), entry(":rustsuffix", "-rust")]);
    let items = retry_query(2, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_values(Some(values.clone()))
            .key_condition_expression("PK = :building")
            .filter_expression("contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    let pks = pk_set(&items);
    assert!(pks.contains(&ss("reservation1-rust")));
    assert!(pks.contains(&ss("reservation2-rust")));
    Ok(())
}

async fn run_query23(ddb: &aws_db_esdk::Client) -> Result<(), crate::BoxError> {
    // Reservations by building ID within a time range, duration > 0.
    let names = HashMap::from([("#duration".to_string(), "Duration".to_string())]); // reserved word
    let values = HashMap::from([
        entry(":building", "B-SEA33"),
        entry(":date1", "MS-2022-07-01"),
        entry(":date2", "MS-2022-07-08"),
        entry(":zero", "0"),
        entry(":rustsuffix", "-rust"),
    ]);
    let items = retry_query(2, || {
        ddb.query()
            .table_name(crate::TABLE_NAME)
            .index_name("GSI-0")
            .set_expression_attribute_values(Some(values.clone()))
            .set_expression_attribute_names(Some(names.clone()))
            .key_condition_expression("PK = :building AND SK BETWEEN :date1 AND :date2")
            .filter_expression("#duration > :zero AND contains(partition_key, :rustsuffix)")
            .send()
    })
    .await?;

    let pks = pk_set(&items);
    assert!(pks.contains(&ss("reservation1-rust")));
    assert!(pks.contains(&ss("reservation2-rust")));
    Ok(())
}
