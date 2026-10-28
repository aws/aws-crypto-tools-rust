// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! An in-process fake DynamoDB that keeps its tables in memory.
//!
//! It is the HTTP client of a real `aws_sdk_dynamodb::Client`, so requests go through
//! the SDK's serializers and responses through its deserializers, and nothing leaves the process.
//! It reads the operation from `X-Amz-Target` and answers from its tables.
//!
//! Expressions: a condition, key condition, or filter is `AND`-joined terms, each
//! `name = :value`, `attribute_exists(name)`, or `attribute_not_exists(name)`;
//! an update is `SET name = :value, ...`. PartiQL: only `SELECT ... FROM "table"` runs.
//! Anything else gets a `ValidationException`, so a test never passes on an ignored expression.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use aws_db_esdk::aws_sdk_dynamodb;
use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_smithy_runtime_api::client::http::{
    HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_runtime_api::http::{Response, StatusCode};
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::retry::RetryConfig;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::json::{self, Json};

pub type Item = HashMap<String, AttributeValue>;
type Obj = BTreeMap<String, Json>;
type Reply = Result<Json, &'static str>;

/// The request ID every response carries.
pub const REQUEST_ID: &str = "fake-request-id";

const VALIDATION: &str = "ValidationException";
const NOT_FOUND: &str = "ResourceNotFoundException";
const CONDITION_FAILED: &str = "ConditionalCheckFailedException";
const TRANSACTION_CANCELED: &str = "TransactionCanceledException";

/// A fake DynamoDB. Clones share the tables.
#[derive(Clone, Debug, Default)]
pub struct FakeDdb {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    tables: BTreeMap<String, Table>,
    /// Each operation called, in order.
    calls: Vec<String>,
    /// Canned responses, by operation, used before the tables are consulted.
    canned: HashMap<String, VecDeque<(u16, String)>>,
    /// How many of each table's BatchWriteItem requests, from the first, are returned unprocessed.
    unprocessed: HashMap<String, usize>,
}

#[derive(Clone, Debug)]
struct Table {
    partition_key: String,
    sort_key: Option<String>,
    /// Items by primary key.
    items: BTreeMap<String, Obj>,
}

impl Table {
    fn key_of(&self, item: &Obj) -> Result<String, &'static str> {
        let mut key = item.get(&self.partition_key).ok_or(VALIDATION)?.to_string();
        if let Some(sort) = &self.sort_key {
            key.push('|');
            key.push_str(&item.get(sort).ok_or(VALIDATION)?.to_string());
        }
        Ok(key)
    }
}

impl FakeDdb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create table `name` with the given primary key.
    #[must_use]
    pub fn with_table(self, name: &str, partition_key: &str, sort_key: Option<&str>) -> Self {
        self.lock().tables.insert(
            name.to_owned(),
            Table {
                partition_key: partition_key.to_owned(),
                sort_key: sort_key.map(str::to_owned),
                items: BTreeMap::new(),
            },
        );
        self
    }

    /// An SDK client whose every request this fake answers.
    pub fn client(&self) -> aws_sdk_dynamodb::Client {
        let config = aws_sdk_dynamodb::Config::builder()
            .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
            .region(aws_sdk_dynamodb::config::Region::new("us-west-2"))
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                "AKIDFAKE",
                "fake-secret",
                None,
                None,
                "fake",
            ))
            .retry_config(RetryConfig::disabled())
            .http_client(self.clone())
            .build();
        aws_sdk_dynamodb::Client::from_conf(config)
    }

    /// Every item stored in `table`, in primary key order.
    pub fn items(&self, table: &str) -> Vec<Item> {
        self.lock().tables[table]
            .items
            .values()
            .map(obj_to_item)
            .collect()
    }

    /// The stored item of `table` with the primary key of `key`.
    pub fn item(&self, table: &str, key: &Item) -> Option<Item> {
        let state = self.lock();
        let t = &state.tables[table];
        let k = t.key_of(&item_to_obj(key)).expect("the key is complete");
        t.items.get(&k).map(obj_to_item)
    }

    /// Store `item` in `table` as is, bypassing any client.
    pub fn set_item(&self, table: &str, item: &Item) {
        let mut state = self.lock();
        let t = state.tables.get_mut(table).expect("the table exists");
        let obj = item_to_obj(item);
        let k = t.key_of(&obj).expect("the item has its primary key");
        t.items.insert(k, obj);
    }

    /// The operations called so far, such as `"PutItem"`.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    /// Answer the next call of `op` with `status` and `body`, instead of from the tables.
    pub fn reply_next(&self, op: &str, status: u16, body: &str) {
        self.lock()
            .canned
            .entry(op.to_owned())
            .or_default()
            .push_back((status, body.to_owned()));
    }

    /// Fail the next call of `op` with DynamoDB error `code`.
    pub fn fail_next(&self, op: &str, status: u16, code: &str) {
        self.reply_next(op, status, &error_body(code));
    }

    /// Return the first `count` BatchWriteItem requests for `table` unprocessed.
    pub fn leave_unprocessed(&self, table: &str, count: usize) {
        self.lock().unprocessed.insert(table.to_owned(), count);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("no test panicked holding the lock")
    }

    fn answer(&self, target: &str, body: &str) -> (u16, String) {
        let mut state = self.lock();
        let op = target
            .strip_prefix("DynamoDB_20120810.")
            .unwrap_or(target)
            .to_owned();
        state.calls.push(op.clone());
        if let Some(reply) = state.canned.get_mut(&op).and_then(VecDeque::pop_front) {
            return reply;
        }
        let request = json::parse(body).expect("the SDK sends JSON");
        match state.dispatch(&op, &request) {
            Ok(json) => (200, json.to_string()),
            Err(code) => (400, error_body(code)),
        }
    }
}

impl HttpClient for FakeDdb {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}

impl HttpConnector for FakeDdb {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let target = request
            .headers()
            .get("x-amz-target")
            .unwrap_or_default()
            .to_owned();
        let body = request
            .body()
            .bytes()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let (status, body) = self.answer(&target, &body);
        let mut response = Response::new(
            StatusCode::try_from(status).expect("a valid status"),
            SdkBody::from(body),
        );
        response
            .headers_mut()
            .insert("x-amzn-RequestId", REQUEST_ID);
        response
            .headers_mut()
            .insert("content-type", "application/x-amz-json-1.0");
        HttpConnectorFuture::ready(Ok(response))
    }
}

/// A DynamoDB JSON-protocol error body.
pub fn error_body(code: &str) -> String {
    format!(
        r#"{{"__type":"com.amazonaws.dynamodb.v20120810#{code}","message":"{code} from the fake"}}"#
    )
}

fn field<'a>(request: &'a Json, name: &str) -> Result<&'a Json, &'static str> {
    request.get(name).ok_or(VALIDATION)
}

fn str_field<'a>(request: &'a Json, name: &str) -> Result<&'a str, &'static str> {
    field(request, name)?.as_str().ok_or(VALIDATION)
}

fn obj_field<'a>(request: &'a Json, name: &str) -> Result<&'a Obj, &'static str> {
    field(request, name)?.as_obj().ok_or(VALIDATION)
}

fn arr_field<'a>(request: &'a Json, name: &str) -> Result<&'a [Json], &'static str> {
    field(request, name)?.as_arr().ok_or(VALIDATION)
}

fn return_values(request: &Json) -> &str {
    request
        .get("ReturnValues")
        .and_then(Json::as_str)
        .unwrap_or("NONE")
}

/// `{"Attributes": item}` when `item` is present, else `{}`.
fn attributes(item: Option<Obj>) -> Json {
    item.map_or_else(
        || Json::Obj(Obj::new()),
        |i| Json::obj([("Attributes", Json::Obj(i))]),
    )
}

/// The expression attribute names and values of a request.
struct Expressions<'a> {
    names: Option<&'a Obj>,
    values: Option<&'a Obj>,
}

impl<'a> Expressions<'a> {
    fn of(request: &'a Json) -> Self {
        Self {
            names: request
                .get("ExpressionAttributeNames")
                .and_then(Json::as_obj),
            values: request
                .get("ExpressionAttributeValues")
                .and_then(Json::as_obj),
        }
    }

    fn name(&self, token: &str) -> Result<String, &'static str> {
        let token = token.trim();
        if token.starts_with('#') {
            let name = self.names.and_then(|n| n.get(token)).ok_or(VALIDATION)?;
            Ok(name.as_str().ok_or(VALIDATION)?.to_owned())
        } else {
            Ok(token.to_owned())
        }
    }

    fn value(&self, token: &str) -> Result<&'a Json, &'static str> {
        self.values
            .and_then(|v| v.get(token.trim()))
            .ok_or(VALIDATION)
    }

    /// Whether `item` (absent when there is no item) satisfies `expr`.
    fn matches(&self, expr: Option<&str>, item: Option<&Obj>) -> Result<bool, &'static str> {
        let Some(expr) = expr else {
            return Ok(true);
        };
        for term in expr.split(" AND ").flat_map(|s| s.split(" and ")) {
            let term = term.trim();
            let ok = if let Some(inner) = call_arg(term, "attribute_not_exists") {
                let name = self.name(inner)?;
                item.is_none_or(|i| !i.contains_key(&name))
            } else if let Some(inner) = call_arg(term, "attribute_exists") {
                let name = self.name(inner)?;
                item.is_some_and(|i| i.contains_key(&name))
            } else if let Some((lhs, rhs)) = term.split_once('=') {
                let name = self.name(lhs)?;
                let want = self.value(rhs)?;
                item.and_then(|i| i.get(&name)) == Some(want)
            } else {
                return Err(VALIDATION);
            };
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Apply `SET a = :x, ...` to `item`, returning the attributes it set.
    fn update(&self, expr: &str, item: &mut Obj) -> Result<Obj, &'static str> {
        let rest = expr
            .trim()
            .get(..4)
            .filter(|p| p.eq_ignore_ascii_case("SET "))
            .map(|_| &expr.trim()[4..])
            .ok_or(VALIDATION)?;
        let mut updated = Obj::new();
        for assignment in rest.split(',') {
            let (lhs, rhs) = assignment.split_once('=').ok_or(VALIDATION)?;
            let name = self.name(lhs)?;
            let value = self.value(rhs)?.clone();
            item.insert(name.clone(), value.clone());
            updated.insert(name, value);
        }
        Ok(updated)
    }
}

/// `inner` when `term` is `func(inner)`.
fn call_arg<'t>(term: &'t str, func: &str) -> Option<&'t str> {
    term.strip_prefix(func)?
        .trim_start()
        .strip_prefix('(')?
        .strip_suffix(')')
}

/// The table a `SELECT ... FROM "table"` statement reads.
fn select_table(statement: &str) -> Result<&str, &'static str> {
    let trimmed = statement.trim_start();
    if !trimmed
        .get(..6)
        .is_some_and(|w| w.eq_ignore_ascii_case("select"))
    {
        return Err(VALIDATION);
    }
    let (_, rest) = trimmed
        .split_once("FROM \"")
        .or_else(|| trimmed.split_once("from \""))
        .ok_or(VALIDATION)?;
    rest.split('"').next().ok_or(VALIDATION)
}

fn table_mut<'a>(
    tables: &'a mut BTreeMap<String, Table>,
    name: &str,
) -> Result<&'a mut Table, &'static str> {
    tables.get_mut(name).ok_or(NOT_FOUND)
}

/// Put `request`'s item, returning the item it replaced.
fn put(tables: &mut BTreeMap<String, Table>, request: &Json) -> Result<Option<Obj>, &'static str> {
    let t = table_mut(tables, str_field(request, "TableName")?)?;
    let item = obj_field(request, "Item")?.clone();
    let key = t.key_of(&item)?;
    let old = t.items.get(&key).cloned();
    let condition = request.get("ConditionExpression").and_then(Json::as_str);
    if !Expressions::of(request).matches(condition, old.as_ref())? {
        return Err(CONDITION_FAILED);
    }
    t.items.insert(key, item);
    Ok(old)
}

/// Delete `request`'s key, returning the item it deleted.
fn delete(
    tables: &mut BTreeMap<String, Table>,
    request: &Json,
) -> Result<Option<Obj>, &'static str> {
    let t = table_mut(tables, str_field(request, "TableName")?)?;
    let key = t.key_of(obj_field(request, "Key")?)?;
    let condition = request.get("ConditionExpression").and_then(Json::as_str);
    if !Expressions::of(request).matches(condition, t.items.get(&key))? {
        return Err(CONDITION_FAILED);
    }
    Ok(t.items.remove(&key))
}

/// Update `request`'s key: the old item, the new item, and the attributes set.
fn update(
    tables: &mut BTreeMap<String, Table>,
    request: &Json,
) -> Result<(Option<Obj>, Obj, Obj), &'static str> {
    let t = table_mut(tables, str_field(request, "TableName")?)?;
    let key_attrs = obj_field(request, "Key")?;
    let key = t.key_of(key_attrs)?;
    let old = t.items.get(&key).cloned();
    let exprs = Expressions::of(request);
    let condition = request.get("ConditionExpression").and_then(Json::as_str);
    if !exprs.matches(condition, old.as_ref())? {
        return Err(CONDITION_FAILED);
    }
    let mut new = old.clone().unwrap_or_else(|| key_attrs.clone());
    let updated = exprs.update(str_field(request, "UpdateExpression")?, &mut new)?;
    t.items.insert(key, new.clone());
    Ok((old, new, updated))
}

/// The item of `table` with the primary key `key`.
fn get(
    tables: &BTreeMap<String, Table>,
    table: &str,
    key: &Obj,
) -> Result<Option<Obj>, &'static str> {
    let t = tables.get(table).ok_or(NOT_FOUND)?;
    Ok(t.items.get(&t.key_of(key)?).cloned())
}

fn item_or_empty(item: Option<Obj>) -> Json {
    item.map_or_else(
        || Json::Obj(Obj::new()),
        |i| Json::obj([("Item", Json::Obj(i))]),
    )
}

/// The first item of the table a SELECT statement reads, as `{"Item": ...}`.
fn select_first(tables: &BTreeMap<String, Table>, statement: &Json) -> Reply {
    let table = select_table(str_field(statement, "Statement")?)?;
    let t = tables.get(table).ok_or(NOT_FOUND)?;
    Ok(item_or_empty(t.items.values().next().cloned()))
}

impl State {
    fn dispatch(&mut self, op: &str, request: &Json) -> Reply {
        match op {
            "PutItem" => {
                let old = put(&mut self.tables, request)?;
                Ok(attributes(
                    old.filter(|_| return_values(request) == "ALL_OLD"),
                ))
            }
            "GetItem" => {
                let item = get(
                    &self.tables,
                    str_field(request, "TableName")?,
                    obj_field(request, "Key")?,
                )?;
                Ok(item_or_empty(item))
            }
            "DeleteItem" => {
                let old = delete(&mut self.tables, request)?;
                Ok(attributes(
                    old.filter(|_| return_values(request) == "ALL_OLD"),
                ))
            }
            "UpdateItem" => {
                let (old, new, updated) = update(&mut self.tables, request)?;
                Ok(attributes(match return_values(request) {
                    "ALL_NEW" => Some(new),
                    "ALL_OLD" => old,
                    "UPDATED_NEW" => Some(updated),
                    _ => None,
                }))
            }
            "Query" | "Scan" => self.search(op, request),
            "BatchWriteItem" => self.batch_write(request),
            "BatchGetItem" => {
                let mut responses = Obj::new();
                for (table, keys_and_attrs) in obj_field(request, "RequestItems")? {
                    let mut items = Vec::new();
                    for key in arr_field(keys_and_attrs, "Keys")? {
                        let key = key.as_obj().ok_or(VALIDATION)?;
                        if let Some(item) = get(&self.tables, table, key)? {
                            items.push(Json::Obj(item));
                        }
                    }
                    responses.insert(table.clone(), Json::Arr(items));
                }
                Ok(Json::obj([
                    ("Responses", Json::Obj(responses)),
                    ("UnprocessedKeys", Json::Obj(Obj::new())),
                ]))
            }
            "TransactWriteItems" => {
                let mut staged = self.tables.clone();
                for action in arr_field(request, "TransactItems")? {
                    transact_write(&mut staged, action).map_err(|e| {
                        if e == CONDITION_FAILED {
                            TRANSACTION_CANCELED
                        } else {
                            e
                        }
                    })?;
                }
                self.tables = staged;
                Ok(Json::Obj(Obj::new()))
            }
            "TransactGetItems" => {
                let mut responses = Vec::new();
                for action in arr_field(request, "TransactItems")? {
                    let g = field(action, "Get")?;
                    let item = get(
                        &self.tables,
                        str_field(g, "TableName")?,
                        obj_field(g, "Key")?,
                    )?;
                    responses.push(item_or_empty(item));
                }
                Ok(Json::obj([("Responses", Json::Arr(responses))]))
            }
            "ExecuteStatement" => {
                let table = select_table(str_field(request, "Statement")?)?;
                let t = self.tables.get(table).ok_or(NOT_FOUND)?;
                let items = t.items.values().cloned().map(Json::Obj).collect();
                Ok(Json::obj([("Items", Json::Arr(items))]))
            }
            "BatchExecuteStatement" => {
                let mut responses = Vec::new();
                for statement in arr_field(request, "Statements")? {
                    let table = select_table(str_field(statement, "Statement")?)?;
                    let Json::Obj(mut response) = select_first(&self.tables, statement)? else {
                        unreachable!("select_first returns an object");
                    };
                    response.insert("TableName".to_owned(), Json::Str(table.to_owned()));
                    responses.push(Json::Obj(response));
                }
                Ok(Json::obj([("Responses", Json::Arr(responses))]))
            }
            "ExecuteTransaction" => {
                let responses = arr_field(request, "TransactStatements")?
                    .iter()
                    .map(|s| select_first(&self.tables, s))
                    .collect::<Result<_, _>>()?;
                Ok(Json::obj([("Responses", Json::Arr(responses))]))
            }
            _ => Err(VALIDATION),
        }
    }

    fn search(&self, op: &str, request: &Json) -> Reply {
        let t = self
            .tables
            .get(str_field(request, "TableName")?)
            .ok_or(NOT_FOUND)?;
        let exprs = Expressions::of(request);
        let key_condition = if op == "Query" {
            Some(str_field(request, "KeyConditionExpression")?)
        } else {
            None
        };
        let filter = request.get("FilterExpression").and_then(Json::as_str);
        let mut items = Vec::new();
        for item in t.items.values() {
            if exprs.matches(key_condition, Some(item))? && exprs.matches(filter, Some(item))? {
                items.push(Json::Obj(item.clone()));
            }
        }
        let count = Json::Num(items.len().to_string());
        let scanned = Json::Num(t.items.len().to_string());
        Ok(Json::obj([
            ("Items", Json::Arr(items)),
            ("Count", count),
            ("ScannedCount", scanned),
        ]))
    }

    fn batch_write(&mut self, request: &Json) -> Reply {
        let mut unprocessed = Obj::new();
        for (table, requests) in obj_field(request, "RequestItems")? {
            let requests = requests.as_arr().ok_or(VALIDATION)?;
            let skip = self
                .unprocessed
                .get(table)
                .copied()
                .unwrap_or(0)
                .min(requests.len());
            if skip > 0 {
                unprocessed.insert(table.clone(), Json::Arr(requests[..skip].to_vec()));
            }
            let t = table_mut(&mut self.tables, table)?;
            for req in &requests[skip..] {
                if let Some(p) = req.get("PutRequest") {
                    let item = obj_field(p, "Item")?.clone();
                    t.items.insert(t.key_of(&item)?, item);
                } else if let Some(d) = req.get("DeleteRequest") {
                    let key = t.key_of(obj_field(d, "Key")?)?;
                    t.items.remove(&key);
                } else {
                    return Err(VALIDATION);
                }
            }
        }
        Ok(Json::obj([("UnprocessedItems", Json::Obj(unprocessed))]))
    }
}

fn transact_write(tables: &mut BTreeMap<String, Table>, action: &Json) -> Result<(), &'static str> {
    if let Some(p) = action.get("Put") {
        put(tables, p).map(|_| ())
    } else if let Some(d) = action.get("Delete") {
        delete(tables, d).map(|_| ())
    } else if let Some(u) = action.get("Update") {
        update(tables, u).map(|_| ())
    } else if let Some(c) = action.get("ConditionCheck") {
        let t = tables.get(str_field(c, "TableName")?).ok_or(NOT_FOUND)?;
        let item = t.items.get(&t.key_of(obj_field(c, "Key")?)?);
        let condition = str_field(c, "ConditionExpression")?;
        if Expressions::of(c).matches(Some(condition), item)? {
            Ok(())
        } else {
            Err(CONDITION_FAILED)
        }
    } else {
        Err(VALIDATION)
    }
}

/// An attribute value in DynamoDB JSON.
pub fn to_json(value: &AttributeValue) -> Json {
    let strs = |v: &[String]| Json::Arr(v.iter().cloned().map(Json::Str).collect());
    let (tag, inner) = match value {
        AttributeValue::S(s) => ("S", Json::Str(s.clone())),
        AttributeValue::N(n) => ("N", Json::Str(n.clone())),
        AttributeValue::B(b) => ("B", Json::Str(STANDARD.encode(b.as_ref()))),
        AttributeValue::Bool(b) => ("BOOL", Json::Bool(*b)),
        AttributeValue::Null(b) => ("NULL", Json::Bool(*b)),
        AttributeValue::Ss(v) => ("SS", strs(v)),
        AttributeValue::Ns(v) => ("NS", strs(v)),
        AttributeValue::Bs(v) => (
            "BS",
            Json::Arr(
                v.iter()
                    .map(|b| Json::Str(STANDARD.encode(b.as_ref())))
                    .collect(),
            ),
        ),
        AttributeValue::L(v) => ("L", Json::Arr(v.iter().map(to_json).collect())),
        AttributeValue::M(m) => ("M", Json::Obj(item_to_obj(m))),
        other => panic!("unsupported attribute value {other:?}"),
    };
    Json::obj([(tag, inner)])
}

/// An attribute value from DynamoDB JSON.
pub fn from_json(json: &Json) -> AttributeValue {
    let (tag, inner) = json
        .as_obj()
        .and_then(|m| m.iter().next())
        .expect("an attribute value is a one-entry object");
    let s = |j: &Json| j.as_str().expect("a string").to_owned();
    let blob = |j: &Json| Blob::new(STANDARD.decode(s(j)).expect("base64"));
    let arr = || inner.as_arr().expect("an array");
    match tag.as_str() {
        "S" => AttributeValue::S(s(inner)),
        "N" => AttributeValue::N(s(inner)),
        "B" => AttributeValue::B(blob(inner)),
        "BOOL" => AttributeValue::Bool(*inner == Json::Bool(true)),
        "NULL" => AttributeValue::Null(*inner == Json::Bool(true)),
        "SS" => AttributeValue::Ss(arr().iter().map(s).collect()),
        "NS" => AttributeValue::Ns(arr().iter().map(s).collect()),
        "BS" => AttributeValue::Bs(arr().iter().map(blob).collect()),
        "L" => AttributeValue::L(arr().iter().map(from_json).collect()),
        "M" => AttributeValue::M(obj_to_item(inner.as_obj().expect("an object"))),
        other => panic!("unknown attribute value type {other}"),
    }
}

fn item_to_obj(item: &Item) -> Obj {
    item.iter().map(|(k, v)| (k.clone(), to_json(v))).collect()
}

fn obj_to_item(obj: &Obj) -> Item {
    obj.iter().map(|(k, v)| (k.clone(), from_json(v))).collect()
}
