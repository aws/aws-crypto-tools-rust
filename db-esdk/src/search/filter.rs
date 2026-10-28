// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Expressions over beacons.
//!
//! A query on a beaconized attribute is rewritten to compare the beacon instead:
//! `A = :v` becomes `aws_dbe_b_A = :v`, with `:v` replaced by its beacon value.
//! A beacon matches more items than the plaintext would,
//! so the decrypted results are filtered again with the original expression.

use std::collections::HashMap;

use aws_crypto_mpl::aws_sdk_dynamodb::types::AttributeValue;

use crate::ddb::Item;
use crate::ddb::filter_expr::{
    Token, convert_to_prefix, convert_to_rpn, eval_expr, parse_expr, parsed_expr_to_string,
};
use crate::error::{Error, val_err};
use crate::search::beacon::{MaybeKeyId, MaybeKeyMap, attr_type_to_str, lcm_partition};
use crate::search::info::{BEACON_PREFIX, Beacon, BeaconPart, BeaconVersionInfo};
use crate::search::key_source::KeyLocation;
use crate::types::CryptoAction;

type Names = HashMap<String, String>;
type Values = HashMap<String, AttributeValue>;

/// The parts of a request an expression rewrite reads and writes.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExprContext {
    pub(crate) key_expr: Option<String>,
    pub(crate) filter_expr: Option<String>,
    pub(crate) values: Option<Values>,
    pub(crate) names: Option<Names>,
}

/// A beaconized expression.
struct ParsedContext {
    expr: Vec<Token>,
    values: Values,
    names: Option<Names>,
}

/// The beacon a value is compared to, and how.
struct EqualityBeacon<'a> {
    beacon: Option<&'a Beacon>,
    for_equality: bool,
    for_contains: bool,
}

impl EqualityBeacon<'_> {
    const NONE: Self = Self {
        beacon: None,
        for_equality: true,
        for_contains: false,
    };
}

/// The attribute name `t` refers to, through `names`.
fn get_attr_name<'a>(t: &'a str, names: Option<&'a Names>) -> &'a str {
    names.and_then(|n| n.get(t)).map_or(t, String::as_str)
}

/// `s` without the beacon prefix, if it has one.
fn real_name(s: &str) -> &str {
    match s.strip_prefix(BEACON_PREFIX) {
        Some(rest) if !rest.is_empty() => rest,
        _ => s,
    }
}

const fn is_equality(t: &Token) -> bool {
    matches!(t, Token::Eq | Token::Ne | Token::In)
}

impl BeaconVersionInfo {
    /// Whether `t` is an attribute that has a beacon, or is encrypted and so needs one.
    fn has_beacon(&self, t: &Token, names: Option<&Names>) -> bool {
        let Token::Attr(s) = t else {
            return false;
        };
        let name = real_name(s);
        let indirect = names.and_then(|n| n.get(name)).map(|n| real_name(n));
        self.beacons.contains_key(name)
            || indirect.is_some_and(|n| self.beacons.contains_key(n))
            || self.encrypted_fields.contains(name)
            || indirect.is_some_and(|n| self.encrypted_fields.contains(n))
    }

    /// The beacon of attribute `t`, which [`Self::has_beacon`].
    fn get_beacon2(&self, t: &Token, names: Option<&Names>) -> Result<&Beacon, Error> {
        let name = real_name(t.as_str());
        if let Some(b) = self.beacons.get(name) {
            if b.is_part_only() {
                return Err(val_err(format!(
                    "Field {name} is encrypted, and has a PartOnly beacon, and so can only be used as part of a compound beacon."
                )));
            }
            return Ok(b);
        }
        let indirect = names.and_then(|n| n.get(name)).map(|n| real_name(n));
        if let Some(b) = indirect.and_then(|n| self.beacons.get(n)) {
            return Ok(b);
        }
        let shown = if self.encrypted_fields.contains(name) {
            name
        } else {
            indirect.unwrap_or(name)
        };
        Err(val_err(format!(
            "Field {shown} is encrypted, and cannot be searched without a beacon."
        )))
    }

    fn get_beacon(
        &self,
        t: &Token,
        op: &Token,
        value: &str,
        names: Option<&Names>,
        values: &Values,
    ) -> Result<EqualityBeacon<'_>, Error> {
        let b = self.get_beacon2(t, names)?;
        can_beacon(b, op, value, values)?;
        Ok(EqualityBeacon {
            beacon: Some(b),
            for_equality: is_equality(op),
            for_contains: *op == Token::Contains,
        })
    }

    fn get_between_beacon(
        &self,
        t: &Token,
        left: &str,
        right: &str,
        names: Option<&Names>,
        values: &Values,
    ) -> Result<EqualityBeacon<'_>, Error> {
        let b = self.get_beacon2(t, names)?;
        can_between(b, left, right, values)?;
        Ok(EqualityBeacon {
            beacon: Some(b),
            for_equality: false,
            for_contains: false,
        })
    }

    /// The beacon value `expr[pos]`, a value, is compared to.
    fn beacon_for_value(
        &self,
        expr: &[Token],
        pos: usize,
        names: Option<&Names>,
        values: &Values,
    ) -> Result<EqualityBeacon<'_>, Error> {
        let value = expr[pos].as_str();
        let at = |i: usize| &expr[i];
        let has = |i: usize| self.has_beacon(&expr[i], names);
        let is_cw = |t: &Token| matches!(t, Token::Contains | Token::BeginsWith);
        // value < ATTR
        if pos + 2 < expr.len() && at(pos + 1).is_comp() && has(pos + 2) {
            return self.get_beacon(at(pos + 2), at(pos + 1), value, names, values);
        }
        // ATTR < value
        if pos >= 2 && at(pos - 1).is_comp() && has(pos - 2) {
            return self.get_beacon(at(pos - 2), at(pos - 1), value, names, values);
        }
        // contains(ATTR, value  or  begins_with(ATTR, value
        if pos >= 4
            && is_cw(at(pos - 4))
            && *at(pos - 3) == Token::Open
            && has(pos - 2)
            && *at(pos - 1) == Token::Comma
        {
            return self.get_beacon(at(pos - 2), at(pos - 4), value, names, values);
        }
        // contains(value, ATTR  or  begins_with(value, ATTR
        if pos >= 2
            && pos + 2 < expr.len()
            && is_cw(at(pos - 2))
            && *at(pos - 1) == Token::Open
            && has(pos + 2)
            && *at(pos + 1) == Token::Comma
        {
            return self.get_beacon(at(pos + 2), at(pos - 2), value, names, values);
        }
        // ATTR BETWEEN value AND *
        if pos >= 2
            && pos + 2 < expr.len()
            && *at(pos - 1) == Token::Between
            && has(pos - 2)
            && matches!(at(pos + 2), Token::Value(_))
        {
            return self.get_between_beacon(
                at(pos - 2),
                value,
                at(pos + 2).as_str(),
                names,
                values,
            );
        }
        // ATTR BETWEEN * AND value
        if pos >= 4
            && *at(pos - 1) == Token::And
            && *at(pos - 3) == Token::Between
            && has(pos - 4)
            && matches!(at(pos - 2), Token::Value(_))
        {
            return self.get_between_beacon(
                at(pos - 4),
                at(pos - 2).as_str(),
                value,
                names,
                values,
            );
        }
        // ATTR IN (value, value, ...)
        match get_in_pos(expr, pos) {
            Some(in_pos) if self.has_beacon(&expr[in_pos - 1], names) => {
                self.get_beacon(&expr[in_pos - 1], &expr[in_pos], value, names, values)
            }
            _ => Ok(EqualityBeacon::NONE),
        }
    }

    /// Rewrite `expr` onto beacons.
    fn beaconize_parsed_expr(
        &self,
        expr: &[Token],
        old_values: &Values,
        mut names: Option<Names>,
        keys: &MaybeKeyMap,
        mut new_values: Values,
        partition: u8,
    ) -> Result<ParsedContext, Error> {
        let mut acc = Vec::with_capacity(expr.len());
        for (pos, token) in expr.iter().enumerate() {
            match token {
                Token::Attr(s) => {
                    let is_indirect = s.starts_with('#');
                    let old_name = if is_indirect {
                        names
                            .as_ref()
                            .and_then(|n| n.get(s))
                            .cloned()
                            .ok_or_else(|| {
                                val_err(format!("the expression uses {s}, which is not in ExpressionAttributeNames"))
                            })?
                    } else {
                        s.clone()
                    };
                    let exclude = matches!(keys, MaybeKeyMap::DontUseKeys)
                        && !is_allowed_on_beacon_pred(expr, pos);
                    match self.beacons.get(&old_name) {
                        Some(beacon) if !exclude => {
                            is_allowed_on_beacon(expr, pos, &old_name)?;
                            if op_needs_beacon(expr, pos) {
                                let new_name = beacon.beacon_name().to_owned();
                                if is_indirect {
                                    if let Some(n) = names.as_mut() {
                                        n.insert(s.clone(), new_name);
                                    }
                                    acc.push(token.clone());
                                } else {
                                    acc.push(Token::Attr(new_name));
                                }
                            } else {
                                acc.push(token.clone());
                            }
                        }
                        _ => acc.push(token.clone()),
                    }
                }
                Token::Value(name) => {
                    let old_value = old_values.get(name).ok_or_else(|| {
                        val_err(format!(
                            "the expression uses {name}, which is not in ExpressionAttributeValues"
                        ))
                    })?;
                    let eb = self.beacon_for_value(expr, pos, names.as_ref(), old_values)?;
                    let new_value = match eb.beacon {
                        None => old_value.clone(),
                        Some(b) => b.get_beacon_value(
                            old_value,
                            keys,
                            eb.for_equality,
                            eb.for_contains,
                            partition,
                        )?,
                    };
                    if new_values.get(name).is_some_and(|v| *v != new_value) {
                        return Err(val_err(format!(
                            "{name} used in two different contexts, which is not allowed."
                        )));
                    }
                    new_values.insert(name.clone(), new_value);
                    acc.push(token.clone());
                }
                _ => acc.push(token.clone()),
            }
        }
        Ok(ParsedContext {
            expr: acc,
            values: new_values,
            names,
        })
    }

    /// The items of `items` for which the reverse Polish expression `parsed` holds,
    /// with each beacon taking the plaintext value it was computed from.
    fn filter_items(
        &self,
        parsed: &[Token],
        items: Vec<Item>,
        names: Option<&Names>,
        values: &Values,
        partition: u8,
    ) -> Result<Vec<Item>, Error> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let mut with_beacons = item.clone();
            with_beacons.extend(self.generate_plain_beacons(&item, partition)?);
            if eval_expr(parsed, &with_beacons, names, values)? {
                out.push(item);
            }
        }
        Ok(out)
    }

    /// Re-apply the key condition and filter of the original request to decrypted items,
    /// dropping the items that matched only because their beacon did.
    pub(crate) fn filter_results(
        &self,
        items: Vec<Item>,
        key_expr: Option<&str>,
        filter_expr: Option<&str>,
        names: Option<&Names>,
        values: Option<&Values>,
    ) -> Result<Vec<Item>, Error> {
        if items.is_empty() || (key_expr.is_none() && filter_expr.is_none()) {
            return Ok(items);
        }
        // Filtering needs no partition: beacons take their plaintext values.
        let partition = 0;
        let empty = Values::new();
        let values = values.unwrap_or(&empty);
        let mut items = items;
        for expr in [key_expr, filter_expr].into_iter().flatten() {
            let parsed = parse_expr(expr);
            let ctx = self.beaconize_parsed_expr(
                &parsed,
                values,
                names.cloned(),
                &MaybeKeyMap::DontUseKeys,
                Values::new(),
                partition,
            )?;
            let rpn = convert_to_rpn(&convert_to_prefix(&ctx.expr));
            items = self.filter_items(&rpn, items, ctx.names.as_ref(), &ctx.values, partition)?;
        }
        Ok(items)
    }

    /// The beacon key id that value `value`, compared to `attr`, names.
    fn key_id_from_attr(
        &self,
        attr: Option<&Token>,
        value: &str,
        names: Option<&Names>,
    ) -> Option<String> {
        let KeyLocation::Multi { key_field_name, .. } = &self.key_source.location else {
            return None;
        };
        let attr = attr?.as_str();
        if get_attr_name(attr, names) == key_field_name {
            return Some(value.to_owned());
        }
        let Some(Beacon::Compound(cmp)) = self.beacons.get(attr) else {
            return None;
        };
        let the_parts: Vec<&BeaconPart> = cmp
            .parts
            .iter()
            .filter(|p| matches!(p, BeaconPart::Signed { loc, .. } if loc.attribute_name() == key_field_name))
            .collect();
        let [part] = the_parts.as_slice() else {
            return None;
        };
        let pieces: Vec<&str> = value
            .split(cmp.split)
            .filter(|s| s.starts_with(part.prefix()))
            .collect();
        let [piece] = pieces.as_slice() else {
            return None;
        };
        Some(piece[part.prefix().len()..].to_owned())
    }

    /// The beacon key ids `expr` names, appended to `so_far`.
    fn get_beacon_key_ids(
        &self,
        expr: Option<&str>,
        values: &Values,
        names: Option<&Names>,
        so_far: &mut Vec<String>,
    ) -> Result<(), Error> {
        let Some(expr) = expr else {
            return Ok(());
        };
        let parsed = parse_expr(expr);
        for (pos, t) in parsed.iter().enumerate() {
            let Token::Value(name) = t else {
                continue;
            };
            let old_value = values.get(name).ok_or_else(|| {
                val_err(format!(
                    "the expression uses {name}, which is not in ExpressionAttributeValues"
                ))
            })?;
            if let AttributeValue::S(s) = old_value {
                let attr = attr_for_value(&parsed, pos);
                if let Some(key_id) = self.key_id_from_attr(attr, s, names)
                    && !so_far.contains(&key_id)
                {
                    so_far.push(key_id);
                }
            }
        }
        Ok(())
    }

    /// The beacon key id a query uses.
    ///
    /// # Errors
    ///
    /// A `Validation` error when a multi key store query names more than one key id.
    pub(crate) fn get_beacon_key_id(
        &self,
        key_expr: Option<&str>,
        filter_expr: Option<&str>,
        values: Option<&Values>,
        names: Option<&Names>,
    ) -> Result<MaybeKeyId, Error> {
        let KeyLocation::Multi { key_field_name, .. } = &self.key_source.location else {
            return Ok(MaybeKeyId::DontUse);
        };
        let Some(values) = values else {
            return Ok(MaybeKeyId::ShouldHave);
        };
        let mut ids = Vec::new();
        self.get_beacon_key_ids(key_expr, values, names, &mut ids)?;
        self.get_beacon_key_ids(filter_expr, values, names, &mut ids)?;
        match ids.len() {
            //= spec/searchable-encryption/search-config.md#get-beacon-key-for-query
            //# If this list of beacon key ids is empty get beacon key for query MUST
            //# return a flag indicating this.
            0 => Ok(MaybeKeyId::ShouldHave),
            //= spec/searchable-encryption/search-config.md#get-beacon-key-for-query
            //# `beacon key id` MUST be this unique value.
            1 => Ok(MaybeKeyId::Id(ids.remove(0))),
            //= spec/searchable-encryption/search-config.md#get-beacon-key-for-query
            //# If this list of beacon key ids has more than one unique beacon key id
            //# then get beacon key for query MUST fail.
            _ => Err(val_err(format!(
                "Multiple values found for {key_field_name} in query : {}",
                ids.join(", ")
            ))),
        }
    }

    /// How many queries a query with key condition `key_expr` takes, one per beacon partition.
    pub(crate) fn get_num_queries(
        &self,
        key_expr: Option<&str>,
        values: Option<&Values>,
    ) -> Result<u8, Error> {
        let (Some(key_expr), Some(values)) = (key_expr, values) else {
            return Ok(1);
        };
        let parsed = parse_expr(key_expr);
        let mut result = 1;
        for (pos, t) in parsed.iter().enumerate() {
            let Token::Value(name) = t else {
                continue;
            };
            let old_value = values.get(name).ok_or_else(|| {
                val_err(format!(
                    "the expression uses {name}, which is not in ExpressionAttributeValues"
                ))
            })?;
            let s = match old_value {
                AttributeValue::S(s) => s.as_str(),
                _ => "",
            };
            let Some(beacon) =
                attr_for_value(&parsed, pos).and_then(|a| self.beacons.get(a.as_str()))
            else {
                continue;
            };
            let partitions = beacon.num_queries(self.max_partitions, s);
            if partitions == 1 || partitions == result {
                continue;
            }
            result = lcm_partition(result, partitions, self.max_partitions);
        }
        Ok(result)
    }

    /// Rewrite the expressions of `context` onto beacons, for `partition`.
    pub(crate) async fn beaconize(
        &self,
        context: &ExprContext,
        key_id: &MaybeKeyId,
        partition: u8,
    ) -> Result<ExprContext, Error> {
        if context.key_expr.is_none() && context.filter_expr.is_none() {
            return Ok(context.clone());
        }

        //= spec/searchable-encryption/search-config.md#get-beacon-key-for-query
        //# The `beacon key id`, [Key Store Cache](#key-store-cache), and a `KeyStore`
        //# MUST be passed to [Get Beacon Key Materials](#get-beacon-key-materials)
        //# and the result returned for Get beacon key for query.
        let keys = self.get_key_map(key_id).await?;
        let empty = Values::new();
        let values = context.values.as_ref().unwrap_or(&empty);
        let mut new_values = Values::new();
        let mut new_names = context.names.clone();
        let mut out = [context.key_expr.clone(), context.filter_expr.clone()];
        for expr in &mut out {
            if let Some(e) = expr.as_deref() {
                let parsed = parse_expr(e);
                let ctx = self.beaconize_parsed_expr(
                    &parsed, values, new_names, &keys, new_values, partition,
                )?;
                *expr = Some(parsed_expr_to_string(&ctx.expr));
                new_values = ctx.values;
                new_names = ctx.names;
            }
        }
        let [key_expr, filter_expr] = out;
        Ok(ExprContext {
            key_expr,
            filter_expr,
            values: (!new_values.is_empty()).then_some(new_values),
            names: new_names,
        })
    }

    /// [`Self::beaconize`], once per partition the query must cover when it takes
    /// fewer queries than there are partitions: the filters are joined with OR.
    pub(crate) async fn do_beaconize(
        &self,
        context: &ExprContext,
        key_id: &MaybeKeyId,
        partition: u8,
        queries: u8,
    ) -> Result<ExprContext, Error> {
        let num = self.max_partitions;
        if queries == num
            || num - partition <= queries
            || context.filter_expr.is_none()
            || context.values.is_none()
        {
            return self.beaconize(context, key_id, partition).await;
        }
        let mut curr = partition;
        let mut exprs: Vec<String> = Vec::new();
        let mut values = Values::new();
        let mut key_expr = None;
        let mut names = None;
        loop {
            let local = self.beaconize(context, key_id, curr).await?;
            if curr == partition {
                exprs.push(local.filter_expr.unwrap_or_default());
                values = local.values.unwrap_or_default();
                key_expr = local.key_expr;
                names = local.names;
            } else {
                let (expr, value) = add_context(
                    values,
                    &local.filter_expr.unwrap_or_default(),
                    &local.values.unwrap_or_default(),
                )?;
                if !exprs.contains(&expr) {
                    exprs.push(expr);
                }
                values = value;
            }
            if num - curr <= queries {
                break;
            }
            curr += queries;
        }
        let filter = if let [only] = exprs.as_slice() {
            only.clone()
        } else {
            exprs
                .iter()
                .map(|e| format!("({e})"))
                .collect::<Vec<_>>()
                .join(" OR ")
        };
        Ok(ExprContext {
            key_expr,
            filter_expr: Some(filter),
            values: Some(values),
            names,
        })
    }
}

/// Reject operator `op` on beacon `b` when a beacon cannot answer it.
fn can_beacon(b: &Beacon, op: &Token, value: &str, values: &Values) -> Result<(), Error> {
    match b {
        Beacon::Standard(_) => match op {
            Token::Ne
            | Token::Lt
            | Token::Gt
            | Token::Le
            | Token::Ge
            | Token::Between
            | Token::BeginsWith => Err(val_err(format!(
                "The operation '{}' cannot be used with a standard beacon.",
                op.as_str()
            ))),
            _ => Ok(()),
        },
        Beacon::Compound(c) => {
            let val = get_string_from_value(value, values, b)?;
            match op {
                Token::Lt | Token::Gt | Token::Le | Token::Ge => {
                    let pieces: Vec<&str> = val.split(c.split).collect();
                    if c.is_less_than_comparable(&pieces)? {
                        Ok(())
                    } else {
                        Err(val_err(format!(
                            "The operation '{}' cannot be used with a compound beacon, unless the value is LessThanComparable : {val}",
                            op.as_str()
                        )))
                    }
                }
                _ => Ok(()),
            }
        }
    }
}

/// The string value of `value`, compared to compound beacon `b`.
fn get_string_from_value<'a>(
    value: &str,
    values: &'a Values,
    b: &Beacon,
) -> Result<&'a str, Error> {
    match values.get(value) {
        Some(AttributeValue::S(s)) => Ok(s),
        Some(other) => Err(val_err(format!(
            "Value {value} supplied for compound beacon {} is of type {} but must be of type S (string).",
            b.name(),
            attr_type_to_str(other)
        ))),
        None => Err(val_err(format!(
            "Value {value} used in query string, but not supplied in value map."
        ))),
    }
}

/// Reject `BETWEEN left AND right` on beacon `b` when a beacon cannot answer it.
fn can_between(b: &Beacon, left: &str, right: &str, values: &Values) -> Result<(), Error> {
    let Beacon::Compound(c) = b else {
        return Err(val_err(
            "The operation BETWEEN cannot be used with a standard beacon.",
        ));
    };
    let left_val = get_string_from_value(left, values, b)?;
    let right_val = get_string_from_value(right, values, b)?;
    let left_parts: Vec<&str> = left_val.split(c.split).collect();
    let right_parts: Vec<&str> = right_val.split(c.split).collect();
    let common = left_parts
        .iter()
        .zip(&right_parts)
        .take_while(|(l, r)| l == r)
        .count();
    let left_less = c.is_less_than_comparable(&left_parts[common..])?;
    let right_less = c.is_less_than_comparable(&right_parts[common..])?;
    if left_less && right_less {
        Ok(())
    } else {
        Err(val_err(format!(
            "To use BETWEEN with a compound beacon, the part after any common prefix must be LessThanComparable : BETWEEN {left_val} AND {right_val}"
        )))
    }
}

/// When `expr[pos]`, a value, is in `ATTR IN (value, ...)`, the position of the `IN`.
fn get_in_pos(expr: &[Token], mut pos: usize) -> Option<usize> {
    loop {
        if pos < 3 {
            return None;
        }
        if expr[pos - 1] == Token::Open && expr[pos - 2] == Token::In {
            return Some(pos - 2);
        }
        if expr[pos - 1] == Token::Comma && matches!(expr[pos - 2], Token::Value(_)) {
            pos -= 2;
        } else {
            return None;
        }
    }
}

/// The attribute `expr[pos]`, a value, is compared to.
fn attr_for_value(expr: &[Token], pos: usize) -> Option<&Token> {
    let is_attr = |t: &Token| matches!(t, Token::Attr(_));
    if pos + 2 < expr.len() && expr[pos + 1].is_comp() && is_attr(&expr[pos + 2]) {
        return Some(&expr[pos + 2]);
    }
    if pos >= 2 && expr[pos - 1].is_comp() && is_attr(&expr[pos - 2]) {
        return Some(&expr[pos - 2]);
    }
    if pos >= 4
        && matches!(expr[pos - 4], Token::Contains | Token::BeginsWith)
        && expr[pos - 3] == Token::Open
        && is_attr(&expr[pos - 2])
        && expr[pos - 1] == Token::Comma
    {
        return Some(&expr[pos - 2]);
    }
    if pos >= 2 && expr[pos - 1] == Token::Between && is_attr(&expr[pos - 2]) {
        return Some(&expr[pos - 2]);
    }
    if pos >= 4
        && expr[pos - 1] == Token::And
        && expr[pos - 3] == Token::Between
        && is_attr(&expr[pos - 4])
    {
        return Some(&expr[pos - 4]);
    }
    let in_pos = get_in_pos(expr, pos)?;
    is_attr(&expr[in_pos - 1]).then(|| &expr[in_pos - 1])
}

/// Whether the function `expr[pos]`, an attribute, is passed to needs its value:
/// `attribute_exists` and `attribute_not_exists` do not.
fn op_needs_beacon(expr: &[Token], pos: usize) -> bool {
    if pos < 2 || expr[pos - 1] != Token::Open {
        return true;
    }
    !matches!(
        expr[pos - 2],
        Token::AttributeExists | Token::AttributeNotExists
    )
}

/// Whether the function `expr[pos]`, an attribute, is passed to can take a beacon:
/// `size` and `attribute_type` cannot.
fn is_allowed_on_beacon_pred(expr: &[Token], pos: usize) -> bool {
    if pos < 2 || expr[pos - 1] != Token::Open {
        return true;
    }
    !matches!(expr[pos - 2], Token::AttributeType | Token::Size)
}

fn is_allowed_on_beacon(expr: &[Token], pos: usize, name: &str) -> Result<(), Error> {
    if is_allowed_on_beacon_pred(expr, pos) {
        Ok(())
    } else {
        Err(val_err(format!(
            "Function {} cannot be used on encrypted fields, but it is being used with {name}",
            expr[pos - 2].as_str()
        )))
    }
}

/// The first name `prev` followed by two capital letters that `values` lacks or maps to `value`.
fn make_new_name(prev: &str, values: &Values, value: &AttributeValue) -> Result<String, Error> {
    for i in b'A'..=b'Z' {
        for j in b'A'..=b'Z' {
            let name = format!("{prev}{}{}", char::from(i), char::from(j));
            if values.get(&name).is_none_or(|v| v == value) {
                return Ok(name);
            }
        }
    }
    Err(val_err(
        "could not pick an unused expression attribute value name",
    ))
}

/// A character that can be part of a value name.
const fn alpha_numeric_under(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `source` with each whole-word `old` replaced by `new`.
fn replace_all_whole(source: &str, old: &str, new: &str) -> String {
    let mut out = source.to_owned();
    let mut pos = 0;
    while let Some(found) = out[pos..].find(old).map(|f| f + pos) {
        let before = out[..found].chars().next_back();
        let after = out[found + old.len()..].chars().next();
        if before.is_some_and(alpha_numeric_under) || after.is_some_and(alpha_numeric_under) {
            pos = found + 1;
            while !out.is_char_boundary(pos) {
                pos += 1;
            }
            continue;
        }
        out.replace_range(found..found + old.len(), new);
        pos = found + new.len();
    }
    out
}

/// Merge a filter beaconized for another partition into `old_values`,
/// renaming each value that now differs.
fn add_context(
    old_values: Values,
    new_filter: &str,
    new_values: &Values,
) -> Result<(String, Values), Error> {
    let mut keys: Vec<&String> = new_values.keys().collect();
    keys.sort();
    let all_unchanged = keys
        .iter()
        .all(|k| old_values.get(*k) == new_values.get(*k));
    if all_unchanged {
        return Ok((new_filter.to_owned(), old_values));
    }
    let mut result_values = old_values.clone();
    let mut result_filter = new_filter.to_owned();
    for key in keys {
        let new_value = &new_values[key];
        if old_values.get(key).is_some_and(|v| v != new_value) {
            if key.is_empty() {
                return Err(val_err(
                    "Unexpected zero length key in ExpressionAttributeValueMap",
                ));
            }
            let new_key = make_new_name(key, &result_values, new_value)?;
            result_values.insert(new_key.clone(), new_value.clone());
            result_filter = replace_all_whole(&result_filter, key, &new_key);
        }
    }
    Ok((result_filter, result_values))
}

/// The name of an encrypted attribute `expr` names, if any.
pub(crate) fn uses_encrypted_field(
    expr: Option<&str>,
    actions: &HashMap<String, CryptoAction>,
    names: Option<&Names>,
) -> Option<String> {
    parse_expr(expr?).into_iter().find_map(|t| match t {
        Token::Attr(s) => {
            let name = get_attr_name(&s, names);
            (actions.get(name) == Some(&CryptoAction::EncryptAndSign)).then(|| name.to_owned())
        }
        _ => None,
    })
}

#[cfg(test)]
#[path = "filter_tests.rs"]
mod tests;
