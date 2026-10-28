// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The public face of structured encryption: the client, its operations, and their data shapes.

use std::collections::HashMap;

use aws_crypto_mpl::cmm::SharedCmm;

use super::ParsedHeader;
use super::util::{AuthAction, AuthField, CryptoField, Terminal};
use crate::error::{Error, val_err};
use crate::types::{AlgorithmSuiteId, CryptoAction, EncryptionContext};

/// A serialized value and its two-byte type id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
//= spec/structured-encryption/structures.md#overview
//= type=implication
//# These structures define a group of related fields that MUST hold certain properties.
//
//= spec/structured-encryption/structures.md#overview
//= type=implication
//# Wherever these structures are referenced in this specification,
//# implementations MUST ensure that all properties of a structure's fields are upheld.
pub struct StructuredDataTerminal {
    //= spec/structured-encryption/structures.md#terminal-value
    //= type=implication
    //# Terminal Value MUST be a sequence of bytes, and MAY be empty (zero-length).
    value: Vec<u8>,

    //= spec/structured-encryption/structures.md#terminal-type-id
    //= type=implication
    //# A Terminal Type ID MUST be a 2 byte value that is used to identify how callers interpret [Terminal Value](#terminal-value).
    type_id: [u8; 2],
}

impl StructuredDataTerminal {
    /// A terminal of `value`, of type `type_id`.
    #[must_use]
    pub const fn new(type_id: [u8; 2], value: Vec<u8>) -> Self {
        Self { value, type_id }
    }

    /// The serialized value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The type id the value is serialized as.
    #[must_use]
    pub const fn type_id(&self) -> [u8; 2] {
        self.type_id
    }

    /// Take the value out of the terminal.
    #[must_use]
    pub fn into_value(self) -> Vec<u8> {
        self.value
    }
}

impl From<StructuredDataTerminal> for Terminal {
    fn from(t: StructuredDataTerminal) -> Self {
        Self::new(t.type_id, t.value)
    }
}

impl From<Terminal> for StructuredDataTerminal {
    fn from(t: Terminal) -> Self {
        Self::new(t.type_id, t.value)
    }
}

/// A member of a structure, named by its key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StructureSegment {
    key: String,
}

impl StructureSegment {
    /// The member named `key`.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// The member's name.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// One step of a [`Path`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathSegment {
    /// A member of a structure.
    //= spec/structured-encryption/structures.md#path-segment
    //= type=implication
    //# A path segment MUST be a string, designating the name of a member of a structure.
    Member(StructureSegment),
}

impl PathSegment {
    /// The step into the structure member named `key`.
    #[must_use]
    pub fn member(key: impl Into<String>) -> Self {
        Self::Member(StructureSegment::new(key))
    }
}

/// The location of a terminal in a structure, outermost step first.
pub type Path = Vec<PathSegment>;

fn to_inner_path(path: Path) -> Vec<String> {
    path.into_iter()
        .map(|segment| match segment {
            PathSegment::Member(member) => member.key,
        })
        .collect()
}

fn from_inner_path(path: Vec<String>) -> Path {
    path.into_iter().map(PathSegment::member).collect()
}

/// Whether a field of a structure being decrypted is covered by the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthenticateAction {
    /// The field is signed.
    Sign,
    /// The field is not signed.
    DoNotSign,
}

impl From<AuthenticateAction> for AuthAction {
    fn from(a: AuthenticateAction) -> Self {
        match a {
            AuthenticateAction::Sign => Self::Sign,
            AuthenticateAction::DoNotSign => Self::DoNotSign,
        }
    }
}

/// A terminal, where it is, and what to do with it when encrypting.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
//= spec/structured-encryption/structures.md#crypto-item
//= type=implication
//# A crypto item MUST consist of
pub struct CryptoItem {
    key: Path,
    data: StructuredDataTerminal,
    action: CryptoAction,
}

impl CryptoItem {
    /// The terminal `data` at `key`, with `action`.
    #[must_use]
    pub const fn new(key: Path, data: StructuredDataTerminal, action: CryptoAction) -> Self {
        Self { key, data, action }
    }

    /// Where the terminal is.
    #[must_use]
    pub fn key(&self) -> &[PathSegment] {
        &self.key
    }

    /// The terminal.
    #[must_use]
    pub const fn data(&self) -> &StructuredDataTerminal {
        &self.data
    }

    /// What is done with the terminal.
    #[must_use]
    pub const fn action(&self) -> CryptoAction {
        self.action
    }
}

impl From<CryptoItem> for CryptoField {
    fn from(x: CryptoItem) -> Self {
        Self {
            key: to_inner_path(x.key),
            data: x.data.into(),
            action: x.action,
        }
    }
}

impl From<CryptoField> for CryptoItem {
    fn from(x: CryptoField) -> Self {
        Self::new(from_inner_path(x.key), x.data.into(), x.action)
    }
}

/// A terminal of a structure being decrypted, where it is, and whether it is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
//= spec/structured-encryption/structures.md#auth-item
//= type=implication
//# An auth item MUST consist of
pub struct AuthItem {
    key: Path,
    data: StructuredDataTerminal,
    action: AuthenticateAction,
}

impl AuthItem {
    /// The terminal `data` at `key`, with `action`.
    #[must_use]
    pub const fn new(key: Path, data: StructuredDataTerminal, action: AuthenticateAction) -> Self {
        Self { key, data, action }
    }

    /// Where the terminal is.
    #[must_use]
    pub fn key(&self) -> &[PathSegment] {
        &self.key
    }

    /// The terminal.
    #[must_use]
    pub const fn data(&self) -> &StructuredDataTerminal {
        &self.data
    }

    /// Whether the terminal is signed.
    #[must_use]
    pub const fn action(&self) -> AuthenticateAction {
        self.action
    }
}

impl From<AuthItem> for AuthField {
    fn from(x: AuthItem) -> Self {
        Self {
            key: to_inner_path(x.key),
            data: x.data.into(),
            action: x.action.into(),
        }
    }
}

fn to_inner_map(map: HashMap<String, StructuredDataTerminal>) -> HashMap<String, Terminal> {
    map.into_iter().map(|(k, v)| (k, v.into())).collect()
}

fn from_inner_map(map: HashMap<String, Terminal>) -> HashMap<String, StructuredDataTerminal> {
    map.into_iter().map(|(k, v)| (k, v.into())).collect()
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, Error> {
    value.ok_or_else(|| val_err(format!("{name} is required")))
}

fn add_context(ec: &mut Option<EncryptionContext>, key: String, value: String) {
    ec.get_or_insert_with(EncryptionContext::new)
        .insert(key, value);
}

/// Encrypts, signs, verifies, and decrypts structures of terminals.
///
/// It is the layer beneath the item encryptor, public only for the test server.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct StructuredEncryption {}

impl StructuredEncryption {
    /// A structured encryption client.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Encrypt and sign a map of top-level fields.
    #[must_use]
    pub fn encrypt_structure(&self) -> EncryptStructureFluentBuilder {
        EncryptStructureFluentBuilder::default()
    }

    /// Verify and decrypt a map of top-level fields.
    #[must_use]
    pub fn decrypt_structure(&self) -> DecryptStructureFluentBuilder {
        DecryptStructureFluentBuilder::default()
    }

    /// Encrypt and sign a list of terminals, each at its own path.
    #[must_use]
    pub fn encrypt_path_structure(&self) -> EncryptPathStructureFluentBuilder {
        EncryptPathStructureFluentBuilder::default()
    }

    /// Verify and decrypt a list of terminals, each at its own path.
    #[must_use]
    pub fn decrypt_path_structure(&self) -> DecryptPathStructureFluentBuilder {
        DecryptPathStructureFluentBuilder::default()
    }

    /// Find the action an encrypted structure's header gives each of its terminals.
    #[must_use]
    pub fn resolve_auth_actions(&self) -> ResolveAuthActionsFluentBuilder {
        ResolveAuthActionsFluentBuilder::default()
    }
}

/// Builds and sends an [`encrypt_structure`](StructuredEncryption::encrypt_structure) call.
#[derive(Clone, Debug, Default)]
pub struct EncryptStructureFluentBuilder {
    table_name: Option<String>,

    //= spec/structured-encryption/structures.md#structured-data-map
    //= type=implication
    //# A Structured Data Map MUST consist of:
    //
    //= spec/structured-encryption/structures.md#structured-data-map
    //= type=implication
    //# - This map MUST NOT allow duplicate key values
    plaintext_structure: Option<HashMap<String, StructuredDataTerminal>>,
    crypto_schema: Option<HashMap<String, CryptoAction>>,
    cmm: Option<SharedCmm>,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
}

impl EncryptStructureFluentBuilder {
    /// The logical table name, bound into every signature. Required.
    #[must_use]
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = Some(name.into());
        self
    }

    /// Set or clear the logical table name.
    #[must_use]
    pub fn set_table_name(mut self, name: Option<String>) -> Self {
        self.table_name = name;
        self
    }

    /// Add one plaintext field. Call again to add more. Required.
    #[must_use]
    pub fn plaintext_structure(
        mut self,
        name: impl Into<String>,
        value: StructuredDataTerminal,
    ) -> Self {
        self.plaintext_structure
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), value);
        self
    }

    /// Set or clear the whole plaintext structure.
    #[must_use]
    pub fn set_plaintext_structure(
        mut self,
        structure: Option<HashMap<String, StructuredDataTerminal>>,
    ) -> Self {
        self.plaintext_structure = structure;
        self
    }

    /// Add the action of one field. Call again to add more.
    /// Required, with exactly the fields of the plaintext structure.
    #[must_use]
    pub fn crypto_schema(mut self, name: impl Into<String>, action: CryptoAction) -> Self {
        self.crypto_schema
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), action);
        self
    }

    /// Set or clear the whole crypto schema.
    #[must_use]
    pub fn set_crypto_schema(mut self, schema: Option<HashMap<String, CryptoAction>>) -> Self {
        self.crypto_schema = schema;
        self
    }

    /// The CMM that provides the encryption materials. Required.
    #[must_use]
    pub fn cmm(mut self, cmm: SharedCmm) -> Self {
        self.cmm = Some(cmm);
        self
    }

    /// Set or clear the CMM.
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// The algorithm suite. The default signs with ECDSA P-384 and HMAC-SHA-384.
    #[must_use]
    pub const fn algorithm_suite_id(mut self, id: AlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(id);
        self
    }

    /// Set or clear the algorithm suite.
    #[must_use]
    pub const fn set_algorithm_suite_id(mut self, id: Option<AlgorithmSuiteId>) -> Self {
        self.algorithm_suite_id = id;
        self
    }

    /// Add one encryption context entry. Call again to add more.
    #[must_use]
    pub fn encryption_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        add_context(&mut self.encryption_context, key.into(), value.into());
        self
    }

    /// Set or clear the whole encryption context.
    #[must_use]
    pub fn set_encryption_context(mut self, ec: Option<EncryptionContext>) -> Self {
        self.encryption_context = ec;
        self
    }

    /// Encrypt and sign the structure.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a required input is unset,
    ///   or the schema does not name exactly the fields of the structure.
    /// - Any error of the CMM, or of serializing or encrypting the structure.
    pub async fn send(self) -> Result<EncryptStructureOutput, Error> {
        //= spec/structured-encryption/encrypt-structure.md#input
        //= reason=each of the four inputs is unwrapped by required(), which rejects it unset
        //# The following inputs to this behavior are REQUIRED:
        let table = required(self.table_name, "table_name")?;
        let plaintext = to_inner_map(required(self.plaintext_structure, "plaintext_structure")?);
        let schema = required(self.crypto_schema, "crypto_schema")?;
        let cmm = required(self.cmm, "cmm")?;

        //= spec/structured-encryption/encrypt-structure.md#input
        //= reason=the algorithm suite and encryption context are passed on as Options
        //# The following inputs to this behavior MUST be OPTIONAL:
        let out = super::encrypt_structure(
            &table,
            plaintext,
            &schema,
            cmm,
            self.algorithm_suite_id,
            self.encryption_context,
        )
        .await?;

        //= spec/structured-encryption/encrypt-structure.md#output
        //# This operation MUST output the following:
        Ok(EncryptStructureOutput {
            encrypted_structure: from_inner_map(out.data),
            crypto_schema: out.schema,
            parsed_header: out.parsed_header,
        })
    }
}

/// The result of [`encrypt_structure`](StructuredEncryption::encrypt_structure).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EncryptStructureOutput {
    encrypted_structure: HashMap<String, StructuredDataTerminal>,
    crypto_schema: HashMap<String, CryptoAction>,
    parsed_header: ParsedHeader,
}

impl EncryptStructureOutput {
    /// Every field, encrypted where its action says, plus the header and footer.
    #[must_use]
    pub const fn encrypted_structure(&self) -> &HashMap<String, StructuredDataTerminal> {
        &self.encrypted_structure
    }

    /// Take the encrypted structure out of the output.
    #[must_use]
    pub fn into_encrypted_structure(self) -> HashMap<String, StructuredDataTerminal> {
        self.encrypted_structure
    }

    /// The action of each signed field.
    #[must_use]
    pub const fn crypto_schema(&self) -> &HashMap<String, CryptoAction> {
        &self.crypto_schema
    }

    /// What the new header says.
    #[must_use]
    pub const fn parsed_header(&self) -> &ParsedHeader {
        &self.parsed_header
    }
}

/// Builds and sends a [`decrypt_structure`](StructuredEncryption::decrypt_structure) call.
#[derive(Clone, Debug, Default)]
pub struct DecryptStructureFluentBuilder {
    table_name: Option<String>,
    encrypted_structure: Option<HashMap<String, StructuredDataTerminal>>,
    authenticate_schema: Option<HashMap<String, AuthenticateAction>>,
    cmm: Option<SharedCmm>,
    encryption_context: Option<EncryptionContext>,
}

impl DecryptStructureFluentBuilder {
    /// The logical table name the structure was encrypted for. Required.
    #[must_use]
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = Some(name.into());
        self
    }

    /// Set or clear the logical table name.
    #[must_use]
    pub fn set_table_name(mut self, name: Option<String>) -> Self {
        self.table_name = name;
        self
    }

    /// Add one encrypted field, the header and footer included. Call again to add more. Required.
    #[must_use]
    pub fn encrypted_structure(
        mut self,
        name: impl Into<String>,
        value: StructuredDataTerminal,
    ) -> Self {
        self.encrypted_structure
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), value);
        self
    }

    /// Set or clear the whole encrypted structure.
    #[must_use]
    pub fn set_encrypted_structure(
        mut self,
        structure: Option<HashMap<String, StructuredDataTerminal>>,
    ) -> Self {
        self.encrypted_structure = structure;
        self
    }

    /// Add whether one field is signed. Call again to add more.
    /// Required, with exactly the fields of the encrypted structure.
    #[must_use]
    pub fn authenticate_schema(
        mut self,
        name: impl Into<String>,
        action: AuthenticateAction,
    ) -> Self {
        self.authenticate_schema
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), action);
        self
    }

    /// Set or clear the whole authenticate schema.
    #[must_use]
    pub fn set_authenticate_schema(
        mut self,
        schema: Option<HashMap<String, AuthenticateAction>>,
    ) -> Self {
        self.authenticate_schema = schema;
        self
    }

    /// The CMM that provides the decryption materials. Required.
    #[must_use]
    pub fn cmm(mut self, cmm: SharedCmm) -> Self {
        self.cmm = Some(cmm);
        self
    }

    /// Set or clear the CMM.
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Add one encryption context entry the structure must have been encrypted with.
    /// Call again to add more.
    #[must_use]
    pub fn encryption_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        add_context(&mut self.encryption_context, key.into(), value.into());
        self
    }

    /// Set or clear the whole encryption context.
    #[must_use]
    pub fn set_encryption_context(mut self, ec: Option<EncryptionContext>) -> Self {
        self.encryption_context = ec;
        self
    }

    /// Verify and decrypt the structure.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a required input is unset,
    ///   or the schema does not name exactly the fields of the structure.
    /// - Any error of the CMM, or of parsing, verifying, or decrypting the structure.
    pub async fn send(self) -> Result<DecryptStructureOutput, Error> {
        //= spec/structured-encryption/decrypt-structure.md#input
        //= reason=each of the four inputs is unwrapped by required(), which rejects it unset
        //# The following inputs to this behavior are REQUIRED:
        let table = required(self.table_name, "table_name")?;
        let encrypted = to_inner_map(required(self.encrypted_structure, "encrypted_structure")?);
        let schema: HashMap<String, AuthAction> =
            required(self.authenticate_schema, "authenticate_schema")?
                .into_iter()
                .map(|(k, a)| (k, a.into()))
                .collect();
        let cmm = required(self.cmm, "cmm")?;

        //= spec/structured-encryption/decrypt-structure.md#input
        //= reason=the encryption context is passed on as an Option
        //# The following inputs to this behavior MUST be OPTIONAL:
        let out =
            super::decrypt_structure(&table, encrypted, &schema, cmm, self.encryption_context)
                .await?;

        //= spec/structured-encryption/decrypt-structure.md#output
        //# This operation MUST output the following:
        Ok(DecryptStructureOutput {
            plaintext_structure: from_inner_map(out.data),
            crypto_schema: out.schema,
            parsed_header: out.parsed_header,
        })
    }
}

/// The result of [`decrypt_structure`](StructuredEncryption::decrypt_structure).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DecryptStructureOutput {
    plaintext_structure: HashMap<String, StructuredDataTerminal>,
    crypto_schema: HashMap<String, CryptoAction>,
    parsed_header: ParsedHeader,
}

impl DecryptStructureOutput {
    /// Every field, decrypted, without the header and footer.
    #[must_use]
    pub const fn plaintext_structure(&self) -> &HashMap<String, StructuredDataTerminal> {
        &self.plaintext_structure
    }

    /// Take the plaintext structure out of the output.
    #[must_use]
    pub fn into_plaintext_structure(self) -> HashMap<String, StructuredDataTerminal> {
        self.plaintext_structure
    }

    /// The action the header gives each signed field.
    #[must_use]
    pub const fn crypto_schema(&self) -> &HashMap<String, CryptoAction> {
        &self.crypto_schema
    }

    /// What the header says.
    #[must_use]
    pub const fn parsed_header(&self) -> &ParsedHeader {
        &self.parsed_header
    }
}

/// Builds and sends an [`encrypt_path_structure`](StructuredEncryption::encrypt_path_structure) call.
#[derive(Clone, Debug, Default)]
pub struct EncryptPathStructureFluentBuilder {
    table_name: Option<String>,

    //= spec/structured-encryption/structures.md#crypto-list
    //= type=implication
    //# A crypto list MUST be a sequence of [crypto item](#crypto-item)
    plaintext_structure: Option<Vec<CryptoItem>>,
    cmm: Option<SharedCmm>,
    algorithm_suite_id: Option<AlgorithmSuiteId>,
    encryption_context: Option<EncryptionContext>,
}

impl EncryptPathStructureFluentBuilder {
    /// The logical table name, bound into every signature. Required.
    #[must_use]
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = Some(name.into());
        self
    }

    /// Set or clear the logical table name.
    #[must_use]
    pub fn set_table_name(mut self, name: Option<String>) -> Self {
        self.table_name = name;
        self
    }

    /// Add one plaintext terminal. Call again to add more. Required.
    #[must_use]
    pub fn plaintext_structure(mut self, item: CryptoItem) -> Self {
        self.plaintext_structure
            .get_or_insert_with(Vec::new)
            .push(item);
        self
    }

    /// Set or clear the whole plaintext structure.
    #[must_use]
    pub fn set_plaintext_structure(mut self, structure: Option<Vec<CryptoItem>>) -> Self {
        self.plaintext_structure = structure;
        self
    }

    /// The CMM that provides the encryption materials. Required.
    #[must_use]
    pub fn cmm(mut self, cmm: SharedCmm) -> Self {
        self.cmm = Some(cmm);
        self
    }

    /// Set or clear the CMM.
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// The algorithm suite. The default signs with ECDSA P-384 and HMAC-SHA-384.
    #[must_use]
    pub const fn algorithm_suite_id(mut self, id: AlgorithmSuiteId) -> Self {
        self.algorithm_suite_id = Some(id);
        self
    }

    /// Set or clear the algorithm suite.
    #[must_use]
    pub const fn set_algorithm_suite_id(mut self, id: Option<AlgorithmSuiteId>) -> Self {
        self.algorithm_suite_id = id;
        self
    }

    /// Add one encryption context entry. Call again to add more.
    #[must_use]
    pub fn encryption_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        add_context(&mut self.encryption_context, key.into(), value.into());
        self
    }

    /// Set or clear the whole encryption context.
    #[must_use]
    pub fn set_encryption_context(mut self, ec: Option<EncryptionContext>) -> Self {
        self.encryption_context = ec;
        self
    }

    /// Encrypt and sign the structure.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a required input is unset, no terminal is signed,
    ///   a path repeats, or a terminal is at the header or footer path.
    /// - Any error of the CMM, or of serializing or encrypting the structure.
    pub async fn send(self) -> Result<EncryptPathStructureOutput, Error> {
        //= spec/structured-encryption/encrypt-path-structure.md#input
        //= reason=each of the three inputs is unwrapped by required(), which rejects it unset
        //# The following inputs to this behavior are REQUIRED:
        let table = required(self.table_name, "table_name")?;
        let data = required(self.plaintext_structure, "plaintext_structure")?
            .into_iter()
            .map(CryptoField::from)
            .collect();
        let cmm = required(self.cmm, "cmm")?;

        //= spec/structured-encryption/encrypt-path-structure.md#input
        //= reason=the algorithm suite and encryption context are passed on as Options
        //# The following inputs to this behavior MUST be OPTIONAL:
        let (out, parsed_header) = super::encrypt_path_structure(
            &table,
            data,
            cmm,
            self.algorithm_suite_id,
            self.encryption_context,
        )
        .await?;

        //= spec/structured-encryption/encrypt-path-structure.md#output
        //# This operation MUST output the following:
        Ok(EncryptPathStructureOutput {
            encrypted_structure: out.into_iter().map(CryptoItem::from).collect(),
            parsed_header,
        })
    }
}

/// The result of [`encrypt_path_structure`](StructuredEncryption::encrypt_path_structure).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EncryptPathStructureOutput {
    encrypted_structure: Vec<CryptoItem>,
    parsed_header: ParsedHeader,
}

impl EncryptPathStructureOutput {
    /// Every terminal, encrypted where its action says, then the header and the footer.
    #[must_use]
    pub fn encrypted_structure(&self) -> &[CryptoItem] {
        &self.encrypted_structure
    }

    /// Take the encrypted structure out of the output.
    #[must_use]
    pub fn into_encrypted_structure(self) -> Vec<CryptoItem> {
        self.encrypted_structure
    }

    /// What the new header says.
    #[must_use]
    pub const fn parsed_header(&self) -> &ParsedHeader {
        &self.parsed_header
    }
}

/// Builds and sends a [`decrypt_path_structure`](StructuredEncryption::decrypt_path_structure) call.
#[derive(Clone, Debug, Default)]
pub struct DecryptPathStructureFluentBuilder {
    table_name: Option<String>,

    //= spec/structured-encryption/structures.md#auth-list
    //= type=implication
    //# An auth list MUST be a sequence of [auth item](#auth-item)
    encrypted_structure: Option<Vec<AuthItem>>,
    cmm: Option<SharedCmm>,
    encryption_context: Option<EncryptionContext>,
}

impl DecryptPathStructureFluentBuilder {
    /// The logical table name the structure was encrypted for. Required.
    #[must_use]
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = Some(name.into());
        self
    }

    /// Set or clear the logical table name.
    #[must_use]
    pub fn set_table_name(mut self, name: Option<String>) -> Self {
        self.table_name = name;
        self
    }

    /// Add one encrypted terminal, the header and footer included. Call again to add more. Required.
    #[must_use]
    pub fn encrypted_structure(mut self, item: AuthItem) -> Self {
        self.encrypted_structure
            .get_or_insert_with(Vec::new)
            .push(item);
        self
    }

    /// Set or clear the whole encrypted structure.
    #[must_use]
    pub fn set_encrypted_structure(mut self, structure: Option<Vec<AuthItem>>) -> Self {
        self.encrypted_structure = structure;
        self
    }

    /// The CMM that provides the decryption materials. Required.
    #[must_use]
    pub fn cmm(mut self, cmm: SharedCmm) -> Self {
        self.cmm = Some(cmm);
        self
    }

    /// Set or clear the CMM.
    #[must_use]
    pub fn set_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.cmm = cmm;
        self
    }

    /// Add one encryption context entry the structure must have been encrypted with.
    /// Call again to add more.
    #[must_use]
    pub fn encryption_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        add_context(&mut self.encryption_context, key.into(), value.into());
        self
    }

    /// Set or clear the whole encryption context.
    #[must_use]
    pub fn set_encryption_context(mut self, ec: Option<EncryptionContext>) -> Self {
        self.encryption_context = ec;
        self
    }

    /// Verify and decrypt the structure.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a required input is unset, no terminal is signed,
    ///   or a path repeats.
    /// - Any error of the CMM, or of parsing, verifying, or decrypting the structure.
    pub async fn send(self) -> Result<DecryptPathStructureOutput, Error> {
        //= spec/structured-encryption/decrypt-path-structure.md#input
        //= reason=each of the three inputs is unwrapped by required(), which rejects it unset
        //# The following inputs to this behavior are REQUIRED:
        let table = required(self.table_name, "table_name")?;
        let data = required(self.encrypted_structure, "encrypted_structure")?
            .into_iter()
            .map(AuthField::from)
            .collect();
        let cmm = required(self.cmm, "cmm")?;

        //= spec/structured-encryption/decrypt-path-structure.md#input
        //= reason=the encryption context is passed on as an Option
        //# The following inputs to this behavior MUST be OPTIONAL:
        let (out, parsed_header) =
            super::decrypt_path_structure(&table, data, cmm, self.encryption_context).await?;

        //= spec/structured-encryption/decrypt-path-structure.md#output
        //# This operation MUST output the following:
        Ok(DecryptPathStructureOutput {
            plaintext_structure: out.into_iter().map(CryptoItem::from).collect(),
            parsed_header,
        })
    }
}

/// The result of [`decrypt_path_structure`](StructuredEncryption::decrypt_path_structure).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DecryptPathStructureOutput {
    plaintext_structure: Vec<CryptoItem>,
    parsed_header: ParsedHeader,
}

impl DecryptPathStructureOutput {
    /// Every terminal, decrypted, with the action the header gave it; no header or footer.
    #[must_use]
    pub fn plaintext_structure(&self) -> &[CryptoItem] {
        &self.plaintext_structure
    }

    /// Take the plaintext structure out of the output.
    #[must_use]
    pub fn into_plaintext_structure(self) -> Vec<CryptoItem> {
        self.plaintext_structure
    }

    /// What the header says.
    #[must_use]
    pub const fn parsed_header(&self) -> &ParsedHeader {
        &self.parsed_header
    }
}

/// Builds and sends a [`resolve_auth_actions`](StructuredEncryption::resolve_auth_actions) call.
#[derive(Clone, Debug, Default)]
pub struct ResolveAuthActionsFluentBuilder {
    table_name: Option<String>,
    auth_actions: Option<Vec<AuthItem>>,
    header_bytes: Option<Vec<u8>>,
}

impl ResolveAuthActionsFluentBuilder {
    /// The logical table name the structure was encrypted for. Required.
    #[must_use]
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = Some(name.into());
        self
    }

    /// Set or clear the logical table name.
    #[must_use]
    pub fn set_table_name(mut self, name: Option<String>) -> Self {
        self.table_name = name;
        self
    }

    /// Add one terminal, the header and footer included. Call again to add more. Required.
    #[must_use]
    pub fn auth_actions(mut self, item: AuthItem) -> Self {
        self.auth_actions.get_or_insert_with(Vec::new).push(item);
        self
    }

    /// Set or clear the whole list of terminals.
    #[must_use]
    pub fn set_auth_actions(mut self, items: Option<Vec<AuthItem>>) -> Self {
        self.auth_actions = items;
        self
    }

    /// The serialized header. Required.
    #[must_use]
    pub fn header_bytes(mut self, header: impl Into<Vec<u8>>) -> Self {
        self.header_bytes = Some(header.into());
        self
    }

    /// Set or clear the serialized header.
    #[must_use]
    pub fn set_header_bytes(mut self, header: Option<Vec<u8>>) -> Self {
        self.header_bytes = header;
        self
    }

    /// Find each terminal's action. Nothing is verified or decrypted.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): a required input is unset, a path repeats,
    ///   or the header or footer terminal is missing.
    /// - [`Serialization`](crate::Error::Serialization): the header does not parse,
    ///   or its legend does not match the signed terminals.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // `send` is async on every fluent builder
    pub async fn send(self) -> Result<ResolveAuthActionsOutput, Error> {
        //= spec/structured-encryption/resolve-auth-actions.md#input
        //= reason=each of the three inputs is unwrapped by required(), which rejects it unset
        //# The following inputs to this behavior are REQUIRED:
        let table = required(self.table_name, "table_name")?;
        let data = required(self.auth_actions, "auth_actions")?
            .into_iter()
            .map(AuthField::from)
            .collect();
        let header = required(self.header_bytes, "header_bytes")?;
        let out = super::resolve_auth_actions(&table, data, &header)?;

        //= spec/structured-encryption/resolve-auth-actions.md#output
        //# This operation MUST output the following:
        Ok(ResolveAuthActionsOutput {
            crypto_actions: out.into_iter().map(CryptoItem::from).collect(),
        })
    }
}

/// The result of [`resolve_auth_actions`](StructuredEncryption::resolve_auth_actions).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResolveAuthActionsOutput {
    crypto_actions: Vec<CryptoItem>,
}

impl ResolveAuthActionsOutput {
    /// Every terminal with its action; an unsigned terminal's is `DO_NOTHING`.
    #[must_use]
    pub fn crypto_actions(&self) -> &[CryptoItem] {
        &self.crypto_actions
    }

    /// Take the terminals out of the output.
    #[must_use]
    pub fn into_crypto_actions(self) -> Vec<CryptoItem> {
        self.crypto_actions
    }
}
