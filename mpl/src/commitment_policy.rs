// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commitment policy — deferred until CMMs, algorithm suites, and encryption/decryption
//! materials are implemented.

//= spec/framework/commitment-policy.md#supported-format-commitment-policy-enum
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# The Material Providers Library MUST provide
//# a distinct commitment policy ENUM for each format.

//= spec/framework/commitment-policy.md#supported-commitment-policy-enum
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# The Material Providers Library also MUST provide
//# a union ENUM for all distinct commitment policy ENUMs
//# called the Commitment Policy ENUM.

//= spec/framework/commitment-policy.md#supported-commitment-policy-enum
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# This means that different formats MAY have duplicate Format Commitment Policy ENUM.

//= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF` MUST be the default algorithm suite

//= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of False

//= spec/framework/commitment-policy.md#esdk-forbid-encrypt-allow-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites

//= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - `05 78` MUST be the default algorithm suite

//= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= spec/framework/commitment-policy.md#esdk-require-encrypt-allow-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST support all algorithm suites

//= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - `05 78` MUST be the default algorithm suite

//= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= spec/framework/commitment-policy.md#esdk-require-encrypt-require-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - `67 01` MUST be the default algorithm suite

//= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - [Get Encryption Materials](./cmm-interface.md#get-encryption-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True

//= spec/framework/commitment-policy.md#dbe-require-encrypt-require-decrypt
//= type=exception
//= reason=Commitment policy is deferred until CMMs, algorithm suites, and encryption/decryption materials are implemented; the enums and behavior will be added back then.
//# - [Decrypt Materials](./cmm-interface.md#decrypt-materials) MUST only support algorithm suites that have a [Key Commitment](./algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings) value of True
