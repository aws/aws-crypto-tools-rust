// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Each operation's output and fluent builder, laid out as in an AWS SDK for Rust crate.

mod fluent_builders;

pub mod encrypt {
    //! The encrypt operation, which encrypts a plaintext held in memory.

    pub use crate::shapes::EncryptOutput;

    pub mod builders {
        //! The fluent builder for [`Client::encrypt`](crate::Client::encrypt).

        pub use crate::operation::fluent_builders::EncryptFluentBuilder;
    }
}

pub mod decrypt {
    //! The decrypt operation, which decrypts an encrypted message held in memory.

    pub use crate::shapes::DecryptOutput;

    pub mod builders {
        //! The fluent builder for [`Client::decrypt`](crate::Client::decrypt).

        pub use crate::operation::fluent_builders::DecryptFluentBuilder;
    }
}

pub mod encrypt_stream {
    //! The streaming encrypt operation.

    pub use crate::shapes::EncryptStreamOutput;

    pub mod builders {
        //! The fluent builder for [`Client::encrypt_stream`](crate::Client::encrypt_stream).

        pub use crate::operation::fluent_builders::EncryptStreamFluentBuilder;
    }
}

pub mod decrypt_stream {
    //! The streaming decrypt operation.

    pub use crate::shapes::DecryptStreamOutput;

    pub mod builders {
        //! The fluent builder for [`Client::decrypt_stream`](crate::Client::decrypt_stream).

        pub use crate::operation::fluent_builders::DecryptStreamFluentBuilder;
    }
}
