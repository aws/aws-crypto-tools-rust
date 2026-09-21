//! rpcv2Cbor Language_Server delegating to the aws-esdk-cpp C++ shim.

pub mod backend;
pub mod seam;
pub mod wire;

// The wire model and error shapes are identical to the Rust Language_Server's;
// reuse them so both servers speak the same commons contract.
pub use aws_esdk_test_server::{error, model};
