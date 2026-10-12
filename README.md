## AWS Crypto Tools Rust

📣 Note: This repository contains all projects supported in Rust
by the @aws/aws-crypto-tools team.

This repository uses semantic versioning and uses [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) to determine project versions.

### Versioning policy for errors

The error types are part of the public API: their variants, their accessors, and `is_retryable()`.
Error handling that decides from those keeps working across minor and patch releases.
A minor or patch release can change:

- **Message text.** Any message, and anything an error prints.
  Decide from the variant and its accessors, never from the message.
- **Failures without a specific variant.** An ESDK operation returns only `aws_esdk::Error`,
  and an MPL operation only `aws_crypto_mpl::Error`.
  A failure that reaches you without a specific variant is a bug:
  a panic, an `Internal` error, or a failure you can recognize only by a type in its source chain.
  A minor or patch release can turn it into a specific variant.
  In C++, the same applies to an exception that is not an `AwsEncryptionSdkException`, and to `InternalException`.
- **The shape of the source chain.** Levels can be added or removed.
  Reach a source with `find_source`.
- **Which variant a collection of failures gets.** The priority between variants, and whose retry kind is kept.
  To act on each failure, use `failures()`.
- **New variants and enum values.** Every `match` needs a catch-all arm, and every C++ `switch` a `default` case.

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

## Security

If you discover a potential security issue in this project
we ask that you notify AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please **do not** create a public GitHub issue.

## License

This project is licensed under the Apache-2.0 License.
