## AWS Crypto Tools Rust

📣 Note: This repository contains all projects supported in Rust
by the @aws/aws-crypto-tools team.

This repository uses semantic versioning and uses [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) to determine project versions.

### Versioning policy for errors

The error types are part of the public API: the variants, their accessors, and
`is_retryable()`. These can change in a minor or patch release:

- **Error messages.** Any message, and anything an error prints, can change.
  Never decide from the text.
- **Errors that are not the library's own.** An ESDK operation returns only
  `aws_esdk::Error`, and an MPL operation only `aws_crypto_mpl::Error`. Anything
  else, an `Internal` error, or a failure recognizable only by a type in its
  source chain is a bug, and a minor or patch release can turn it into a
  specific variant. In C++, the same applies to an exception that is not an
  `AwsEncryptionSdkException`, and to `InternalException`.
- **The shape of the source chain.** Levels can be added or removed; reach a
  source with `find_source`.
- **Which variant a collection of failures gets.** The priority order between
  variants, and whose retry kind is kept, can change. Use `failures()` to act on
  each failure.
- **New variants and enum values.** Every `match` needs a catch-all arm, and
  every C++ `switch` a `default` case.

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

## Security

If you discover a potential security issue in this project
we ask that you notify AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please **do not** create a public GitHub issue.

## License

This project is licensed under the Apache-2.0 License.
