# Conformance config format

`config.toml` next to the scripts. The checked crates are not listed: every
crate whose `Cargo.toml` has a library and no `publish = false` is checked, and
each model service with `@localService` goes to the crate that defines the most
of its shapes. Every `rename`, `out_of_scope`, `mirror` and `deviation` entry needs a `reason`.

```toml
[smithy]
version = "1.74.1"                 # Smithy CLI release
sha256 = "6b50..."                 # of smithy-cli-linux-x86_64.zip

[[model]]                          # one per model repo
repo = "https://github.com/aws/aws-cryptographic-material-providers-library"
ref = "<full commit>"
paths = ["model/traits.smithy", "AwsCryptographyPrimitives/Model"]

[checks]
docs = true                        # modeled @documentation must appear in the Rust docs

[lint]                             # settings for the model-free lint rules
const_ok = ["AlgorithmSuite"]      # structs that are fixed tables; their getters may stay const
const_ok_reason = "..."            # why, shown in the report

[[rename]]                         # the Rust name for a shape, member, or operation
shape = "ns#Shape"                 # or "ns#Shape$member", or "ns#Operation"
rust = "RustName"                  # an operation may map to "Type::method"
reason = "..."
status = "proposed"                # accepted (default) | proposed | deferred | rejected (fix the code)

[[out_of_scope]]                   # cut a shape (and what only it reaches) from the closure
shape = "ns#Operation"
reason = "not ported yet"
status = "proposed"

[[mirror]]                         # a Rust-only operation checked like a modeled one
like = "ns#Encrypt"
rust = "EncryptStream"
drop_members = ["plaintext"]
reason = "..."

[[deviation]]                      # accept findings by id (fnmatch glob)
id = "member_type:materialProviders#GetEncryptionMaterialsInput$maxPlaintextLength"
reason = "..."
status = "accepted"
observed = "Option<u64>"           # optional pin: a different observed value reopens it
what_differs = "The model uses a signed i64."  # optional, for the review page
justification = "A size can't be negative."    # optional: why we do it this way
later = "breaking"                              # optional: would switching to the model after release break callers?
later_why = "Changing u64 to i64 changes the setter and getter."
example_strict = '''               # optional caller code for the review page, when
EncryptionMaterials::builder()     # the generated signature lines can't show the change
    .algorithm_suite(info)'''
example_ours = '''
EncryptionMaterials::builder()
    .algorithm_suite_id(id)'''
```

Finding ids are `<check>:<subject>`. Model findings use the short shape id (`keyStore#Foo$bar`); lint findings use the Rust path.
