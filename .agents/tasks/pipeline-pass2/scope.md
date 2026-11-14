# pipeline-pass2 scope (docs only)
- HEAD: 851977d8f6f7cfb2b362d9ab2ef63fb1e0770f3a (matches expected 851977d)
- Branch: MPL-Verus
- git status --short: clean (empty)
- git diff --stat 620771c 5f2dc72: esdk/ only (8 files, all under esdk/shims/aws-esdk-cpp/: CMakeLists.txt, Makefile, performance-tests/Makefile, src/lib.rs, test-server/{Cargo.lock,Cargo.toml,build.rs,src/lib.rs}; 165+/37-)
- git show --stat 41f1d51: esdk/shims/aws-esdk-cpp/src/lib.rs (retry config, +7/-1)
- git show --stat 5f2dc72 (origin/main, #189): 7 files, same esdk/shims/aws-esdk-cpp paths
## Spec
- Remote master: 94c2bfe1c15e6d8746219b6b2606dc2266a7cf45
- Last run pin: 877edcc -> MOVED
- Diff 877edcc..94c2bfe: only client-apis/decrypt.md (+11/-6); framework/ (MPL docs) unchanged
- Local spec/framework commit e8334535: not resolvable in the esdk repo; not compared
