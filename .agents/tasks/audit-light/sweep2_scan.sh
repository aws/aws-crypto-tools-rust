#!/bin/zsh
# Sweep 2 code-surface scan over non-test code.
# Test regions excluded: mpl/src/error.rs >=460, mpl/src/error/generated.rs >=3423,
# prim/src/error/generated.rs >=988; esdk shim tests.rs (whole file) not scanned.
cd "${0:A:h}/../../.."
files=($(find mpl/src prim/src -name '*.rs' | sort) esdk/shims/aws-esdk-cpp/src/lib.rs)
cutoff() { case $1 in
  mpl/src/error.rs) echo 460;; mpl/src/error/generated.rs) echo 3423;;
  prim/src/error/generated.rs) echo 988;; *) echo 999999;; esac; }
scan() { # $1 label, $2 ERE
  for f in $files; do
    c=$(cutoff $f)
    grep -nE -- "$2" "$f" | grep -vE '^[0-9]+:[[:space:]]*//' | while IFS=: read -r n rest; do
      (( n < c )) && printf '%s\t%s:%s\t%s\n' "$1" "$f" "$n" "${rest##[[:space:]]#}"
    done
  done
}
case $1 in
 panic) scan PANIC '\.unwrap\(\)|\.expect\(|panic!|unreachable!|unimplemented!|todo!|[^_]assert(_eq|_ne)?!' ;;
 index) scan INDEX '[A-Za-z0-9_)]\[[^]"]*\]' ;;
 arith) scan ARITH '[]A-Za-z0-9_)] (\+|-|\*|/|%) [A-Za-z0-9_(&]|\+=|-=|\*=|/=' ;;
 copy) scan COPY 'copy_from_slice|split_at\(|from_be_bytes|try_into\(\)|<\[u8; ?[0-9A-Z_]+\]>::try_from|as u(8|16|32|64|size)|as usize' ;;
 ext) scan EXT '\.(decrypt|encrypt|generate_data_key_without_plaintext|re_encrypt|get_item|query|transact_write_items|put_item|create_table|describe_table)\(\)|aws_lc_rs::|LessSafeKey|UnboundKey|SystemRandom|EcdsaKeyPair' ;;
 secret) scan SECRET 'PlaintextDataKey|wrapping_key|private_key|plaintext\(|\.plaintext|Zeroiz|zeroize\(|impl (std::fmt::|fmt::)?Debug for|println!|eprintln!|log::|tracing::' ;;
 err) scan ERR 'format!\(' ;;
 loop) scan LOOP '(^|[^a-z_])(for [a-z_(, )]+ in|while|loop)( |\{)|with_capacity|vec!\[|reserve\(|repeat\(' ;;
esac
