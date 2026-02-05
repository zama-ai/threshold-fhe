#!/bin/bash

# This script is used to run the non-threshold KAT generation for NIST submission.
# In particular, it regenerates the KAT files, store them and check against the expected hash.


# Assumes the build.sh script was used
OUTPUT_DIR="./tfhe_kat"

EXPECTED_HASH_CLIENT_KEY="e632247063e3712eb6de0244fdf08bede700dc7052d018fbc9420e60cfceb36b"
EXPECTED_HASH_SERVER_KEY="5c4c8d372972a13297dc691f90ac2cb9784f44b20d5b090f29c8155b64dff99d"
EXPECTED_HASH_CTXT_43="55d217ab5f970299619a3a08c7388eb74887c0f7830aa0b60d5ee50a467b4498"
EXPECTED_HASH_CTXT_4445="85fb15a41a29abea8e732afd43c640b21b7009f96e0c11460c83e07e302b2c8f"

# Tested on M2 Pro
EXPECTED_HASH_CTXT_ADD_ARM="600bef55a6ba73abdd7d57c325659bc906aabbd525eeeaafc53d0e369245a36c"
EXPECTED_HASH_CTXT_MUL_ARM="c196cb43e9b8eadc052f365767e4b34e1e4a7e033de0c94e53ff96fe4bc893eb"

# Tested on Intel(R) Xeon(R) Platinum 8488C
EXPECTED_HASH_CTXT_ADD_X86="3ea6a23186f35763d651ce5c425094f35e50b086f38e4a1e20f75e8bdf169757"
EXPECTED_HASH_CTXT_MUL_X86="93ed566f85e6efbc6a69167f63fe6872e63e1179006b395c3a223e9fd59f1a15"


# Check hash fn
check_hash() {
    local file_path=$1
    local expected_hash=$2

    local computed_hash
    computed_hash=$(sha256sum "$file_path" | cut -d ' ' -f 1)

    if [ "$computed_hash" != "$expected_hash" ]; then
        echo "❌ Hash mismatch for $file_path. Expected: $expected_hash, Got: $computed_hash"
    else
        echo "✅ Hash match for $file_path: $computed_hash"
    fi
}

# Run the latency benchmarks
cargo run --bin non-threshold-kat --release -- --path-to-kat-folder $OUTPUT_DIR --generate-kat

check_hash "$OUTPUT_DIR/client_key.bin" "$EXPECTED_HASH_CLIENT_KEY"
check_hash "$OUTPUT_DIR/server_key.bin" "$EXPECTED_HASH_SERVER_KEY"
check_hash "$OUTPUT_DIR/ciphertext_43.bin" "$EXPECTED_HASH_CTXT_43"
check_hash "$OUTPUT_DIR/ciphertext_4445.bin" "$EXPECTED_HASH_CTXT_4445"



ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    echo "Running on arm64, checking against result for Apple M2 Pro"
    echo "If running on a different CPU, the hashes may differ."
    check_hash "$OUTPUT_DIR/ciphertext_add.bin" "$EXPECTED_HASH_CTXT_ADD_MCHIP"
    check_hash "$OUTPUT_DIR/ciphertext_mult.bin" "$EXPECTED_HASH_CTXT_MUL_MCHIP"
elif [ "$ARCH" = "x86_64" ]; then
    echo "Running on x86, checking against result for Intel(R) Xeon(R) Platinum 8488C."
    echo "If running on a different CPU, the hashes may differ."
    check_hash "$OUTPUT_DIR/ciphertext_add.bin" "$EXPECTED_HASH_CTXT_ADD_X86"
    check_hash "$OUTPUT_DIR/ciphertext_mult.bin" "$EXPECTED_HASH_CTXT_MUL_X86"
else
    echo "Unknown architecture: $ARCH. Skipping add/mul KAT checks."
fi


