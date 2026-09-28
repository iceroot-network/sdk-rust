#!/usr/bin/env bash
# check-deps.sh: the dependency guard of the SDK workspace.
#
#   tools/check-deps.sh
#
# Fails when:
#   - a consensus or node crate of heartwood-core (heartwood-kernel, heartwood-state,
#     heartwood-transactions, heartwood-p2p-wire, heartwood-logger) is anywhere in the dependency
#     tree, on any target and any edge;
#   - heartwood-crypto is built with a feature outside the allow-list tools/check-deps.allow on a
#     normal or build edge (features that only tests enable do not count); `genesis`, `fixed-aux`
#     and `legacy-schnorr` are refused even if listed;
#   - iceroot-keystore is built with its test-only feature `testing` (the weak bounds and the
#     caller's salt and nonce) on a normal or build edge;
#   - tokio, reqwest or hyper is in the build for wasm32-unknown-unknown.
#
# The Tauri plugin (crates/tauri-plugin-iceroot) is a workspace of its own; the first three checks
# apply to its tree as well, with its default features (its feature `test-seams` is the test
# build's, which no application enables).
#
# Runs from any directory; needs cargo on PATH.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
allow_file="$root/tools/check-deps.allow"
fail=0

tree() {
    cargo tree --manifest-path "$root/Cargo.toml" --workspace --prefix none "$@"
}

plugin_tree() {
    cargo tree --manifest-path "$root/crates/tauri-plugin-iceroot/Cargo.toml" --prefix none "$@"
}

# Each tree is read into a variable first, so that a failing cargo fails the guard. The plugin's
# edges are checked with the workspace's.
all_edges=$(tree --target all -e all --format '{p}')
all_edges+=$'\n'$(plugin_tree --target all -e all --format '{p}')
normal_edges=$(tree --target all -e normal,build --format '{p}|{f}')
normal_edges+=$'\n'$(plugin_tree --target all -e normal,build --format '{p}|{f}')
wasm_edges=$(tree --target wasm32-unknown-unknown -e normal,build --format '{p}')

# 1. No consensus or node crate of heartwood-core, anywhere.
forbidden='^(heartwood-kernel|heartwood-state|heartwood-transactions|heartwood-p2p-wire|heartwood-logger) '
if hits=$(grep -E "$forbidden" <<<"$all_edges" | sort -u); then
    echo "FAIL a consensus or node crate of heartwood-core is a dependency:"
    sed 's/^/    /' <<<"$hits"
    fail=1
fi

# 2. heartwood-crypto features on normal and build edges.
allowed=()
if [ -f "$allow_file" ]; then
    while IFS= read -r line; do
        line=${line%%#*}
        line=${line//[[:space:]]/}
        [ -n "$line" ] && allowed+=("$line")
    done <"$allow_file"
fi
if ! grep -q -E '^heartwood-crypto ' <<<"$normal_edges"; then
    echo "FAIL heartwood-crypto is not in the dependency tree"
    fail=1
fi
features=$(grep -E '^heartwood-crypto ' <<<"$normal_edges" | cut -d'|' -f2 | tr ',' '\n' |
    sed '/^$/d' | sort -u || true)
for feature in $features; do
    case "$feature" in
        default) continue ;;
        genesis | fixed-aux | legacy-schnorr)
            echo "FAIL heartwood-crypto is built with the feature '$feature', which is never allowed"
            fail=1
            continue
            ;;
    esac
    ok=0
    for allowed_feature in "${allowed[@]+"${allowed[@]}"}"; do
        [ "$feature" = "$allowed_feature" ] && ok=1
    done
    if [ "$ok" = 0 ]; then
        echo "FAIL heartwood-crypto is built with the feature '$feature', which is not in tools/check-deps.allow"
        fail=1
    fi
done

# 3. The keystore's test-only feature on normal and build edges.
if grep -E '^iceroot-keystore ' <<<"$normal_edges" | cut -d'|' -f2 | tr ',' '\n' | grep -qx 'testing'; then
    echo "FAIL iceroot-keystore is built with the test-only feature 'testing' on a normal or build edge"
    fail=1
fi

# 4. No async runtime or HTTP stack in the WebAssembly build.
if hits=$(grep -E '^(tokio|reqwest|hyper) ' <<<"$wasm_edges" | sort -u); then
    echo "FAIL the wasm32 build contains:"
    sed 's/^/    /' <<<"$hits"
    fail=1
fi

if [ "$fail" = 1 ]; then
    echo "check-deps: FAILED"
    exit 1
fi
echo "check-deps: passed"
