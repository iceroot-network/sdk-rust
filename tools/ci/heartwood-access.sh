#!/usr/bin/env bash
# heartwood-access.sh: gives git and cargo read access to heartwood-core on a CI machine.
#
#   HEARTWOOD_TOKEN=<read-only token> tools/ci/heartwood-access.sh
#
# heartwood-core is not public yet, and Cargo.toml names heartwood-crypto's repository as
# ssh://git@github.com/iceroot-network/heartwood-core.git.
# This script masks the token in the job's log, rewrites heartwood-core's SSH addresses (both
# spellings) to HTTPS, and gives git the token as an authorization header for heartwood-core's
# HTTPS address only. It makes Cargo fetch with the git command line, which reads that
# configuration, and checks the access through the address Cargo uses.
# The settings are git configuration in the environment (GIT_CONFIG_COUNT and its pairs), which
# Cargo passes on to git, handed to the job's later steps through GITHUB_ENV. No git
# configuration file holds the token, and Cargo's git database, which the dependency cache
# saves, never sees it. Only the runner's GITHUB_ENV file does: never cache or upload it.
set +x
set -euo pipefail

if [ -z "${HEARTWOOD_TOKEN:-}" ]; then
    echo "::error::HEARTWOOD_TOKEN is empty. The repository secret with a read-only fine-grained token for heartwood-core is missing, or this run gets no secrets (a pull request from a fork)."
    exit 1
fi
printf '::add-mask::%s\n' "$HEARTWOOD_TOKEN"

: "${GITHUB_ENV:?Run this script in a GitHub Actions step}"
authorization=$(printf 'x-access-token:%s' "$HEARTWOOD_TOKEN" | base64 | tr -d '\r\n')
printf '::add-mask::%s\n' "$authorization"

https_url="https://github.com/iceroot-network/heartwood-core"
keys=(
    "url.$https_url.insteadOf"
    "url.$https_url.insteadOf"
    "http.$https_url.git.extraheader"
)
values=(
    "ssh://git@github.com/iceroot-network/heartwood-core"
    "git@github.com:iceroot-network/heartwood-core"
    "AUTHORIZATION: basic $authorization"
)
# Preserve any git configuration already passed through the environment.
count=${GIT_CONFIG_COUNT:-0}
for i in "${!keys[@]}"; do
    export "GIT_CONFIG_KEY_$count=${keys[$i]}" "GIT_CONFIG_VALUE_$count=${values[$i]}"
    printf '%s=%s\n' "GIT_CONFIG_KEY_$count" "${keys[$i]}" \
        "GIT_CONFIG_VALUE_$count" "${values[$i]}" >>"$GITHUB_ENV"
    count=$((count + 1))
done
export GIT_CONFIG_COUNT=$count CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_TERMINAL_PROMPT=0
printf '%s=%s\n' GIT_CONFIG_COUNT "$count" CARGO_NET_GIT_FETCH_WITH_CLI true \
    GIT_TERMINAL_PROMPT 0 >>"$GITHUB_ENV"

git ls-remote --exit-code "ssh://git@github.com/iceroot-network/heartwood-core.git" HEAD >/dev/null
echo "heartwood-access: heartwood-core is readable"
