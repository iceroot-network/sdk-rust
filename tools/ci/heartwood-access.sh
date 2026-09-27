#!/usr/bin/env bash
# heartwood-access.sh: gives git and cargo read access to heartwood-core on a CI machine.
#
#   HEARTWOOD_DEPLOY_KEY=<private key> tools/ci/heartwood-access.sh
#
# heartwood-core is not public yet, and Cargo.toml fetches heartwood-crypto from it over SSH, at
# ssh://git@github.com/iceroot-network/heartwood-core.git.
# This script installs a read-only deploy key of heartwood-core under an SSH host alias of its
# own, so that the key serves that repository only, pins GitHub's published SSH host key, rewrites
# heartwood-core's github.com addresses (both spellings) to the alias, and checks the access
# through the address Cargo uses. It changes the user's ~/.ssh and global git configuration: run
# it on CI machines. Cargo fetches in a repository of its own, so the rewrite has to be global
# there (or in git's environment); a repository's own git configuration would not reach it.
set -euo pipefail

if [ -z "${HEARTWOOD_DEPLOY_KEY:-}" ]; then
    echo "::error::HEARTWOOD_DEPLOY_KEY is empty. The repository secret with a read-only deploy key of heartwood-core is missing, or this run gets no secrets (a pull request from a fork)."
    exit 1
fi

install -d -m 700 "$HOME/.ssh"
key="$HOME/.ssh/heartwood-core"
(
    umask 077
    printf '%s\n' "$HEARTWOOD_DEPLOY_KEY" | tr -d '\r' >"$key"
)
# GitHub's published Ed25519 host key, SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.
echo 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' \
    >>"$HOME/.ssh/known_hosts"
cat >>"$HOME/.ssh/config" <<CONFIG
Host github-heartwood-core
    HostName github.com
    User git
    IdentityFile $key
    IdentitiesOnly yes
CONFIG
chmod 600 "$HOME/.ssh/config"

alias_url="ssh://git@github-heartwood-core/iceroot-network/heartwood-core"
git config --global --add url."$alias_url".insteadOf "ssh://git@github.com/iceroot-network/heartwood-core"
git config --global --add url."$alias_url".insteadOf "git@github.com:iceroot-network/heartwood-core"

git ls-remote --exit-code "ssh://git@github.com/iceroot-network/heartwood-core.git" HEAD >/dev/null
echo "heartwood-access: heartwood-core is readable"
