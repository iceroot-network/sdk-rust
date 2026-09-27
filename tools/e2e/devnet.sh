#!/usr/bin/env bash
# devnet.sh: a short-lived local devnet for the SDK's end-to-end tests.
#
#   tools/e2e/devnet.sh run [--] <command> [args...]
#       generate a fresh devnet, start it, wait for its second block, run the command against it,
#       then stop the devnet and remove it; exits with the command's status
#   tools/e2e/devnet.sh stop
#       stop and remove the devnet of an interrupted run
#
# The devnet is one node of the reference implementation on this machine, run by the devnet
# tooling: a checkout whose Makefile has the targets gen, up, down, logs and reset for
# BACKEND=native, and which writes each network to networks/<name>. Point ICEROOT_DEVNET_TOOLS at
# it; the tooling's own settings (the reference build, Node and PostgreSQL) apply.
#
# Chains stay short. The devnet stops when the command ends, and at the latest when the chain
# reaches the last height of E2E_ROUNDS rounds (at most 5) or the time those rounds take; the
# command is then stopped and the run fails.
#
# Environment:
#   ICEROOT_DEVNET_TOOLS          the devnet tooling checkout                        [required]
#   E2E_NAME                      the network's name                                 [sdk-e2e]
#   E2E_API_PORT, E2E_P2P_PORT    the node's ports on 127.0.0.1                      [4973, 4972]
#   E2E_EPOCH_DELAY               seconds from generation to the chain's epoch       [60]
#   E2E_ROUNDS                    the most rounds the chain may run, 1 to 5          [5]
#   E2E_KEEP=1                    keep the network directory (keys, logs) and the artifacts
#
# The command gets:
#   ICEROOT_E2E_RELAY             the relay URL, API base path included
#   ICEROOT_E2E_WALLETS           the generated wallets file, with the genesis wallets' passphrases
#   ICEROOT_E2E_MAX_HEIGHT        the last height the chain may reach
#   ICEROOT_E2E_ARTIFACTS         a directory the tests share, for results one language writes and
#                                 another checks
#
# Every key of the devnet comes from the tooling's public default seed: nothing on it has value.

set -Eeuo pipefail

die() { echo "devnet: $*" >&2; exit 2; }
say() { echo "[$(date -u +%H:%M:%S)] devnet: $*" >&2; }

TOOLS=${ICEROOT_DEVNET_TOOLS:-}
NAME=${E2E_NAME:-sdk-e2e}
API_PORT=${E2E_API_PORT:-4973}
P2P_PORT=${E2E_P2P_PORT:-4972}
EPOCH_DELAY=${E2E_EPOCH_DELAY:-60}
ROUNDS=${E2E_ROUNDS:-5}
KEEP=${E2E_KEEP:-}

[[ "$NAME" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]] || die "E2E_NAME must be 1 to 32 of a-z, 0-9, _ and -"
[[ "$ROUNDS" =~ ^[1-5]$ ]] || die "E2E_ROUNDS is 1 to 5: test chains stay short"
[[ "$EPOCH_DELAY" =~ ^[0-9]+$ ]] || die "E2E_EPOCH_DELAY is a number of seconds"
[[ "$API_PORT" =~ ^[0-9]+$ && "$P2P_PORT" =~ ^[0-9]+$ ]] || die "the ports are numbers"

RELAY="http://127.0.0.1:$API_PORT/api"

tooling() {
    [ -n "$TOOLS" ] || die "set ICEROOT_DEVNET_TOOLS to the devnet tooling checkout"
    [ -f "$TOOLS/Makefile" ] || die "$TOOLS has no Makefile: not the devnet tooling"
    NETWORK_DIR="$TOOLS/networks/$NAME"
}

# The tooling's variables are set on make's command line, where they override the environment:
# npm, for one, exports NODE (the path of node), which the tooling would take for a node's name.
tool() {
    make -s -C "$TOOLS" BACKEND=native NAME="$NAME" NODE= NODES= ARGS= EPOCH= FORCE= YES= ACTION= ROLE= "$@"
}

# The height of the node's last block, or 0 when the node does not answer.
height() {
    local body
    body=$(curl -fsS --max-time 5 "$RELAY/node/status" 2>/dev/null) || { echo 0; return; }
    grep -o '"now":[0-9]*' <<<"$body" | head -n 1 | cut -d: -f2 || echo 0
}

# A number from the node's configuration (the milestone in force at its tip).
configured() {
    curl -fsS --max-time 5 "$RELAY/node/configuration" | grep -o "\"$1\":[0-9]*" | head -n 1 | cut -d: -f2
}

wait_height() {
    local target=$1 limit=$2 start=$SECONDS h
    while :; do
        h=$(height)
        [ "${h:-0}" -ge "$target" ] && return 0
        [ $((SECONDS - start)) -lt "$limit" ] || { say "no block $target after ${limit}s (at ${h:-0})"; return 1; }
        sleep 4
    done
}

teardown() {
    say "stopping the devnet at height $(height)"
    tool down >/dev/null 2>&1 || true
    if [ -n "$KEEP" ]; then
        say "kept $NETWORK_DIR${ARTIFACTS:+ and $ARTIFACTS}"
        return
    fi
    tool reset YES=1 >/dev/null 2>&1 || true
    rm -rf -- "$NETWORK_DIR"
    [ -z "${ARTIFACTS:-}" ] || rm -rf -- "$ARTIFACTS"
}

show_logs() {
    say "the node's last log lines:"
    tool logs ARGS="relay 25" >&2 2>/dev/null || true
    tool logs ARGS="forger 10" >&2 2>/dev/null || true
}

run() {
    [ "${1:-}" != "--" ] || shift
    [ $# -gt 0 ] || die "usage: devnet.sh run [--] <command> [args...]"
    tooling
    if curl -fsS --max-time 2 "$RELAY/node/status" >/dev/null 2>&1; then
        die "a node already answers at $RELAY: stop it, or choose other ports (E2E_API_PORT, E2E_P2P_PORT)"
    fi

    say "generating $NAME (epoch in ${EPOCH_DELAY}s, API port $API_PORT)"
    tool gen FORCE=1 EPOCH="+$EPOCH_DELAY" ARGS="--p2p-port $P2P_PORT --api-port $API_PORT" >/dev/null
    ARTIFACTS=$(mktemp -d "${TMPDIR:-/tmp}/iceroot-e2e.XXXXXX")
    trap 'teardown' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    say "starting the node"
    tool up >/dev/null
    wait_height 2 $((EPOCH_DELAY + 240)) || { show_logs; exit 1; }

    local seats block_time max_height deadline
    seats=$(configured activeDelegates)
    block_time=$(configured blockTime)
    [ -n "$seats" ] && [ -n "$block_time" ] || die "the node's configuration has no seats or block time"
    max_height=$((ROUNDS * seats))
    deadline=$((SECONDS + max_height * block_time + 120))
    say "height 2 reached; the chain may run to height $max_height ($ROUNDS rounds of $seats blocks)"

    export ICEROOT_E2E_RELAY="$RELAY"
    export ICEROOT_E2E_WALLETS="$NETWORK_DIR/wallets.json"
    export ICEROOT_E2E_MAX_HEIGHT="$max_height"
    export ICEROOT_E2E_ARTIFACTS="$ARTIFACTS"

    # The command runs in its own process group, so that the round limit stops all of it.
    setsid "$@" &
    local pid=$! status=0 h stopped=
    trap 'kill -TERM -- -"$pid" 2>/dev/null || true; exit 130' INT
    trap 'kill -TERM -- -"$pid" 2>/dev/null || true; exit 143' TERM
    while kill -0 "$pid" 2>/dev/null; do
        sleep 15
        h=$(height)
        if [ "${h:-0}" -ge "$max_height" ] || [ "$SECONDS" -ge "$deadline" ]; then
            say "the chain reached height ${h:-?} of $max_height, or its time ran out: stopping the command"
            kill -TERM -- -"$pid" 2>/dev/null || true
            sleep 5
            kill -KILL -- -"$pid" 2>/dev/null || true
            stopped=1
            break
        fi
    done
    wait "$pid" || status=$?
    if [ -n "$stopped" ]; then
        status=124
    fi
    say "the command ended with status $status at height $(height)"
    [ "$status" = 0 ] || show_logs
    return "$status"
}

stop() {
    tooling
    NETWORK_DIR="$TOOLS/networks/$NAME"
    teardown
}

case "${1:-}" in
    run) shift; run "$@" ;;
    stop) stop ;;
    *) die "usage: devnet.sh run [--] <command> [args...] | devnet.sh stop" ;;
esac
