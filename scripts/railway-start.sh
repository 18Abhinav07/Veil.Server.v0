#!/usr/bin/env bash
set -euo pipefail

export PROVER_API_DEPLOYMENTS_PATH="${PROVER_API_DEPLOYMENTS_PATH:-deployments/testnet/deployments.json}"
export PROVER_API_STELLAR_RPC_URL="${PROVER_API_STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
export PROVER_API_LISTEN_ADDR="${PROVER_API_LISTEN_ADDR:-0.0.0.0:3001}"

export RELAYER_CONTRACT_CONFIG_PATH="${RELAYER_CONTRACT_CONFIG_PATH:-deployments/testnet/deployments.json}"
export RELAYER_STELLAR_RPC_URL="${RELAYER_STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
export RELAYER_NETWORK_PASSPHRASE="${RELAYER_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
export RELAYER_LISTEN_ADDR="${RELAYER_LISTEN_ADDR:-0.0.0.0:3000}"

choose_artifact() {
  local current_value="$1"
  shift

  if [[ -n "$current_value" && -f "$current_value" ]]; then
    printf '%s' "$current_value"
    return
  elif [[ -n "$current_value" ]]; then
    echo "Ignoring missing artifact override: $current_value" >&2
  fi

  local candidate
  for candidate in "$@"; do
    if [[ -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  done

  printf '%s' "${@: -1}"
}

export PROVER_API_WASM_PATH="$(
  choose_artifact "${PROVER_API_WASM_PATH:-}" \
    "runtime-artifacts/circuits/policy_tx_2_2.wasm" \
    "target/circuits-artifacts/release/policy_tx_2_2.wasm" \
    "target/circuits-artifacts/debug/policy_tx_2_2.wasm"
)"
export PROVER_API_R1CS_PATH="$(
  choose_artifact "${PROVER_API_R1CS_PATH:-}" \
    "runtime-artifacts/circuits/policy_tx_2_2.r1cs" \
    "target/circuits-artifacts/release/policy_tx_2_2.r1cs" \
    "target/circuits-artifacts/debug/policy_tx_2_2.r1cs"
)"
export PROVER_API_PK_PATH="${PROVER_API_PK_PATH:-deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin}"

for required_file in \
  "$PROVER_API_DEPLOYMENTS_PATH" \
  "$PROVER_API_WASM_PATH" \
  "$PROVER_API_R1CS_PATH" \
  "$PROVER_API_PK_PATH" \
  "$RELAYER_CONTRACT_CONFIG_PATH"; do
  if [[ ! -f "$required_file" ]]; then
    echo "Missing required deployment artifact: $required_file" >&2
    exit 1
  fi
done

if [[ -z "${RELAYER_SECRET:-}" ]]; then
  echo "Missing required env var: RELAYER_SECRET" >&2
  exit 1
fi

echo "Starting prover-api on $PROVER_API_LISTEN_ADDR"
./target/release/prover-api &
prover_pid=$!

echo "Starting relayer on $RELAYER_LISTEN_ADDR"
./target/release/relayer &
relayer_pid=$!

terminate() {
  kill "$prover_pid" "$relayer_pid" 2>/dev/null || true
  wait "$prover_pid" "$relayer_pid" 2>/dev/null || true
}

trap terminate INT TERM

wait -n "$prover_pid" "$relayer_pid"
status=$?
terminate
exit "$status"
