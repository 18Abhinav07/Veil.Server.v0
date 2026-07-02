# Veil Server

Stellar testnet contracts, circuit artifacts, prover API, and relayer for the Veil private USDC wallet.

## Overview

This repository contains the on-chain and proof-generation layer used by Veil. It packages the Soroban contracts, Groth16 verifier integration, Circom circuit artifacts, deployment metadata, HTTP prover service, and HTTP relayer service required by the client application.

The server supports two active privacy pools:

| Pool | Purpose |
| --- | --- |
| Wallet pool | Deposits, private sends, note-to-note transfers, batch payouts, and public withdrawals. |
| Market pool | Market note deposits, private YES/NO positions, payout transfers, claims, and public withdrawals. |

The current deployment target is Stellar testnet.

## Current Testnet Deployment

The canonical source of contract truth is `deployments/testnet/deployments.json`.

| Component | Value |
| --- | --- |
| Network | `testnet` |
| ASP membership | `CCJAUAGWKBWEWS7CYCRLOHCPY6OTHRV6KXAV4ISCZR5JCYSODSIDLS4J` |
| ASP membership deployment ledger | `3390579` |
| ASP non-membership | `CCVNPJO5RUE6GBA4Q2PVKOGNWTULAQR4HSR5KX5ARJ363F6RHGLZ2FB6` |
| Groth16 verifier | `CA7JDHSEPAO2DIWW4ZW6GAVWUPYSO6ELANBMUMEFZ7TD35WIZ3J7A6TS` |
| Public key registry | `CDI5633NLCDD3ITPSXTWWLBY3GY5ATI3SCFEJ42UD6E3Z4CKTA3XYQQ7` |
| Wallet pool | `CDEB3AIFRAGHGPLM24EDHHETSH4Y4L4NAYGSHHW7MQWXUQ65G7LEDBFY` |
| Wallet pool deployment ledger | `3390591` |
| Market pool | `CBQ2TULUH6Z2V2JGUSOD2U2G3VUIBJ55XRP3FICJKOETXFXLRBHSH4UW` |
| Market pool deployment ledger | `3390595` |
| USDC token contract | `CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA` |
| USDC issuer | `GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5` |

Both pools currently use the depth-10 `policy_tx_2_2` circuit stack. Pool depth, proving key, verifier, contract deployment JSON, prover configuration, relayer configuration, and frontend environment variables must be updated together.

## Repository Map

```text
contracts/                         Soroban contracts
contracts/pool/                    Main privacy pool contract
contracts/asp-membership/          ASP membership Merkle tree
contracts/asp-non-membership/      ASP non-membership tree
contracts/circom-groth16-verifier/ On-chain Groth16 verifier wrapper
contracts/public-key-registry/     User public key registry
circuits/                          Circom circuit build crate
circuit-keys/                      Circuit key tooling
services/prover-api/               HTTP proof-generation API
services/relayer/                  HTTP transaction relayer
app/crates/core/                   Shared Rust libraries
deployments/testnet/               Testnet deployment metadata and circuit keys
deployments/scripts/deploy.sh      Contract deployment script
e2e-tests/                         Testnet integration tests
railpack.json                      Railway/Railpack service config
```

## Architecture

Veil uses a two-input, two-output privacy transaction circuit. A valid transaction proves:

- ownership of private input notes,
- Merkle membership for note commitments,
- ASP membership or non-membership state,
- correct nullifier derivation,
- correct output commitment derivation,
- balance conservation across inputs, outputs, and public amount,
- binding to the public pool root and external transaction data.

The prover API reconstructs pool state, prepares circuit inputs, runs Groth16 proof generation, and returns relay-ready transaction bodies. The relayer simulates those transaction bodies, signs them with the configured relayer key, submits them to Stellar, and returns the transaction result to the caller.

## Services

### `prover-api`

The prover service provides proof preparation endpoints used by the frontend and worker:

- deposit proof preparation,
- withdrawal proof preparation,
- private transfer proof preparation,
- output note key helpers,
- health checks.

Required runtime artifacts:

```text
runtime-artifacts/circuits/policy_tx_2_2.wasm
runtime-artifacts/circuits/policy_tx_2_2.r1cs
deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin
deployments/testnet/deployments.json
```

### `relayer`

The relayer exposes:

- `GET /health`
- `POST /relay`

It signs and submits prepared pool transactions using `RELAYER_SECRET`. The relayer secret must remain server-side.

## Environment

Use `.env.example` as the local template.

Core runtime:

```bash
NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
STELLAR_RPC_URL=https://soroban-testnet.stellar.org
PROVER_API_URL=http://localhost:3001
RELAYER_URL=http://127.0.0.1:3000
```

Prover API:

```bash
PROVER_API_LISTEN_ADDR=0.0.0.0:3001
PROVER_API_STELLAR_RPC_URL=https://soroban-testnet.stellar.org
PROVER_API_DEPLOYMENTS_PATH=deployments/testnet/deployments.json
PROVER_API_WASM_PATH=runtime-artifacts/circuits/policy_tx_2_2.wasm
PROVER_API_R1CS_PATH=runtime-artifacts/circuits/policy_tx_2_2.r1cs
PROVER_API_PK_PATH=deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin
```

Relayer:

```bash
RELAYER_LISTEN_ADDR=0.0.0.0:3000
RELAYER_STELLAR_RPC_URL=https://soroban-testnet.stellar.org
RELAYER_NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
RELAYER_CONTRACT_CONFIG_PATH=deployments/testnet/deployments.json
RELAYER_SECRET=...
```

Pool variables shared with the client:

```bash
POOL_ID=CDEB3AIFRAGHGPLM24EDHHETSH4Y4L4NAYGSHHW7MQWXUQ65G7LEDBFY
NEXT_PUBLIC_POOL_ID=CDEB3AIFRAGHGPLM24EDHHETSH4Y4L4NAYGSHHW7MQWXUQ65G7LEDBFY
POOL_DEPLOYMENT_LEDGER=3390591
NEXT_PUBLIC_POOL_DEPLOYMENT_LEDGER=3390591
MARKET_POOL_ID=veil_market_pool_v1
MARKET_POOL_CONTRACT_ID=CBQ2TULUH6Z2V2JGUSOD2U2G3VUIBJ55XRP3FICJKOETXFXLRBHSH4UW
NEXT_PUBLIC_MARKET_POOL_CONTRACT_ID=CBQ2TULUH6Z2V2JGUSOD2U2G3VUIBJ55XRP3FICJKOETXFXLRBHSH4UW
MARKET_POOL_DEPLOYMENT_LEDGER=3390595
MARKET_POOL_TREE_DEPTH=10
```

Do not commit real secrets.

## Local Development

Build the service binaries:

```bash
cargo build -p prover-api -p relayer --release
```

Run contract and service tests:

```bash
cargo test -p pool
cargo test -p prover-api -p relayer
```

Start both backend services:

```bash
bash scripts/railway-start.sh
```

Default local ports:

| Service | URL |
| --- | --- |
| Prover API | `http://127.0.0.1:3001` |
| Relayer | `http://127.0.0.1:3000` |

Health checks:

```bash
curl http://127.0.0.1:3001/health
curl http://127.0.0.1:3000/health
```

## Deployment

Railway uses `railpack.json`.

Build command:

```bash
cargo build -p prover-api -p relayer --release
```

Runtime artifacts are copied into:

```text
runtime-artifacts/bin/prover-api
runtime-artifacts/bin/relayer
runtime-artifacts/circuits/policy_tx_2_2.wasm
runtime-artifacts/circuits/policy_tx_2_2.r1cs
```

Start command:

```bash
bash scripts/railway-start.sh
```

Before pushing backend changes:

1. Confirm `deployments/testnet/deployments.json` contains the intended contracts.
2. Run `cargo test -p pool`.
3. Run `cargo test -p prover-api -p relayer`.
4. Run `cargo build -p prover-api -p relayer --release`.
5. Confirm Railway variables match the deployment JSON.

## Contract Deployment

Use `deployments/scripts/deploy.sh` for fresh testnet deployments.

The current pool contract does not require a maximum deposit constructor argument.

Typical deployment shape:

```bash
./deployments/scripts/deploy.sh testnet \
  --deployer <stellar-cli-identity> \
  --asp-levels 10 \
  --pool-levels 10 \
  --vk-file deployments/testnet/circuit_keys/policy_tx_2_2_vk.json \
  --pool classic:USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5:CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA
```

After deployment:

1. Update `deployments/testnet/deployments.json`.
2. Update backend service variables.
3. Update frontend pool variables.
4. Rerun backend tests.
5. Rerun frontend deployment checks.
6. Redeploy backend before frontend.

## Security Notes

- This is testnet infrastructure and should not be treated as audited custody software.
- `RELAYER_SECRET`, ASP admin secrets, and market escrow private keys must remain server-side.
- Circuit proving keys and verifier contracts must stay in sync.
- If a circuit or proving key is regenerated, redeploy the verifier and pool contracts before using the new artifacts.
- Pool privacy does not hide public entry and exit transactions. Deposits and withdrawals remain visible on Stellar.

## Related Repositories

- Client app, wallet UI, market UI, worker, and app API routes: `Veil.Client.v0`
- Server contracts, prover API, relayer, and deployment metadata: `Veil.Server.v0`
