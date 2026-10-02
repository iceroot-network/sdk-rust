# Devnet response fixtures

Responses of the reference implementation's REST API, recorded on 2026-09-27 (UTC) from a local single-node devnet: network byte 90, 53 validator seats, 8-second blocks, ROOT with 8 decimals. Before recording, the devnet ran every transaction type it keeps (transfers, votes and vote withdrawals, burns, second keys, validator registrations, temporary and permanent resignations, second-signed transactions) together with refused submissions. The chain was stopped within five rounds.

Each response body is stored byte for byte as the node sent it. `index.json` lists, for every fixture, the request (method and path relative to the `/api` base path), the HTTP status, the `X-Block-Height` and `Retry-After` headers when present, and the file. For submissions, `requestFile` holds the posted body.

| Group | Fixtures |
|---|---|
| Node | `node-status`, `node-configuration`, `node-configuration-crypto`, `node-fees`, `node-fees-30-days`, `blockchain` |
| Accounts | `wallet-*` (genesis, voter, second key, a never-seen address, two refused ids), `wallet-transactions*`, `wallet-votes` |
| Transactions | one per kind (`transaction-*`), listings per kind (`transactions-*`), the pool (`transaction-unconfirmed-*`, `transactions-unconfirmed`), a missing id |
| Submissions | `submit-accepted`, `submit-mixed` (accepted, low fee, wrong nonce, insufficient balance, bad signature, repeated), `submit-empty` (HTTP 422) |
| Blocks | `blocks-last`, `blocks-first`, `blocks-page`, `block-by-height`, `block-by-id`, `block-transactions`, `block-not-found`, `blocks-missed` |
| Validators | `delegates-page*`, `delegate-by-name`, `delegate-by-address`, `delegate-resigned`, `delegate-revoked`, `delegate-unranked`, `delegate-not-found`, `delegate-voters`, `delegate-blocks`, `delegate-missed-blocks` |
| Rounds | `round-1-delegates`, `round-2-delegates` |
| Rate limit | `rate-limited` (HTTP 429 after the per-minute allowance was spent) |

Every key, address and passphrase behind these responses comes from a public devnet seed. They hold no value and must never be used for anything else.
