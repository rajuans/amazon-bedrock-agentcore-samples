# Code walkthrough — Coinbase CDP sample

This document explains every file in the sample: what it does, the functions in
it, the AWS and Coinbase CDP APIs it calls, and what it reads from and writes to
`.env`. For the run order, see the [README](../README.md); for the threat model,
see [`SECURITY.md`](SECURITY.md).

## How the pieces fit

```
                         .env  (config in, resource IDs written back)
                           │
 setup/provision_stack.py ─┼─► IAM roles, CoinbaseCDP credential provider,
                           │   payment manager, payment connector      (AgentCore control plane)
 setup/provision_payments.py ─► CDP embedded wallet (instrument) + session (AgentCore data plane)
 WalletHub (browser)        ─► user funds the wallet and grants delegated signing
 setup/cdp_policy_payment_demo.py ─► CDP project policy checked through ProcessPayment (AgentCore + CDP)
 setup/cdp_policy_setup.py / cdp_policy_remove.py ─► account-scoped policy for CDP server accounts
 agent/secure_payment_agent.py ─► the agent buys paid content          (Strands + AgentCore plugin)
 agent/session_budget_demo.py  ─► session budget refuses a payment     (AgentCore data plane)
 agent/guardrails_demo.py      ─► offline app-level check
 policies/                     ─► Cedar, Dogwood, and CDP policy definitions + local tests
```

## `agent/`

`utils.py`, `secure_payment_agent.py`, `session_budget_demo.py`, and
`guardrails_demo.py` are the same as in the Privy sample — the agent code is
provider-agnostic. See the [Privy walkthrough](../../privy/docs/CODE_WALKTHROUGH.md#agent)
for a function-by-function description. In short:

| File | Does |
|---|---|
| `utils.py` | `.env` loading and validation, idempotent `create_*` (treats `ConflictException` and `ValidationException … already exists` as "exists"), status polling, writing IDs back to `.env` |
| `secure_payment_agent.py` | creates a budgeted session, wires `AgentCorePaymentsPlugin` into a Strands agent with `http_request`, and asks it to buy the paid endpoint |
| `session_budget_demo.py` | a session capped below the price; `generate_payment_header` is refused with `InsufficientBudget`, budget untouched |
| `guardrails_demo.py` | offline cap + allowlist decisions for three scenarios |

## `setup/`

### `provision_stack.py` — the shared AgentCore stack

Same structure as the Privy version (four least-privilege IAM roles, then the
credential provider, manager, and connector, polled to `READY`), with the Coinbase
specifics:

- `_provider_config()` →
  `CreatePaymentCredentialProvider(credentialProviderVendor="CoinbaseCDP",
  providerConfigurationInput={"coinbaseCdpConfiguration": {apiKeyId, apiKeySecret,
  walletSecret}})`.
- `CreatePaymentConnector(type="CoinbaseCDP",
  credentialProviderConfigurations=[{"coinbaseCDP": {"credentialProviderArn": …}}])`.
- If `PAYMENT_MANAGER_ARN` is preset, the existing manager is reused (for accounts
  at the manager quota); on re-runs, the provider and connector are found by name.

Writes the role ARNs, `CREDENTIAL_PROVIDER_ARN`, `PAYMENT_MANAGER_ARN`/`_ID`, and
`PAYMENT_CONNECTOR_ID`.

### `provision_payments.py` — the wallet and the session

`create_payment_instrument(EMBEDDED_CRYPTO_WALLET, network ETHEREUM, linked email)`
creates a CDP end-user (embedded) wallet; `create_payment_session` creates the
budget. Writes `INSTRUMENT_ID`, `WALLET_ADDRESS`, `SESSION_ID`, and prints the
WalletHub link (`paymentInstrumentDetails.embeddedCryptoWallet.redirectUrl`) where
the user funds the wallet and grants delegated signing.

### `cdp_policy_setup.py` — the CDP rule, and the server-account variant

`_build_rule(recipients=None)` builds the CDP Policy Engine rule:
`SignEndUserEvmTypedDataRule` (or `SignEvmTypedDataRule` for server accounts, via
`CDP_TYPED_DATA_OP`) with action `accept` and one `SignEvmTypedDataFieldCriterion`
over the EIP-3009 `TransferWithAuthorization` types:

- `EvmTypedAddressCondition(path="to", operator="in", addresses=…)` — recipient allowlist;
- `EvmTypedNumericalCondition(path="value", operator="<=", value=<cap in base units>)` — per-tx cap.

`main(wallet_address)` creates an **account-scoped** policy and attaches it with
`cdp.evm.update_account(...)`. That only works for CDP **server** accounts; the
AgentCore wallet is an end-user account, governed by a project-scoped policy (see
the payment demo).

### `cdp_policy_payment_demo.py` — check the policy through AgentCore

Uses **project-scoped** CDP policies, which govern every end-user signing request
in the CDP project. It refuses to run if a project policy already exists, so it
never overwrites yours. Each step creates a fresh session and calls
`generate_payment_header` against a real 402 (`_try_pay`):

| Step | Project policy | `ProcessPayment` must |
|---|---|---|
| 0 | none | succeed — proves delegation, funding, and session (otherwise stop with exit 2) |
| 1 | allow only a decoy `to` | fail **with a policy error** (`_is_policy_refusal`) |
| 2 | allow the merchant | succeed — proves the rule matches the signing request |

Each policy is deleted right after its step. Payment headers are never sent, so no
USDC moves. `POSITIVE_CONTROL=0` skips step 2.

### `cdp_policy_remove.py` — clean up the server-account variant

Clears the account's policy (`update_account(account_policy="")`) and deletes the
policy object.

## `policies/`

| File | What it is |
|---|---|
| `agentcore_policy.cedar` | point-in-time AgentCore Policy (cap + allowlist) |
| `dogwood/` | temporal policies (provenance, velocity, rolling cap) + local test suite — identical to the Privy sample |
| `cdp_recipient_allowlist_policy.json` | the CDP rule in JSON form, for reference |

## Data that moves where

| Secret / ID | Lives in | Used by |
|---|---|---|
| CDP API key secret, wallet secret | `.env` (local dev only) → AgentCore Identity after `provision_stack.py` | AgentCore, to sign; the CDP policy scripts |
| Wallet address, instrument ID, session ID | `.env` | demos and agent |
