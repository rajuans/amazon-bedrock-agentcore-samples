# Code walkthrough — Stripe/Privy sample

This document explains every file in the sample: what it does, the functions in
it, the AWS and Privy APIs it calls, and what it reads from and writes to `.env`.
For the run order, see the [README](../README.md); for the threat model, see
[`SECURITY.md`](SECURITY.md).

## How the pieces fit

```
                         .env  (config in, resource IDs written back)
                           │
 setup/provision_stack.py ─┼─► IAM roles, StripePrivy credential provider,
                           │   payment manager, payment connector      (AgentCore control plane)
 setup/provision_payments.py ─► Privy embedded wallet (instrument) + session (AgentCore data plane)
 setup/privy_policy_setup.py ─► condition set + policy                (Privy REST, privy_client.py)
 frontend-patch/            ─► user delegates; policy set on the agent signer (Privy SDK, browser)
 setup/privy_policy_probe.py ─► policy checked directly               (Privy wallet RPC)
 setup/privy_policy_payment_demo.py ─► policy checked through ProcessPayment (AgentCore + Privy)
 agent/secure_payment_agent.py ─► the agent buys paid content          (Strands + AgentCore plugin)
 agent/session_budget_demo.py  ─► session budget refuses a payment     (AgentCore data plane)
 agent/guardrails_demo.py      ─► offline app-level check
 policies/                     ─► Cedar, Dogwood, and Privy policy definitions + local tests
```

Every script loads `.env` from the sample root through `agent/utils.py`, so the
scripts can run in any order once their inputs exist.

## `agent/`

### `utils.py` — shared helpers

| Function | Purpose |
|---|---|
| `client_token()` | fresh UUID for idempotent `create_*` calls |
| `require_env(key)` | return a required `.env` value; fail clearly on unset or `<placeholder>` values |
| `load_env()` | load `.env` and return the config dict the agent and demos use (region, manager ARN, connector, instrument, wallet, user, network, budget, cap, allowlist) |
| `idempotent_create(create_fn, conflict_msg, **kw)` | call a control-plane `create_*`; return `None` if the resource already exists. Treats both `ConflictException` and `ValidationException … already exists` (what `CreatePaymentCredentialProvider` returns) as "exists" |
| `wait_for_status(get_fn, expected, …)` | poll a `Get*` call until `status` reaches `expected`; raise on `*_FAILED` or timeout |
| `print_summary(title, **fields)` | aligned key/value printout |
| `write_env_values(**pairs)` | upsert `KEY=value` lines into `.env` (how setup scripts hand IDs to later steps) |

### `secure_payment_agent.py` — the autonomous purchase

1. `load_env()`, then `sts:GetCallerIdentity` to show which identity runs.
2. `PaymentManager.create_payment_session(limits={"maxSpendAmount": …}, expiry_time_in_minutes=60)` —
   the server-side budget for this run.
3. `AgentCorePaymentsPlugin(AgentCorePaymentsPluginConfig(...))` with the manager
   ARN, user, instrument, session, region, and network preference
   (`eip155:84532` for Base Sepolia). The plugin intercepts any 402 the agent's
   HTTP tool receives, calls `ProcessPayment`, and retries with the payment header.
4. A Strands `Agent` with a Bedrock model, the `http_request` tool, the plugin,
   and a system prompt that forbids following "free trial" or alternative URLs
   in a 402 body.
5. Asks the agent to fetch `PAID_ENDPOINT`, then asks for the remaining budget
   (the plugin also exposes read-only budget tools).

The agent code contains no payment logic; swapping the connector between Coinbase
and Privy does not change this file.

### `session_budget_demo.py` — the session guardrail

Fetches a real 402 challenge, creates a session capped at `$0.0001` (below the
`$0.001` price), and calls `generate_payment_header`. The service refuses with
`InsufficientBudget`; the script then reads the session to show the budget was
not touched. No model is involved — the rejection is the raised exception.

### `guardrails_demo.py` — the app-level backstop (offline)

`evaluate_guardrails(recipient, amount_usd)` returns a `Decision` (allowed, reason,
enforcing layer) using `PER_TX_CAP_USD` and `RECIPIENT_ALLOWLIST`; `guarded_pay`
is the body you would wrap in a Strands `@tool`. `main()` runs three scenarios:
allowed merchant, a $500 payment, a non-allowlisted recipient.

## `setup/`

### `provision_stack.py` — the shared AgentCore stack

| Step | Calls |
|---|---|
| IAM roles (`setup_payment_roles`, `_ensure_role`, `_statement`) | `iam:GetRole` / `CreateRole` / `UpdateAssumeRolePolicy` / `PutRolePolicy` for four roles: **ControlPlane** (manage managers/connectors/providers, write secrets, PassRole), **Management** (instruments and sessions; `ProcessPayment` explicitly denied), **ProcessPayment** (the agent runtime), **ResourceRetrieval** (the manager's execution role, trusted by `bedrock-agentcore.amazonaws.com`) |
| Assume the control-plane role (`_assume`) | `sts:AssumeRole`, falling back to the caller if the role is still propagating |
| Credential provider (`_provider_config`) | `CreatePaymentCredentialProvider(credentialProviderVendor="StripePrivy", providerConfigurationInput={"stripePrivyConfiguration": {appId, appSecret, authorizationId, authorizationPrivateKey}})`; rejects a key that still has the `wallet-auth:` prefix; on re-run, `GetPaymentCredentialProvider(name=…)` |
| Payment manager | `CreatePaymentManager(authorizerType="AWS_IAM", roleArn=<ResourceRetrieval>)`, then poll `GetPaymentManager` until `READY`. If `PAYMENT_MANAGER_ARN` is preset, reuse that manager instead (for accounts at the manager quota) |
| Connector | `CreatePaymentConnector(type="StripePrivy", credentialProviderConfigurations=[{"stripePrivy": {"credentialProviderArn": …}}])`, then poll `GetPaymentConnector`; on re-run, find it by name |

Writes: the four role ARNs, `CREDENTIAL_PROVIDER_ARN`, `PAYMENT_MANAGER_ARN`/`_ID`,
`PAYMENT_CONNECTOR_ID`.

### `provision_payments.py` — the wallet and the session

`PaymentManager.create_payment_instrument(payment_instrument_type="EMBEDDED_CRYPTO_WALLET",
payment_instrument_details={"embeddedCryptoWallet": {"network": "ETHEREUM",
"linkedAccounts": [{"email": …}]}})` — AgentCore provisions a Privy embedded
wallet owned by the end user and returns its address. Then
`create_payment_session(...)` with the budget. Writes `INSTRUMENT_ID`,
`WALLET_ADDRESS`, `SESSION_ID`, and prints the funding and delegation steps.

### `privy_client.py` — Privy REST client

| Item | Purpose |
|---|---|
| `TRANSFER_WITH_AUTHORIZATION`, `EIP712_DOMAIN` | the EIP-3009 and EIP-712 domain type lists, in the field order clients send |
| `eip3009_typed_data(with_domain_type)` | the `typed_data` block for a policy condition, with or without `EIP712Domain` (Privy matches a typed-data condition only on an exact `types` match) |
| `canonicalize(obj)` | RFC 8785 JSON canonicalization (sorted keys, no whitespace) for request signing |
| `PrivyClient.from_env()` | Basic auth with `PRIVY_APP_ID:PRIVY_APP_SECRET` plus the `privy-app-id` header |
| `PrivyClient.sign(method, url, body)` | `privy-authorization-signature`: ECDSA P-256 / SHA-256 over the canonical `{version, method, url, body, headers}` payload, using the authorization private key (PKCS#8 DER, base64) |
| `get_wallet`, `find_wallet_by_address` | `GET /v1/wallets/{id}`, `GET /v1/wallets?address=…` |
| `update_wallet(id, body, signed)` | `PATCH /v1/wallets/{id}` (signed when the wallet has an owner) |
| `rpc(id, body)` | `POST /v1/wallets/{id}/rpc`, always signed — signs as the authorization key |
| `create_condition_set`, `add_condition_set_items`, `replace_condition_set_items`, `get_condition_set_items`, `delete_condition_set` | `/v1/condition_sets…`; items are stored in both the given and lowercase casing because matching is case-sensitive |
| `create_policy`, `delete_policy` | `/v1/policies` |
| `governing_policy_ids(wallet, auth_id)` | the policies that apply when the agent signs: the agent signer's `override_policy_ids` if set, else the wallet's `policy_ids` |
| `wallet_update_mode(wallet, auth_id)` | whether the app may change the wallet's policies: no owner → yes; owned by the authorization key → yes, signed; owned by anyone else (the user) → no, with an explanation |

### `privy_policy_setup.py` — create the Privy policy

`build_allowlist_rules(condition_set_id)` returns two otherwise-identical `ALLOW`
rules on `eth_signTypedData_v4` — one declaring `EIP712Domain`, one not — each
requiring domain `chainId == 84532`, message `to` in the condition set, and
message `value <= cap` (hex). Rule names stay under Privy's 50-character limit.
`main()` reads the wallet (`describe_wallet` prints owner, policies, signers),
creates the condition set and policy, and writes `PRIVY_WALLET_ID`,
`PRIVY_CONDITION_SET_ID`, `PRIVY_POLICY_ID`. Then:

- **app may update the wallet** → `PATCH policy_ids` (signed if owned by the key);
- **user-owned wallet** (the AgentCore case) → prints the `policyIds` change for
  the delegation frontend instead.

If creating the policy fails, it deletes the condition set it just made.

### `privy_policy_probe.py` — check the policy directly

`typed_data(...)` builds an EIP-3009 message for Base Sepolia USDC with
`validBefore = 1`, so any signature is already expired. `attempt(...)` sends it via
`PrivyClient.rpc` as the agent signer and classifies the reply (`SIGNED`, `DENIED`
for a policy violation, or the error). `main([wallet_id])` runs five cases —
allowed merchant, lowercase merchant, wrong recipient, over cap, wrong chain —
with and without `EIP712Domain`, and exits non-zero on any mismatch.

### `privy_policy_payment_demo.py` — check the policy through AgentCore

Requires `PRIVY_POLICY_ID` to govern the agent signer. It never touches the
user's wallet; it changes the policy's **condition set**, which the app owns:

| Step | Condition set | `ProcessPayment` must |
|---|---|---|
| 0 | merchant | succeed (proves delegation, funding, and that the rules match the signer's request shape) |
| 1 | decoy only | fail |
| 2 | merchant | succeed again (only the set changed, so step 1 was the policy) |

`try_pay` creates a fresh session and calls `generate_payment_header` against a
real 402; headers are never sent, so no USDC moves. Step 1 accepts a policy error
or the `InternalServerException` AgentCore currently returns for a Privy policy
refusal, and step 2 confirms the cause. The original condition set is restored in
`finally`.

### `privy_policy_remove.py` — clean up

Detaches the policy from the wallet's `policy_ids` (signed if needed) and deletes
it and its condition set. If the policy is the agent signer's override (set by the
user), it refuses: deleting it underneath the signer would break the agent's
signing; the user must remove the agent first.

## `frontend-patch/`

`attach-policy.patch` and `setup_frontend.sh` patch Privy's AgentCore SDK
frontend so **Connect agent** sets the sample's policy on the agent signer. See
[`frontend-patch/README.md`](../frontend-patch/README.md).

## `policies/`

| File | What it is |
|---|---|
| `agentcore_policy.cedar` | point-in-time AgentCore Policy: baseline `permit` for `PaymentsTarget___pay_merchant`, `forbid` above 500000 base units, `forbid` unless the recipient is allowlisted (`.contains()`) |
| `dogwood/payment_guardrails.dw` | the deployable policy set: Cedar cap and allowlist, plus temporal recipient provenance (the only `permit` for payments), velocity limit, and rolling spend cap |
| `dogwood/schema.cedarschema` | action schema for the two Gateway tools |
| `dogwood/agentcore.dwschema` | local copy of AgentCore's documented temporal event schema |
| `dogwood/traces/*.log`, `gen_traces.py` | replay scenarios and their generator |
| `dogwood/test_dogwood_policies.py` | validates both policy files and checks every verdict (15 checks) |
| `privy_allowlist_cap_policy.json` | the Privy policy `privy_policy_setup.py` creates, for reference |

## `test_privy_payment_agent.ipynb`

A notebook that runs the README steps cell by cell: install, check `.env`, confirm
AWS identity, provision, create the wallet, poll until active, the offline demos,
the Dogwood tests, the live demos, the Privy policy setup and probe, the agent,
and cleanup.

## Data that moves where

| Secret / ID | Lives in | Used by |
|---|---|---|
| Privy App Secret, authorization private key | `.env` (local dev only) → AgentCore Identity (Secrets Manager) after `provision_stack.py` | AgentCore, to sign on the user's behalf; the Privy scripts, to manage policies and probe |
| Privy App Secret (frontend) | frontend `.env.local` (server-side only) | the frontend's `check-signers` API route |
| Wallet address, instrument ID, session ID | `.env` | demos and agent |
| Policy ID, condition set ID | `.env`; policy ID also in the patched frontend | payment demo, probe, remove script |
