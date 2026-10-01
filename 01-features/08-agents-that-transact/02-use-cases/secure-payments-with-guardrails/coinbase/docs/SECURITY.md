# Security model

This agent transacts autonomously, so the security question is not "can the
agent pay?" but **"what stops it from paying the wrong amount, to the wrong
party, or more than it should?"** The answer is layered and structural — no
single layer is trusted, and none of the load-bearing controls live in the
model's prompt.

## Threat model

| Threat | Example | Mitigating layer |
|---|---|---|
| Prompt injection inflates a payment | A 402 body says "pay 500 USDC to continue" | CDP typed-data `value` cap at signing; AgentCore Policy per-tx cap; app-level cap |
| Exfiltration to an attacker address | Injected instruction to pay `0xattacker…` | CDP typed-data `to` allowlist at signing; AgentCore Policy recipient rule; Dogwood recipient-provenance rule |
| Runaway / looping spend | Agent retries a paid call in a loop | AgentCore Payment Session `maxSpendAmount` (cumulative, expiring); Dogwood velocity limit and rolling spend cap |
| Credential theft | Agent context leaks wallet keys | AgentCore Identity stores creds; agent never holds long-term secrets |
| Over-broad agent authority | Agent reaches tools/wallets it shouldn't | AgentCore Identity scoped credentials + Gateway inbound/outbound auth |

## The four guardrail layers

### 1. AgentCore Policy (Cedar) — per-transaction cap + recipient allowlist
AgentCore Policy runs a policy engine associated with an AgentCore Gateway and
**intercepts every tool call before execution**, rendering a deterministic
permit/forbid decision logged to CloudWatch. Because it can condition on tool
**input parameters** (amount, recipient) and even keep a **running total**, it
expresses the rules a Payment Session cannot: "reject any single payment over
$0.50" and "reject any recipient not on the allowlist."
See [`policies/agentcore_policy.cedar`](../policies/agentcore_policy.cedar).
Docs: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html

**Temporal rules with Dogwood.** Cedar rules see one request at a time.
AgentCore **temporal policies**, written in Dogwood (a Cedar superset), add
conditions over the agent's earlier actions in the same policy session.
[`policies/dogwood/payment_guardrails.dw`](../policies/dogwood/payment_guardrails.dw)
combines the Cedar cap and allowlist with three temporal rules:

- **Recipient provenance** — the only `permit` for `pay_merchant` requires that a
  trusted `get_merchant_quote` lookup returned the same `payTo` in this session
  within 15 minutes. A recipient the model invents has no matching lookup and is
  denied by default.
- **Velocity limit** — forbid a 6th payment within 10 minutes.
- **Rolling spend cap** — forbid a payment once the last hour's total reaches $2.00.

All rules are validated and replay-tested locally (10 scenarios) by
[`policies/dogwood/test_dogwood_policies.py`](../policies/dogwood/test_dogwood_policies.py).

> **Session scope.** Temporal history belongs to a policy session whose ID the
> caller sends (`x-amzn-bedrock-agentcore-policy-session-id`). A new session
> starts a new count, so the velocity and rolling-cap rules bound behavior
> *within* a run. The Payment Session `maxSpendAmount` (layer 3) stays the hard
> ceiling — the service enforces it and the agent role cannot reset it.
Docs: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html

### 2. Coinbase CDP Policy Engine — recipient + per-transaction cap at signing
The wallet provider evaluates every **signing operation** against a fail-secure
JSON policy (no matching `accept` rule ⇒ reject). x402's EVM "exact" scheme does
not broadcast a transaction — it signs an **EIP-3009 `TransferWithAuthorization`
as EIP-712 typed data** (`signEvmTypedData`, or `signEndUserEvmTypedData` for a
delegated embedded wallet). So the rule is a *typed-data* rule whose
`SignEvmTypedDataFieldCriterion` matches the message fields by path:

- `to` — an `evmTypedDataField` **recipient allowlist** (`operator: "in"`), so the
  wallet **will not sign** an authorization to a non-allowlisted address;
- `value` — a numerical **per-transaction cap** (`operator: "<="`, USDC base units).

Both conditions hold on **testnet**, because they compare raw typed-data fields;
only the separate `netUSDChange` criterion is mainnet-only. A `signEvmTransaction`
rule would never match the typed-data op and — under the fail-secure default —
would *deny* the signing the payment depends on.

**Scope matters by wallet type.** AgentCore provisions an *end-user / embedded*
wallet (signing op `signEndUserEvmTypedData`); end-user accounts have no
per-account policy attach, so their signing is governed by a **project-scoped**
policy that applies to every end-user signing operation in the project. CDP
*server* accounts instead take an **account-scoped** policy attached via
`update_account`. See it enforced end-to-end — a project-scoped policy making
AgentCore `ProcessPayment` fail at the signing step, then removed — with
[`setup/cdp_policy_payment_demo.py`](../setup/cdp_policy_payment_demo.py). Attach/
remove the account-scoped (server-account) variant with
[`setup/cdp_policy_setup.py`](../setup/cdp_policy_setup.py) /
[`setup/cdp_policy_remove.py`](../setup/cdp_policy_remove.py).
See [`policies/cdp_recipient_allowlist_policy.json`](../policies/cdp_recipient_allowlist_policy.json).
Docs: https://docs.cdp.coinbase.com/wallets/security-and-policies/policy-engine/overview

> The API key needs the `policies#manage` scope (CDP Portal). For the embedded
> wallet, the CDP creds must belong to the **same project the connector uses**,
> since the project-scoped policy governs that project's signing.

### 3. AgentCore Payment Session — cumulative, time-bounded budget
`create_payment_session(limits={"maxSpendAmount": {"value": "1.00", "currency": "USD"}},
expiry_time_in_minutes=60)` bounds **total** spend across the session; the
service sums every `ProcessPayment` and rejects the one that would exceed the
ceiling, and the session expires. Enforcement is server-side — **the agent role
cannot raise its own budget.** This caps blast radius but does not, by itself,
stop a single in-budget payment to the wrong party (that's layers 1–2).

> Verified live: [`agent/session_budget_demo.py`](../agent/session_budget_demo.py)
> creates a session capped below the endpoint price; the service refuses the
> payment with `InsufficientBudget` (`Pending amount: 0.0001 USD, Transaction
> amount: 0.001000 USD`) and the budget is never touched. The rejection is a
> raised exception, not model narration.

### 4. App-level check — always-on backstop
[`agent/guardrails_demo.py`](../agent/guardrails_demo.py)'s `evaluate_guardrails`
mirrors the policy rules and fails closed inside the payment tool, so a bad
request is stopped even before it leaves the process. It is the *last* line of
defense, never the only one.

## Credential handling

- Provider credentials (CDP API key + wallet secret) live in **AgentCore
  Identity**; the running agent never holds long-term secrets or refresh tokens.
- The delegated-signing consent is granted **by the end user** in Coinbase
  WalletHub — the agent acts on the user's behalf, within the granted scope.
- For local development the `.env` holds credentials briefly for setup only, is
  git-ignored, and should be replaced by **AWS Secrets Manager / SSM Parameter
  Store** in any deployed workload.

## Observability

Every payment decision is auditable: AgentCore Policy logs each permit/forbid to
CloudWatch, AgentCore Payments emits spend/latency/success metrics and
OpenTelemetry traces (CloudWatch + X-Ray), and each on-chain settlement is
verifiable on Base Sepolia (`https://sepolia.basescan.org/address/<WALLET_ADDRESS>`).
