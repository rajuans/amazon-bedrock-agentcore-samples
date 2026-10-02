# Secure Payment Agent — Strands + AgentCore Payments + Stripe/Privy

A sample **autonomous payment agent** that buys a paid (x402-gated) resource,
paying in **USDC on Base Sepolia (testnet)** through **Amazon Bedrock AgentCore
Payments** with **Stripe (Privy)** as the wallet provider — wrapped in
**layered, policy-enforced spending guardrails**.

This is the Privy counterpart to the Coinbase CDP sample. The agent, the budgeted
session, the Cedar policy, and the app-level check are provider-agnostic; only the
wallet-provider connector and the **signing-layer policy** differ.

The agent never holds open-ended access to funds and cannot raise its own
limits. Every control that matters is enforced by infrastructure (a policy
engine, the wallet provider, and a budgeted session), not by the model's prompt.

> **Testnet only.** Base Sepolia with free USDC from
> [faucet.circle.com](https://faucet.circle.com/). Testnet USDC has no value.

## How it works

```
Agent (Strands + http_request)
  │  GET https://…/paid-api
  ├─► 402 Payment Required
  │        AgentCorePaymentsPlugin intercepts the 402
  │        → session budget check → sign USDC tx via Privy → payment proof
  │        → retry with the payment header (PAYMENT-SIGNATURE for x402 v2, X-PAYMENT for v1)
  ├─► 200 OK  (agent receives the paid content)
  └─► Agent summarizes the result
```

The x402 "exact" scheme signs an **EIP-3009 `TransferWithAuthorization`** as
EIP-712 typed data. On Privy that is an `eth_signTypedData_v4` operation, which is
exactly what the Privy policy engine screens.

## Layered guardrails (defense in depth)

| Layer | Enforces | Where |
|---|---|---|
| **AgentCore Policy** (Cedar + Dogwood) | per-transaction amount cap + recipient allowlist, evaluated before execution; with Dogwood temporal policies, also recipient provenance, a velocity limit, and a rolling spend cap | [`policies/agentcore_policy.cedar`](policies/agentcore_policy.cedar), [`policies/dogwood/`](policies/dogwood/) |
| **Privy Policy Engine** | recipient `to` allowlist **+** per-transaction `value` cap on the EIP-3009 typed data, fail-closed, at signing time | [`policies/privy_allowlist_cap_policy.json`](policies/privy_allowlist_cap_policy.json) |
| **AgentCore Payment Session** | cumulative, time-bounded spend ceiling (`maxSpendAmount`) | created in [`setup/provision_payments.py`](setup/provision_payments.py) |
| **App-level check** | always-on cap + allowlist backstop | [`agent/guardrails_demo.py`](agent/guardrails_demo.py) |

> A Payment Session caps *cumulative* spend only. Rejecting a *single* high-value
> payment, or a payment to a *specific* recipient, requires the policy layers
> above — see [`docs/SECURITY.md`](docs/SECURITY.md).

## Privy vs Coinbase CDP — what differs

| | Coinbase CDP | Stripe / Privy |
|---|---|---|
| Connector vendor | `CoinbaseCDP` | `StripePrivy` |
| Credentials | API Key ID/Secret + Wallet Secret | App ID + App Secret + Authorization ID + P-256 Private Key |
| Signing op (x402) | `signEndUserEvmTypedData` | `eth_signTypedData_v4` |
| Policy attach scope | project-scoped (end-user accounts) | **per-wallet** (`policy_ids`) |
| Policy polarity | allow-rule allowlist (fail-secure) | **fail-closed**: unmatched/unlisted method ⇒ DENY |
| Recipient rule | typed-data `to` `in` allowlist | typed-data `to` `in_condition_set` |
| Per-tx cap | typed-data `value` `<=` | typed-data `value` `lte` |

This sample implements the Privy lever as **fail-closed ALLOW rules** (approved
recipient + under cap + right chain), rather than an OFAC-style denylist. See
[`docs/SECURITY.md`](docs/SECURITY.md) for why — a denylist on a typed-data field
can fail *open* if its `types` schema doesn't match the request exactly, a gap an
AgentCore Payments pentest found in a Privy `to` denylist.

## Repository layout

```
.
├── agent/
│   ├── secure_payment_agent.py   # the autonomous x402 purchase (happy path)
│   ├── guardrails_demo.py        # 3 scenarios: happy path, high amount, bad recipient
│   ├── session_budget_demo.py    # live: session budget rejects an over-budget payment
│   └── utils.py                  # env load/validate helpers
├── setup/
│   ├── provision_stack.py        # create IAM roles + Privy credential provider + manager + connector
│   ├── provision_payments.py     # create per-user wallet + budgeted session
│   ├── privy_client.py           # minimal Privy REST client + P-256 request signing
│   ├── privy_policy_setup.py     # create condition set + policy (allowlist + cap + chain), attach to wallet
│   ├── privy_policy_probe.py     # check the attached policy signs/refuses the right typed data (no funds move)
│   ├── privy_policy_remove.py    # detach + delete the Privy policy (cleanup)
│   └── privy_policy_payment_demo.py # live: the policy decides whether AgentCore ProcessPayment succeeds
├── policies/
│   ├── agentcore_policy.cedar    # per-tx cap + recipient allowlist (Cedar)
│   ├── dogwood/                  # temporal policies: provenance, velocity, rolling cap (+ tests)
│   └── privy_allowlist_cap_policy.json
├── docs/SECURITY.md              # threat model + the four guardrail layers
├── .env.privy.sample             # copy to .env; never commit real secrets
└── requirements.txt
```

## Prerequisites

- An AWS account in a region where AgentCore Payments is available
  (`us-east-1`, `us-west-2`, `eu-central-1`, `ap-southeast-2`), AWS CLI configured.
- **Python 3.10+** and **Node.js 20+** (for the AgentCore CLI).
- A **dedicated Privy app** ([dashboard.privy.io](https://dashboard.privy.io/)):
  App ID, App Secret, and a P-256 authorization key pair (Authorization ID +
  Private Key). Do not reuse an app that serves other purposes.
- Amazon Bedrock model access for the agent's LLM.

## Quick start

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.privy.sample .env      # then fill in your values
```

**1 — Provision the shared payment stack** (IAM roles + Privy credential provider
+ PaymentManager + PaymentConnector). This raw-boto3 script mirrors the public
awslabs sample's 4-role privilege separation and writes every resulting ARN/ID
into `.env`:

```bash
python setup/provision_stack.py
```

<details><summary>Alternative: the AgentCore CLI</summary>

```bash
npm install -g @aws/agentcore
agentcore create --name PaymentSetup --framework Strands --protocol HTTP \
  --model-provider Bedrock --memory none
cd PaymentSetup
agentcore add payment-manager --name MyPaymentManager \
  --auto-payment true --default-spend-limit 1.00
agentcore add payment-connector --manager MyPaymentManager \
  --name MyPrivyConnector --provider StripePrivy \
  --app-id "$PRIVY_APP_ID" \
  --app-secret "$PRIVY_APP_SECRET" \
  --authorization-id "$PRIVY_AUTHORIZATION_ID" \
  --authorization-private-key "$PRIVY_AUTHORIZATION_PRIVATE_KEY"
agentcore validate && agentcore deploy -y
agentcore status --type payment   # copy PAYMENT_MANAGER_ARN + PAYMENT_CONNECTOR_ID into ../.env
```
</details>

**2 — Create the per-user wallet + budgeted session:**

```bash
python setup/provision_payments.py
```

**3 — Fund the wallet + grant delegated signing** (once): fund `WALLET_ADDRESS`
at [faucet.circle.com](https://faucet.circle.com/) (Base Sepolia), then grant the
agent delegated signing through the Privy
[AgentCore SDK frontend](https://github.com/privy-io/aws-agentcore-sdk): set
`NEXT_PUBLIC_PRIVY_APP_ID`, `NEXT_PUBLIC_PRIVY_SIGNER_ID` (= your authorization
key ID), `PRIVY_APP_SECRET`, and `NEXT_PUBLIC_NETWORK_MODE=testnet` in
`.env.local`, add the frontend's origin to the Privy app's allowed origins, log in
as `LINKED_EMAIL`, and choose **Connect agent**.

> **Attach the policy at this step.** The AgentCore wallet is owned by the end
> user, so only the user can put a policy on the agent's signer. Run step 4's
> `privy_policy_setup.py` first; it prints a policy ID. Then, in the frontend's
> `src/components/modals/connect-agent-modal.tsx`, change
> `signers: [{ signerId, policyIds: [] }]` to
> `signers: [{ signerId, policyIds: ["<policy id>"] }]` before you click
> **Connect agent**. If the agent was already connected without the policy,
> remove the signer and add it again — re-adding an existing signer is a no-op.

**4 — (Recommended) the Privy signing-layer policy** (recipient allowlist +
per-tx cap + chain pin, fail-closed at signing). Creates a Privy condition set of
approved recipients and a policy, then attaches it to the wallet by `policy_ids`.
The script reads the wallet first: it signs the update with the authorization key
if that key owns the wallet, and stops with an explanation if the end user owns it
(only the owner can change a wallet's policies — then attach the policy during
delegation instead).

```bash
# Attach the policy to the wallet backing your instrument:
python setup/privy_policy_setup.py

# Check enforcement directly: signs allowed EIP-3009 messages, refuses wrong
# recipient / over-cap / wrong chain. Every message is already expired
# (validBefore = 1), so no signature can move funds.
python setup/privy_policy_probe.py

# Prove it end to end through AgentCore, in three steps: (0) with no policy the
# payment must succeed — this checks delegation and funding first; (1) with a
# decoy-only policy ProcessPayment must fail with a policy error; (2) with a
# merchant-allowed policy it must succeed again (positive control). Restores the
# wallet's original policies afterwards; no payment header is sent, so no USDC moves.
python setup/privy_policy_payment_demo.py

# Remove the policy after testing:
python setup/privy_policy_remove.py
```

**4b — (Optional) test the Dogwood temporal policies locally** — no AWS
needed. Validates the policy set and replays 10 scenarios (injected recipient,
velocity, rolling spend cap, and more). See
[`policies/dogwood/README.md`](policies/dogwood/README.md) to build the CLI and
deploy the rules:

```bash
DOGWOOD=/path/to/dogwood python policies/dogwood/test_dogwood_policies.py
```

**5 — Run:**

```bash
python agent/secure_payment_agent.py   # autonomous purchase (happy path)
python agent/guardrails_demo.py         # guardrail rejections (runs offline)
python agent/session_budget_demo.py     # live: over-budget payment refused server-side
```

## Verification status

- **Provider-agnostic layers** (budgeted session, Cedar policy, app-level check)
  behave identically to the Coinbase sample, which was verified live on Base
  Sepolia (`session_budget_demo.py` refuses an over-budget payment server-side
  with `InsufficientBudget`).
- **Dogwood temporal policies** (`policies/dogwood/`) are validated and
  replay-tested locally with the `dogwood` 1.0 CLI against a copy of
  AgentCore's documented event schema: 10/10 scenarios pass. They have not yet
  been deployed to a live AgentCore Gateway in this sample.
- **Verified live (2026-10-02, Base Sepolia):**
  - *Happy path* — the agent paid **0.001 USDC** through AgentCore + the Privy
    connector and received the content. Settlement tx
    [`0x0a83c4c706422d24920b9b6421d650f8fc9f4728494a237b6e3e9a2b270d63d1`](https://sepolia.basescan.org/tx/0x0a83c4c706422d24920b9b6421d650f8fc9f4728494a237b6e3e9a2b270d63d1).
  - *Privy policy* — `privy_policy_setup.py` created the two-rule policy, and
    `privy_policy_probe.py` against a wallet carrying it passed all 10 cases:
    allowed payments signed (both `types` shapes, both address casings); wrong
    recipient, over-cap, and wrong chain were refused. With no policy on the
    agent signer, Privy signed every case.
  - *Exact `types` match* — a policy with only the no-`EIP712Domain` rule
    refused an allowed payment sent with `EIP712Domain` (fail-closed); a `DENY`
    rule on `to` without `EIP712Domain` let a payment to the denied address be
    signed when the request carried `EIP712Domain` (fail-open).
  - *Wallet ownership* — the AgentCore-created wallet is user-owned (`owner_id`
    is the user), so the app cannot attach policies to it; the policy must be set
    on the agent signer at delegation (see step 3).
- **Not yet run live:** `privy_policy_payment_demo.py` through AgentCore with the
  policy on the agent signer.

## Security notes

- The `.env` pattern is for **local development only**. In deployed workloads,
  source credentials from AWS Secrets Manager / SSM Parameter Store; AgentCore
  Identity stores the provider credentials so the agent never sees long-term
  secrets. See [`docs/SECURITY.md`](docs/SECURITY.md).
- Never commit a real `.env` (it is git-ignored).

## References (public)

- AgentCore Payments — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/payments-getting-started.html
- AgentCore Policy — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
- AgentCore temporal policies (Dogwood) — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html
- Dogwood language guide — https://dogwood-policy.github.io/dogwood/index.html
- AWS samples — https://github.com/awslabs/agentcore-samples (`01-features/08-agents-that-transact`)
- Privy policies — https://docs.privy.io/controls/policies
- Privy AgentCore SDK — https://github.com/privy-io/aws-agentcore-sdk
- x402 protocol — https://docs.cdp.coinbase.com/x402/welcome
- Strands Agents — https://strandsagents.com/

## License

MIT-0. See [LICENSE](LICENSE).
