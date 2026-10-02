# Secure Payment Agent — Strands + AgentCore Payments + Stripe/Privy

A sample **autonomous payment agent** that buys a paid (x402-gated) resource,
paying in **USDC on Base Sepolia (testnet)** through **Amazon Bedrock AgentCore
Payments** with **Stripe (Privy)** as the wallet provider — wrapped in
**layered, policy-enforced spending guardrails**.

This is the Privy counterpart to the Coinbase CDP sample. The agent, the budgeted
session, the Cedar/Dogwood policies, and the app-level check are provider-agnostic;
only the wallet connector and the **signing-layer policy** differ.

The agent never holds open-ended access to funds and cannot raise its own limits.
Every control that matters is enforced by infrastructure (a policy engine, the
wallet provider, and a budgeted session), not by the model's prompt.

> **Testnet only.** Base Sepolia with free USDC from
> [faucet.circle.com](https://faucet.circle.com/). Testnet USDC has no value.

For a file-by-file explanation of the code, see
[`docs/CODE_WALKTHROUGH.md`](docs/CODE_WALKTHROUGH.md). For the threat model, see
[`docs/SECURITY.md`](docs/SECURITY.md).

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
EIP-712 typed data. On Privy that is an `eth_signTypedData_v4` request, which is
what the Privy policy engine screens.

## Layered guardrails (defense in depth)

| Layer | Enforces | Where |
|---|---|---|
| **AgentCore Policy** (Cedar + Dogwood) | per-transaction cap + recipient allowlist before execution; with Dogwood temporal policies, also recipient provenance, a velocity limit, and a rolling spend cap | [`policies/agentcore_policy.cedar`](policies/agentcore_policy.cedar), [`policies/dogwood/`](policies/dogwood/) |
| **Privy Policy Engine** | recipient `to` allowlist **+** per-transaction `value` cap **+** chain pin on the EIP-3009 typed data, fail-closed, at signing time | [`policies/privy_allowlist_cap_policy.json`](policies/privy_allowlist_cap_policy.json) |
| **AgentCore Payment Session** | cumulative, time-bounded spend ceiling (`maxSpendAmount`) | [`setup/provision_payments.py`](setup/provision_payments.py) |
| **App-level check** | always-on cap + allowlist backstop | [`agent/guardrails_demo.py`](agent/guardrails_demo.py) |

A Payment Session caps *cumulative* spend only. Rejecting a *single* high-value
payment, or a payment to a *specific* recipient, needs the policy layers above.

## Privy vs Coinbase CDP — what differs

| | Coinbase CDP | Stripe / Privy |
|---|---|---|
| Connector vendor | `CoinbaseCDP` | `StripePrivy` |
| Credentials | API Key ID/Secret + Wallet Secret | App ID + App Secret + Authorization ID + P-256 private key |
| Signing request (x402) | `signEndUserEvmTypedData` | `eth_signTypedData_v4` |
| Who attaches the policy | the developer (project-scoped policy) | the **end user**, on the agent signer, at delegation |
| Policy evaluation | accept rules; no match ⇒ reject | ALLOW rules; no match ⇒ DENY; unlisted method ⇒ DENY |
| Recipient rule | typed-data `to` `in` list | typed-data `to` `in_condition_set` |
| Per-tx cap | typed-data `value` `<=` | typed-data `value` `lte` (hex) |
| Refusal seen by the caller | `AccessDeniedException … blocked by a policy` | `InternalServerException` (see Troubleshooting) |

## Verified live (Base Sepolia, 2026-10-02)

| Check | Result |
|---|---|
| Agent happy path | paid 0.001 USDC through AgentCore + Privy; tx [`0x0a83c4c7…63d1`](https://sepolia.basescan.org/tx/0x0a83c4c706422d24920b9b6421d650f8fc9f4728494a237b6e3e9a2b270d63d1) |
| Session budget | over-budget payment refused server-side with `InsufficientBudget` (shared code path, run on the Coinbase stack) |
| Privy policy, direct (`privy_policy_probe.py`) | 10/10 on the AgentCore wallet: allowed payments signed (both `types` shapes, both address casings); wrong recipient, over-cap, wrong chain refused. With no policy, Privy signed every case |
| Privy policy through AgentCore (`privy_policy_payment_demo.py`) | allowed → header produced; decoy → refused; allowed again → header produced |
| Exact `types` match | ALLOW rule without `EIP712Domain` refused an allowed payment sent with it (fail-closed); a `DENY` rule without it let a payment to the denied address be signed (fail-open) |
| Wallet ownership | AgentCore-created wallet is user-owned; the app cannot change its policies |
| Dogwood temporal policies | validated and replay-tested locally (15/15 checks); not deployed to a live Gateway |

## Prerequisites

- An AWS account in a Region where AgentCore Payments is available (`us-east-1`,
  `us-west-2`, `eu-central-1`, `ap-southeast-2`), with credentials configured.
- **Python 3.10+** and **Node.js 20+** (Node is only for the delegation frontend
  in step 5).
- A **dedicated Privy app** at [dashboard.privy.io](https://dashboard.privy.io/):
  App ID, App Secret, and a P-256 authorization key (**Wallet infrastructure →
  Authorization → New key**: note the key ID and the private key).
- An email inbox for the wallet's end user.
- Amazon Bedrock model access for the agent's LLM.

## Step by step

### 1. Install

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.privy.sample .env
```

### 2. Configure `.env`

Fill in at least:

| Key | Value |
|---|---|
| `AWS_REGION` | e.g. `us-east-1` |
| `PRIVY_APP_ID`, `PRIVY_APP_SECRET` | from the Privy app settings |
| `PRIVY_AUTHORIZATION_ID` | the authorization key ID |
| `PRIVY_AUTHORIZATION_PRIVATE_KEY` | the private key, **without** the `wallet-auth:` prefix |
| `LINKED_EMAIL` | the end user's email |
| `USER_ID` | any stable user id, e.g. `demo-user-001` |

Values must be bare (no quotes, no trailing `;`). The setup scripts write the
remaining keys back into `.env`.

### 3. Provision the payment stack

```bash
python setup/provision_stack.py
```

Creates (idempotently) four least-privilege IAM roles, a `StripePrivy` credential
provider, a payment manager, and a payment connector, and writes their IDs to
`.env`. Expected tail:

```
4) Payment connector (manager → Privy credential provider):
   paymentConnectorId: privyconnector-…
   connector READY
```

If the account is at its payment-manager quota (default 5), set
`PAYMENT_MANAGER_ARN` in `.env` to an existing manager first; the script then
adds the Privy connector to it (`reusing existing manager …`).

### 4. Create the wallet, the session, and the Privy policy

```bash
python setup/provision_payments.py   # Privy embedded wallet + budgeted session
python setup/privy_policy_setup.py   # condition set + two-rule policy
```

`provision_payments.py` writes `INSTRUMENT_ID`, `WALLET_ADDRESS`, and `SESSION_ID`.
`privy_policy_setup.py` creates the approved-recipients condition set and the
policy, and writes `PRIVY_WALLET_ID`, `PRIVY_CONDITION_SET_ID`, and
`PRIVY_POLICY_ID`. Because the AgentCore wallet is user-owned, it prints the
policy ID to attach at delegation instead of attaching it itself:

```
The wallet is owned by …, so this app cannot attach the policy itself. Attach it
when the user delegates signing to the agent: …
      signers: [{ signerId, policyIds: ["<policy id>"] }]
```

### 5. Fund the wallet and delegate signing (with the policy)

1. Fund `WALLET_ADDRESS` with Base Sepolia USDC at
   [faucet.circle.com](https://faucet.circle.com/) (1 USDC is plenty).
2. Set up the delegation frontend — Privy's
   [AgentCore SDK frontend](https://github.com/privy-io/aws-agentcore-sdk), patched
   so **Connect agent** attaches the policy to the agent signer:

   ```bash
   bash frontend-patch/setup_frontend.sh            # clones, patches, writes .env.local, installs
   cd ../privy-agentcore-frontend && npx -y pnpm@9 dev
   ```

   See [`frontend-patch/README.md`](frontend-patch/README.md) for what the patch
   changes. Running it on a remote host? Tunnel the port from your laptop:
   `ssh -N -L 3000:127.0.0.1:3000 <host>`.
3. In the Privy dashboard, add `http://localhost:3000` to the app's allowed origins.
4. Open `http://localhost:3000`, log in as `LINKED_EMAIL`, click **Connect agent**.

### 6. Verify the Privy policy

```bash
python setup/privy_policy_probe.py
```

Signs EIP-3009 messages through Privy as the agent signer — with and without
`EIP712Domain` — and checks each verdict. Every message has `validBefore = 1`
(already expired), so no signature can move funds. Expected:

```
Request types WITH EIP712Domain:
  PASS  allowlisted merchant, $0.001, Base Sepolia    expected SIGNED  got SIGNED
  PASS  same, recipient lowercase                     expected SIGNED  got SIGNED
  PASS  non-allowlisted recipient                     expected DENIED  got DENIED
  PASS  over the $0.50 cap                            expected DENIED  got DENIED
  PASS  wrong chain (Base mainnet 8453)               expected DENIED  got DENIED
…
All cases matched the policy.
```

### 7. Run the demos and the agent

```bash
python agent/guardrails_demo.py              # offline: app-level decisions
python agent/session_budget_demo.py          # live: InsufficientBudget, budget untouched
python setup/privy_policy_payment_demo.py    # live: allowed → decoy → allowed through ProcessPayment
python agent/secure_payment_agent.py         # live: the agent buys the paid content (0.001 USDC)
```

`privy_policy_payment_demo.py` flips the policy's condition set (which the app
owns) between the merchant and a decoy, so it never changes the user's wallet, and
restores the set afterwards. No payment header is sent, so no USDC moves. Expected
end: `✅ Privy policy enforcement confirmed end to end.`

### 8. Test the AgentCore Policy rules locally (optional, no AWS)

```bash
DOGWOOD=/path/to/dogwood python policies/dogwood/test_dogwood_policies.py   # 15/15 checks
```

See [`policies/dogwood/README.md`](policies/dogwood/README.md) to build the CLI and
deploy the rules to a Gateway.

### 9. Clean up

```bash
python setup/privy_policy_remove.py
```

If the policy is the agent signer's (set at delegation), the script refuses to
delete it — have the user remove the agent in the frontend first. To remove the
AWS resources, delete the instrument, connector, and (if you created it) the
manager — see the cleanup section of the
[AgentCore Payments quick start](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/payments-getting-started.html#payments-getting-started-cleanup).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ServiceQuotaExceededException … maxManagers limit exceeded` | account at its payment-manager quota | set `PAYMENT_MANAGER_ARN` to an existing manager and re-run step 3 |
| `ValidationException … Credential provider … already exists` on re-run | provider created by an earlier run | handled — the script looks it up by name |
| Privy `401` / auth errors | `.env` values quoted or ending in `;`, or key has `wallet-auth:` | store bare values; strip the prefix |
| `privy_policy_setup.py` creates the policy but does not attach it | wallet is user-owned (expected for AgentCore) | attach at delegation (step 5) |
| Probe: every case `SIGNED` | no policy on the agent signer | redo step 5 with the patched frontend |
| Probe: allowed cases `DENIED` | policy `types` don't match what the signer sends | keep both rule shapes from `privy_policy_setup.py` |
| **Connect agent** button missing after an earlier delegation | upstream frontend treats any existing signer as connected | use the patched frontend — it re-adds the signer with the policy |
| Browser console: CSP errors for `explorer-api.walletconnect.com` | frontend's CSP blocks WalletConnect's wallet directory | harmless; login and Connect agent still work |
| `ProcessPayment` → `InternalServerException … Something went wrong` (SDK retries 4×) for a disallowed recipient | AgentCore currently reports a Privy policy refusal as a generic 5xx | expected today; the payment demo confirms the cause with its allowed-again step |
| `Delegation not completed` | the user has not connected the agent | step 5 |

## Repository layout

```
.
├── agent/
│   ├── secure_payment_agent.py     # autonomous x402 purchase (happy path)
│   ├── guardrails_demo.py          # offline: happy path, high amount, bad recipient
│   ├── session_budget_demo.py      # live: session budget rejects an over-budget payment
│   └── utils.py                    # .env helpers, idempotent create, status polling
├── setup/
│   ├── provision_stack.py          # IAM roles + Privy credential provider + manager + connector
│   ├── provision_payments.py       # per-user Privy wallet + budgeted session
│   ├── privy_client.py             # Privy REST client + P-256 request signing
│   ├── privy_policy_setup.py       # condition set + two-rule policy (attach, or print for delegation)
│   ├── privy_policy_probe.py       # check the policy directly with expired messages
│   ├── privy_policy_payment_demo.py # live: allowed → decoy → allowed through ProcessPayment
│   └── privy_policy_remove.py      # detach + delete the policy
├── frontend-patch/                 # patch + script for the Privy delegation frontend
├── policies/
│   ├── agentcore_policy.cedar      # per-tx cap + recipient allowlist (Cedar)
│   ├── dogwood/                    # temporal policies + local test suite
│   └── privy_allowlist_cap_policy.json
├── docs/
│   ├── SECURITY.md                 # threat model + the four layers
│   └── CODE_WALKTHROUGH.md         # file-by-file walkthrough
├── .env.privy.sample
└── requirements.txt
```

## Security notes

- The `.env` pattern is for **local development only**. In deployed workloads,
  source credentials from AWS Secrets Manager or SSM Parameter Store; AgentCore
  Identity stores the provider credentials so the agent never sees long-term
  secrets.
- Never commit `.env` or the frontend's `.env.local` (both hold secrets).
- Use a **dedicated** Privy app for AgentCore Payments.

## References

- AgentCore Payments — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/payments-getting-started.html
- AgentCore Policy — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
- AgentCore temporal policies (Dogwood) — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html
- Privy + AgentCore recipe — https://docs.privy.io/recipes/agent-integrations/agentcore-payments
- Privy policies — https://docs.privy.io/controls/policies/overview
- Privy AgentCore SDK frontend — https://github.com/privy-io/aws-agentcore-sdk
- x402 protocol — https://docs.cdp.coinbase.com/x402/welcome
- Strands Agents — https://strandsagents.com/

## License

MIT-0. See [LICENSE](LICENSE).
