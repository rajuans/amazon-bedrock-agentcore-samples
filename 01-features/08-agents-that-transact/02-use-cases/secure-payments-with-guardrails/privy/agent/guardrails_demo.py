"""Payment guardrails demo — reject a high amount and a non-allowlisted recipient.

An AgentCore Payment Session only caps *cumulative* spend (`maxSpendAmount`); it
cannot express a *per-transaction* amount cap or a *per-recipient* rule. Those
belong in a policy layer:

  • AgentCore Policy (Cedar)  -> per-tx amount cap + recipient allowlist,
                                 evaluated on every payment tool call through an
                                 AgentCore Gateway, BEFORE execution.
                                 (policies/agentcore_policy.cedar)
  • Privy Policy Engine       -> recipient allowlist + per-tx `value` cap enforced
                                 at signing time, fail-closed (unmatched => DENY).
                                 (policies/privy_allowlist_cap_policy.json)

`evaluate_guardrails` below mirrors those same rules so the agent's payment tool
fails closed even before the request leaves the process — defense in depth. The
authoritative, tamper-proof enforcement is the two policy layers above; the app
check is the always-on backstop.

Run standalone (no AWS needed) to see the decisions:
    python agent/guardrails_demo.py
"""

import os
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Defaults match .env.privy.sample and the two policy files.
PER_TX_CAP_USD = float(os.environ.get("PER_TX_CAP_USD", "0.50"))
ALLOWLIST = [
    a.strip().lower()
    for a in os.environ.get(
        "RECIPIENT_ALLOWLIST", "0xA27f7cB624B57C79d7F9de03ae9F5C705c2858dB"
    ).split(",")
    if a.strip()
]


@dataclass
class Decision:
    allowed: bool
    reason: str
    layer: str  # which guardrail layer decides in production


def evaluate_guardrails(recipient: str, amount_usd: float) -> Decision:
    """Deterministic, fail-closed guardrail check (mirrors the policy layer)."""
    if recipient.strip().lower() not in ALLOWLIST:
        return Decision(
            False,
            f"recipient {recipient} is not on the allowlist",
            "Privy Policy Engine (typed-data `to` allowlist) + AgentCore Policy",
        )
    if amount_usd > PER_TX_CAP_USD:
        return Decision(
            False,
            f"amount ${amount_usd:.2f} exceeds per-transaction cap ${PER_TX_CAP_USD:.2f}",
            "Privy Policy Engine (typed-data `value` lte) + AgentCore Policy",
        )
    return Decision(True, "within per-tx cap and recipient allowlisted", "—")


def guarded_pay(recipient: str, amount_usd: float) -> str:
    """Strands @tool body: authorize a payment, then (in production) settle it.

    Wire this into a Strands Agent with `from strands import tool` and
    `@tool` — the docstring becomes the tool description the model sees.
    Here it returns the guardrail decision so the demo is runnable offline.
    """
    d = evaluate_guardrails(recipient, amount_usd)
    if not d.allowed:
        return f"PAYMENT REJECTED — {d.reason}. Enforced by: {d.layer}."
    # In production: settle within the funded AgentCore Payment Session
    # (manager.process_payment / the AgentCorePaymentsPlugin x402 flow).
    return f"PAYMENT APPROVED — ${amount_usd:.2f} to {recipient} (would settle in USDC on Base Sepolia)."


SCENARIOS = [
    ("Buy content from the allowlisted merchant", "0xA27f7cB624B57C79d7F9de03ae9F5C705c2858dB", 0.10),
    ("Agent tries to pay a HIGH amount", "0xA27f7cB624B57C79d7F9de03ae9F5C705c2858dB", 500.00),
    ("Agent tries to pay a NON-ALLOWLISTED recipient", "0x000000000000000000000000000000000000dEaD", 0.10),
]


def main() -> None:
    print(f"Per-transaction cap: ${PER_TX_CAP_USD:.2f}   Allowlist: {ALLOWLIST}\n")
    for title, recipient, amount in SCENARIOS:
        print(f"▶ {title}")
        print(f"    pay(recipient={recipient}, amount_usd={amount})")
        print(f"    {guarded_pay(recipient, amount)}\n")


if __name__ == "__main__":
    main()
