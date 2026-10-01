"""Generate the replay traces in traces/ (run once; the .log files are committed).

Each trace is a sequence of Gateway tool calls in a policy session. A
`::request` line is a decision point (the replay prints Allow/Deny for it); a
`::response` line records a completed call. Timestamps are seconds.
"""
import os

GW = 'AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/payments-gateway"'
USER = 'AgentCore::OAuthUser::"agent-user-1"'
MERCHANT = "0xa27f7cb624b57c79d7f9de03ae9f5c705c2858db"
MERCHANT_2 = "0x2222222222222222222222222222222222222222"  # also allowlisted
ATTACKER = "0x000000000000000000000000000000000000dead"
QUOTE = 'AgentCore::Action::"PaymentsTarget___get_merchant_quote"'
PAY = 'AgentCore::Action::"PaymentsTarget___pay_merchant"'

_rid = [0]


def _common(rid, sid):
    return (f'eventPrincipal: {USER}, eventResource: {GW}, '
            f'requestId: "{rid}", sessionId: "{sid}"')


def quote(t, pay_to, sid="sess-1", url="https://merchant.example/paid-api"):
    """A permitted lookup: request (decision) then its response with payTo."""
    _rid[0] += 1
    rid = f"q{_rid[0]}"
    inp = f'input: {{ resourceUrl: "{url}" }}'
    scope = f"scope(principal: {USER}, resource: {GW})"
    ctx = f'request_context(input: {{ resourceUrl: "{url}" }}, sessionId: "{sid}")'
    return [
        f"@{t} {scope} {ctx} {QUOTE}::request({inp}, {_common(rid, sid)})",
        f'@{t + 1} {scope} {QUOTE}::response({inp}, output: {{ payTo: "{pay_to}", amount: 1000 }}, {_common(rid, sid)})',
    ]


def pay(t, recipient, amount, sid="sess-1"):
    """A payment attempt: the request is the decision point."""
    _rid[0] += 1
    rid = f"p{_rid[0]}"
    inp = f'input: {{ amount: {amount}, recipient: "{recipient}" }}'
    scope = f"scope(principal: {USER}, resource: {GW})"
    ctx = f'request_context({inp}, sessionId: "{sid}")'
    return [f"@{t} {scope} {ctx} {PAY}::request({inp}, {_common(rid, sid)})"]


SCENARIOS = {
    # Lookup, then pay the looked-up, allowlisted merchant a small amount.
    "01_happy_path": quote(0, MERCHANT) + pay(10, MERCHANT, 1000),
    # Injected address: the lookup returned the merchant, the agent pays someone else.
    "02_injected_recipient": quote(0, MERCHANT) + pay(10, ATTACKER, 1000),
    # No lookup at all in this session.
    "03_no_lookup": pay(0, MERCHANT, 1000),
    # The lookup is older than the 15-minute window.
    "04_lookup_expired": quote(0, MERCHANT) + pay(1000, MERCHANT, 1000),
    # Single payment above the $0.50 per-transaction cap.
    "05_over_per_tx_cap": quote(0, MERCHANT) + pay(10, MERCHANT, 600000),
    # A (malicious) lookup returned a non-allowlisted payTo: provenance passes,
    # the Cedar allowlist still forbids it.
    "06_lookup_returns_unlisted": quote(0, ATTACKER) + pay(10, ATTACKER, 1000),
    # Velocity: five payments allowed, the sixth inside 10 minutes denied; after
    # the window passes (and a fresh lookup) payments are allowed again.
    "07_velocity": (quote(0, MERCHANT)
                    + sum((pay(10 + 10 * i, MERCHANT, 1000) for i in range(6)), [])
                    + quote(700, MERCHANT) + pay(710, MERCHANT, 1000)),
    # Rolling cap: $0.50 x3 allowed (total $1.50); the 4th reaches $2.00 -> denied.
    "08_rolling_spend_cap": (quote(0, MERCHANT)
                             + sum((pay(10 + 10 * i, MERCHANT, 500000) for i in range(4)), [])),
    # Caveat: history is per policy session. Three $0.50 payments in sess-A,
    # then a new session sess-B starts with an empty history -> allowed.
    "09_new_session_resets": (quote(0, MERCHANT, sid="sess-A")
                              + sum((pay(10 + 10 * i, MERCHANT, 500000, sid="sess-A") for i in range(3)), [])
                              + quote(100, MERCHANT, sid="sess-B")
                              + pay(110, MERCHANT, 500000, sid="sess-B")),
    # Provenance on its own: MERCHANT_2 is allowlisted, but this session's
    # lookup returned MERCHANT, so paying MERCHANT_2 matches no permit -> denied.
    "10_allowlisted_but_not_looked_up": quote(0, MERCHANT) + pay(10, MERCHANT_2, 1000),
}

if __name__ == "__main__":
    os.makedirs("traces", exist_ok=True)
    for name, lines in SCENARIOS.items():
        with open(os.path.join("traces", f"{name}.log"), "w") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"wrote traces/{name}.log ({len(lines)} events)")
