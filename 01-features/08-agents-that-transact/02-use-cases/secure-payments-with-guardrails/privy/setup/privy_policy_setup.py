"""Optional — attach a Privy signing-layer policy to the embedded wallet.

This is the fail-secure backstop of the recipient + per-transaction guardrails,
the Stripe/Privy analogue of the Coinbase CDP policy. Privy evaluates every
signing request against the policies attached to the wallet (`policy_ids`).
Within a method, a request that matches no ALLOW rule is denied, and an
unlisted method defaults to DENY.

x402's EVM "exact" scheme signs an EIP-3009 `TransferWithAuthorization` as
EIP-712 typed data via `eth_signTypedData_v4`. The policy allows that method
only when ALL of these hold:

  • domain `chainId`  == 84532 (Base Sepolia)
  • message `to`      in the approved-recipients condition set
  • message `value`   <= the per-transaction cap (USDC base units, as hex)

CRITICAL — exact `types` match. Privy evaluates a typed-data message condition
only when the rule's `types` map equals the signing request's `types` map,
including whether `EIP712Domain` is declared and the field order. On a mismatch
the condition is false. For this ALLOW-only policy a mismatch denies the payment
(fail-closed). Because clients differ on whether they send `EIP712Domain`, the
policy carries two otherwise-identical ALLOW rules, one per shape. Run
`setup/privy_policy_probe.py` to see which shape your wallet's signer accepts.

Wallet ownership. AgentCore creates a USER-OWNED Privy embedded wallet; the
user's delegation adds the app's authorization key as a signer. Only the owner
can change a wallet's policies, so this script reads the wallet first:
  - no owner, or owned by this authorization key -> attach the policy to the
    wallet's `policy_ids` (signed with the key when it is the owner);
  - owned by the user (the AgentCore case)       -> create the policy but do not
    attach it; print its id. The user attaches it when delegating: in the Privy
    AgentCore SDK frontend, the "Connect agent" step calls
        addSessionSigners({ signers: [{ signerId, policyIds: ["<policy id>"] }] })
    which sets the policy as the agent signer's override policy.

    python setup/privy_policy_setup.py              # wallet found by WALLET_ADDRESS
    python setup/privy_policy_setup.py <wallet_id>

Env knobs:
    RECIPIENT_ALLOWLIST   comma-separated merchant `to` addresses to allow
    PER_TX_CAP_USD        per-transaction USDC cap (converted to 6-dp base units)
    CHAIN_ID              EIP-155 chain id (default 84532, Base Sepolia)

Docs: https://docs.privy.io/controls/policies/overview
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

from dotenv import load_dotenv

from utils import ENV_FILE, require_env, write_env_values

load_dotenv(ENV_FILE, override=True)

from privy_client import (  # noqa: E402
    PrivyClient, PrivyError, eip3009_typed_data, governing_policy_ids, wallet_update_mode,
)

CHAIN_ID = os.environ.get("CHAIN_ID", "84532")

# Merchant recipient(s) to allow — the x402 `payTo`, NOT the token contract.
RECIPIENT_ALLOWLIST = [
    a.strip()
    for a in os.environ.get(
        "RECIPIENT_ALLOWLIST", "0xA27f7cB624B57C79d7F9de03ae9F5C705c2858dB"
    ).split(",")
    if a.strip()
]
PER_TX_CAP_USD = float(os.environ.get("PER_TX_CAP_USD", "0.50"))
# USDC has 6 decimals; Privy compares uint256 typed-data fields given as hex.
PER_TX_CAP_HEX = hex(int(round(PER_TX_CAP_USD * 1_000_000)))


def build_allowlist_rules(condition_set_id, cap_hex=PER_TX_CAP_HEX, chain_id=CHAIN_ID):
    """Two fail-closed ALLOW rules — identical except for the declared `types`
    shape (with and without EIP712Domain), so the policy matches whichever
    shape the signing client sends."""
    rules = []
    for with_domain in (True, False):
        td = eip3009_typed_data(with_domain)
        rules.append({
            # Privy rule names must be fewer than 50 characters.
            "name": f"x402 USDC allowlist + cap ({'with' if with_domain else 'no'} EIP712Domain)",
            "method": "eth_signTypedData_v4",
            "action": "ALLOW",
            "conditions": [
                {"field_source": "ethereum_typed_data_domain", "field": "chainId",
                 "operator": "eq", "value": chain_id},
                {"field_source": "ethereum_typed_data_message", "field": "to",
                 "operator": "in_condition_set", "value": condition_set_id, "typed_data": td},
                {"field_source": "ethereum_typed_data_message", "field": "value",
                 "operator": "lte", "value": cap_hex, "typed_data": td},
            ],
        })
    return rules


def resolve_wallet(privy, wallet_id_arg=None):
    wallet_id = wallet_id_arg or os.environ.get("PRIVY_WALLET_ID", "").strip()
    if wallet_id:
        return privy.get_wallet(wallet_id)
    return privy.find_wallet_by_address(require_env("WALLET_ADDRESS"))


def describe_wallet(wallet):
    signers = wallet.get("additional_signers") or []
    print(f"Privy wallet {wallet['id']}  address {wallet.get('address')}")
    print(f"  owner_id:           {wallet.get('owner_id')}")
    print(f"  policy_ids:         {wallet.get('policy_ids') or []}")
    for s in signers:
        print(f"  additional signer:  {s.get('signer_id')}  override_policy_ids="
              f"{s.get('override_policy_ids') or []}")
    auth_id = os.environ.get("PRIVY_AUTHORIZATION_ID", "").strip()
    mine = [s for s in signers if s.get("signer_id") == auth_id]
    if mine and mine[0].get("override_policy_ids"):
        print("  WARNING: the AgentCore signer has override_policy_ids, which apply to its "
              "signing instead of the wallet's policy_ids.")
    if signers and not mine and wallet.get("owner_id") != auth_id:
        print(f"  WARNING: this app's authorization key ({auth_id}) is not a signer on the "
              "wallet — delegation may not be complete.")


def main(wallet_id_arg=None):
    privy = PrivyClient.from_env()
    auth_id = os.environ.get("PRIVY_AUTHORIZATION_ID", "").strip()
    wallet = resolve_wallet(privy, wallet_id_arg)
    describe_wallet(wallet)
    signed, problem = wallet_update_mode(wallet, auth_id)

    set_id = privy.create_condition_set("x402 approved recipients")
    privy.add_condition_set_items(set_id, RECIPIENT_ALLOWLIST)
    print(f"\nCreated approved-recipients condition set {set_id}: {RECIPIENT_ALLOWLIST}")
    try:
        policy_id = privy.create_policy("x402 recipient allowlist and per-tx cap",
                                        build_allowlist_rules(set_id))
    except PrivyError:
        privy.delete_condition_set(set_id)  # don't leave an orphaned condition set behind
        raise
    print(f"Created policy {policy_id}")
    write_env_values(PRIVY_WALLET_ID=wallet["id"], PRIVY_CONDITION_SET_ID=set_id,
                     PRIVY_POLICY_ID=policy_id)

    if problem:  # user-owned wallet: the user attaches the policy at delegation
        print(f"\nThe wallet is owned by {wallet.get('owner_id')}, so this app cannot attach "
              "the policy itself. Attach it when the user delegates signing to the agent:")
        print("  Privy AgentCore SDK frontend (https://github.com/privy-io/aws-agentcore-sdk),")
        print("  src/components/modals/connect-agent-modal.tsx — change")
        print("      signers: [{ signerId, policyIds: [] }]")
        print("  to")
        print(f'      signers: [{{ signerId, policyIds: ["{policy_id}"] }}]')
        print(f"  (signerId = NEXT_PUBLIC_PRIVY_SIGNER_ID = {auth_id}), then log in as the wallet's")
        print("  user and choose Connect agent.")
        if policy_id in governing_policy_ids(wallet, auth_id):
            print("\nThe policy already governs the agent signer.")
        print("\nAfter delegation, verify:  python setup/privy_policy_probe.py")
        return

    current = wallet.get("policy_ids") or []
    try:
        privy.update_wallet(wallet["id"], {"policy_ids": list(dict.fromkeys([*current, policy_id]))},
                            signed=signed)
    except PrivyError:
        privy.delete_policy(policy_id)  # don't leave an orphaned policy behind
        privy.delete_condition_set(set_id)
        raise
    print(f"\nAttached policy {policy_id} to wallet {wallet['id']}"
          f"{' (signed with the authorization key)' if signed else ''}")
    print("  method:          eth_signTypedData_v4 (unmatched => DENY)")
    print(f"  recipient `to`:  in condition set {set_id}")
    print(f"  `value`:         <= {PER_TX_CAP_HEX} base units (${PER_TX_CAP_USD:.2f} USDC)")
    print(f"  domain chainId:  == {CHAIN_ID}")
    print("\nVerify enforcement:  python setup/privy_policy_probe.py")
    print("Remove after testing: python setup/privy_policy_remove.py")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) == 2 else None)
