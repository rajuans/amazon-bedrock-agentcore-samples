"""Optional — attach a Coinbase CDP signing-layer policy to the wallet.

This is the fail-secure backstop of the recipient + per-transaction guardrails:
the CDP Policy Engine evaluates every signing operation and rejects anything no
rule accepts, so a bad payment is refused at signing time even if every upstream
check were bypassed.

x402's EVM "exact" scheme does NOT broadcast a transaction — the wallet signs an
EIP-3009 `TransferWithAuthorization` as **EIP-712 typed data** (`signEvmTypedData`
for a server account, `signEndUserEvmTypedData` for a delegated end-user/embedded
account); the facilitator submits it on-chain. So the correct rule is a
*typed-data* rule whose `SignEvmTypedDataFieldCriterion` matches the message
fields by path:

  • `to`    -> recipient allowlist   (EvmTypedAddressCondition, operator "in")
  • `value` -> per-transaction cap   (EvmTypedNumericalCondition, "<=", base units)

Both conditions work on **testnet**, because they compare raw typed-data fields
(only the `netUSDChange` criterion is mainnet-only). A `signEvmTransaction` rule —
what an earlier version of this script used — would never match, and under the
fail-secure default it would DENY the signing the payment depends on.

Requires the CDP SDK and CDP API credentials for the **project that owns the
wallet**, with policy-management scope:

    pip install cdp-sdk
    export CDP_API_KEY_ID=...       # same values as COINBASE_API_KEY_ID
    export CDP_API_KEY_SECRET=...
    export CDP_WALLET_SECRET=...

Usage:
    python setup/cdp_policy_setup.py <wallet_address>

Env knobs (fall back to .env / the sample defaults):
    RECIPIENT_ALLOWLIST   comma-separated merchant `to` addresses to allow
    PER_TX_CAP_USD        per-transaction USDC cap (converted to 6-dp base units)
    CDP_TYPED_DATA_OP     signEndUserEvmTypedData (default) | signEvmTypedData

Docs: https://docs.cdp.coinbase.com/wallets/security-and-policies/policy-engine/overview
"""

import asyncio
import os
import sys

# Merchant recipient(s) to allow — the x402 `payTo`, NOT the token contract.
RECIPIENT_ALLOWLIST = [
    a.strip()
    for a in os.environ.get(
        "RECIPIENT_ALLOWLIST", "0xA27f7cB624B57C79d7F9de03ae9F5C705c2858dB"
    ).split(",")
    if a.strip()
]
PER_TX_CAP_USD = float(os.environ.get("PER_TX_CAP_USD", "0.50"))
# USDC has 6 decimals; the typed-data `value` field is in base units.
PER_TX_CAP_BASE_UNITS = str(int(round(PER_TX_CAP_USD * 1_000_000)))

# AgentCore embedded wallets are delegated end-user accounts, so the signing
# operation is the EndUser variant by default. Override for a server account.
TYPED_DATA_OP = os.environ.get("CDP_TYPED_DATA_OP", "signEndUserEvmTypedData")

# EIP-3009 TransferWithAuthorization is the message x402 signs for USDC.
EIP3009_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


def _build_rule(recipients=None):
    from cdp.policies.types import (
        EvmTypedAddressCondition,
        EvmTypedNumericalCondition,
        SignEndUserEvmTypedDataRule,
        SignEvmTypedDataFieldCriterion,
        SignEvmTypedDataRule,
        SignEvmTypedDataTypes,
    )

    criterion = SignEvmTypedDataFieldCriterion(
        types=SignEvmTypedDataTypes(
            types=EIP3009_TYPES, primaryType="TransferWithAuthorization"
        ),
        conditions=[
            EvmTypedAddressCondition(
                path="to", operator="in", addresses=recipients or RECIPIENT_ALLOWLIST
            ),
            EvmTypedNumericalCondition(
                path="value", operator="<=", value=PER_TX_CAP_BASE_UNITS
            ),
        ],
    )
    rule_cls = (
        SignEndUserEvmTypedDataRule
        if TYPED_DATA_OP == "signEndUserEvmTypedData"
        else SignEvmTypedDataRule
    )
    return rule_cls(action="accept", operation=TYPED_DATA_OP, criteria=[criterion])


async def main(wallet_address: str) -> None:
    from cdp import CdpClient
    from cdp.policies.types import CreatePolicyOptions
    from cdp.update_account_types import UpdateAccountOptions

    async with CdpClient() as cdp:
        policy = await cdp.policies.create_policy(
            policy=CreatePolicyOptions(
                scope="account",
                description="Secure payment agent x402 recipient and cap",
                rules=[_build_rule()],
            )
        )
        await cdp.evm.update_account(
            address=wallet_address,
            update=UpdateAccountOptions(account_policy=policy.id),
        )
        print(f"Attached CDP policy {policy.id} to {wallet_address}")
        print(f"  operation:        {TYPED_DATA_OP}")
        print(f"  recipient `to` in {RECIPIENT_ALLOWLIST}")
        print(f"  `value` <= {PER_TX_CAP_BASE_UNITS} base units (${PER_TX_CAP_USD:.2f} USDC)")
        print("\nRemove it after testing:  python setup/cdp_policy_remove.py "
              f"{wallet_address} {policy.id}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python setup/cdp_policy_setup.py <wallet_address>")
    asyncio.run(main(sys.argv[1]))
