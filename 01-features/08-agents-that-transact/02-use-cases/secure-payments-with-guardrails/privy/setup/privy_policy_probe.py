"""Probe the Privy policy directly — does the wallet sign what it should, and
refuse what it should not?

Run AFTER `setup/privy_policy_setup.py` has attached the policy. This sends
`eth_signTypedData_v4` requests for EIP-3009 `TransferWithAuthorization`
messages straight to the wallet's Privy RPC endpoint, signed with the same
authorization key AgentCore uses, and checks each verdict:

  allowed merchant, small value, Base Sepolia        -> must be SIGNED
  same, recipient in lowercase                        -> must be SIGNED
  non-allowlisted recipient                           -> must be DENIED
  value above the per-transaction cap                 -> must be DENIED
  wrong chain (Base mainnet, 8453)                    -> must be DENIED

Each case is sent twice: with and without `EIP712Domain` in the request's
`types`, because Privy matches typed-data conditions only on an exact `types`
match. If the allowed cases come back DENIED, the typed-data conditions are not
matching the request shape and the policy is blocking every payment.

Safe by construction: every message has `validBefore = 1` (1970-01-01), so any
signature produced is already expired and cannot be submitted on-chain. No
funds move, and nothing goes through AgentCore.

Requires: delegation completed (the authorization key is a signer on the
wallet), PRIVY_* credentials in .env, and PRIVY_WALLET_ID or WALLET_ADDRESS.

    python setup/privy_policy_probe.py              # wallet from .env
    python setup/privy_policy_probe.py <wallet_id>  # any wallet the key can sign for
"""

import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

from dotenv import load_dotenv

from utils import ENV_FILE

load_dotenv(ENV_FILE, override=True)

from privy_client import EIP712_DOMAIN, TRANSFER_WITH_AUTHORIZATION, PrivyClient, PrivyError  # noqa: E402
from privy_policy_setup import PER_TX_CAP_USD, RECIPIENT_ALLOWLIST, resolve_wallet  # noqa: E402

BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
NOT_ALLOWLISTED = "0x000000000000000000000000000000000000dEaD"
SMALL = 1000                                             # $0.001
OVER_CAP = int(round(PER_TX_CAP_USD * 1_000_000)) + 100_000


def typed_data(wallet_address, to, value, chain_id, with_domain_type):
    types = {"TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION}
    if with_domain_type:
        types = {"EIP712Domain": EIP712_DOMAIN, **types}
    return {
        "types": types,
        "primary_type": "TransferWithAuthorization",
        "domain": {"name": "USDC", "version": "2", "chainId": chain_id,
                   "verifyingContract": BASE_SEPOLIA_USDC},
        "message": {"from": wallet_address, "to": to, "value": str(value),
                    "validAfter": "0", "validBefore": "1",          # already expired
                    "nonce": "0x" + secrets.token_hex(32)},
    }


def attempt(privy, wallet, td):
    try:
        out = privy.rpc(wallet["id"], {"method": "eth_signTypedData_v4", "params": {"typed_data": td}})
        return "SIGNED" if out.get("data", {}).get("signature") else f"UNEXPECTED {out}"
    except PrivyError as e:
        if "policy" in e.text.lower():
            return "DENIED"
        return f"ERROR {e.status}: {e.text[:160]}"


def main(wallet_id=None) -> int:
    privy = PrivyClient.from_env()
    wallet = resolve_wallet(privy, wallet_id)
    addr = wallet["address"]
    merchant = RECIPIENT_ALLOWLIST[0]
    print(f"Wallet {wallet['id']} ({addr})  policy_ids={wallet.get('policy_ids') or []}")
    if not (wallet.get("policy_ids") or any(s.get("override_policy_ids")
                                            for s in wallet.get("additional_signers") or [])):
        print("WARNING: no policy attached — every case below is expected to sign. "
              "Run setup/privy_policy_setup.py first.")

    cases = [
        ("allowlisted merchant, $0.001, Base Sepolia", merchant, SMALL, 84532, "SIGNED"),
        ("same, recipient lowercase", merchant.lower(), SMALL, 84532, "SIGNED"),
        ("non-allowlisted recipient", NOT_ALLOWLISTED, SMALL, 84532, "DENIED"),
        (f"over the ${PER_TX_CAP_USD:.2f} cap", merchant, OVER_CAP, 84532, "DENIED"),
        ("wrong chain (Base mainnet 8453)", merchant, SMALL, 8453, "DENIED"),
    ]
    failures = 0
    for with_domain in (True, False):
        print(f"\nRequest types {'WITH' if with_domain else 'WITHOUT'} EIP712Domain:")
        for label, to, value, chain, want in cases:
            got = attempt(privy, wallet, typed_data(addr, to, value, chain, with_domain))
            ok = got == want
            failures += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {label:45} expected {want:7} got {got}")

    print("\nAll cases matched the policy." if not failures else
          f"\n{failures} case(s) did not match. If allowed cases were DENIED, the policy's "
          "typed-data `types` do not match what the signer sends — the policy blocks every payment.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) == 2 else None))
