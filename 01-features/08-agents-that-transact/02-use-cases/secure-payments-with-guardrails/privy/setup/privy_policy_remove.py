"""Remove a Privy policy attached by privy_policy_setup.py.

Cleanup after testing: detach the policy from the wallet (clear it from
`policy_ids`), then delete the policy object. Detach and delete are independent —
detaching leaves the wallet governed by whatever policies remain; deleting
removes the policy object itself.

Requires the same Privy credentials as privy_policy_setup.py.

Usage:
    python setup/privy_policy_remove.py                       # read ids from .env
    python setup/privy_policy_remove.py <wallet_id> <policy_id>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

from dotenv import load_dotenv

from utils import ENV_FILE, require_env

load_dotenv(ENV_FILE, override=True)

from privy_policy_setup import PrivyClient  # noqa: E402


def main(wallet_id=None, policy_id=None):
    privy = PrivyClient()
    wallet_id = wallet_id or require_env("PRIVY_WALLET_ID")
    policy_id = policy_id or require_env("PRIVY_POLICY_ID")

    # 1) Detach: remove this policy from the wallet's policy_ids.
    remaining = [p for p in privy.get_wallet(wallet_id).get("policy_ids", []) if p != policy_id]
    privy.attach_policy(wallet_id, remaining)
    print(f"Detached policy {policy_id} from wallet {wallet_id} (remaining: {remaining})")

    # 2) Delete the policy object.
    privy.delete_policy(policy_id)
    print(f"Deleted policy {policy_id}")
    print("(The condition set is left in place; delete it from the Privy dashboard if unused.)")


if __name__ == "__main__":
    args = sys.argv[1:]
    main(args[0] if len(args) >= 1 else None, args[1] if len(args) >= 2 else None)
