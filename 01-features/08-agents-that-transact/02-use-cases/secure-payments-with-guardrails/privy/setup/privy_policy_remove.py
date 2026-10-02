"""Remove a Privy policy attached by privy_policy_setup.py.

Cleanup after testing: detach the policy from the wallet (drop it from
`policy_ids`), then delete the policy object and its condition set. Uses a
signed request when the wallet is owned by this app's authorization key.

Usage:
    python setup/privy_policy_remove.py                       # ids from .env
    python setup/privy_policy_remove.py <wallet_id> <policy_id>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

from dotenv import load_dotenv

from utils import ENV_FILE, require_env, write_env_values

load_dotenv(ENV_FILE, override=True)

from privy_client import PrivyClient, PrivyError, governing_policy_ids, wallet_update_mode  # noqa: E402


def main(wallet_id=None, policy_id=None):
    privy = PrivyClient.from_env()
    wallet = privy.get_wallet(wallet_id or require_env("PRIVY_WALLET_ID"))
    policy_id = policy_id or require_env("PRIVY_POLICY_ID")

    auth_id = os.environ.get("PRIVY_AUTHORIZATION_ID", "").strip()
    signed, problem = wallet_update_mode(wallet, auth_id)
    if policy_id in (wallet.get("policy_ids") or []):
        if problem:
            raise SystemExit(f"Cannot detach the policy: {problem}")
        remaining = [p for p in wallet["policy_ids"] if p != policy_id]
        privy.update_wallet(wallet["id"], {"policy_ids": remaining}, signed=signed)
        print(f"Detached policy {policy_id} from wallet {wallet['id']} (remaining: {remaining})")
    elif policy_id in governing_policy_ids(wallet, auth_id):
        # Set as the agent signer's policy at delegation; only the wallet's user can
        # change that. Deleting it underneath the signer would break the agent's signing.
        raise SystemExit(
            f"Policy {policy_id} is the agent signer's policy, set when the user delegated. "
            "Have the user remove the agent (or re-delegate without the policy) in the "
            "Privy AgentCore SDK frontend, then run this script again to delete it.")

    privy.delete_policy(policy_id)
    print(f"Deleted policy {policy_id}")

    set_id = os.environ.get("PRIVY_CONDITION_SET_ID", "").strip()
    if set_id:
        try:
            privy.delete_condition_set(set_id)
            print(f"Deleted condition set {set_id}")
        except PrivyError as e:
            print(f"(condition set {set_id} not deleted: {e.status})")
    write_env_values(PRIVY_POLICY_ID="", PRIVY_CONDITION_SET_ID="")


if __name__ == "__main__":
    args = sys.argv[1:]
    main(args[0] if len(args) >= 1 else None, args[1] if len(args) >= 2 else None)
