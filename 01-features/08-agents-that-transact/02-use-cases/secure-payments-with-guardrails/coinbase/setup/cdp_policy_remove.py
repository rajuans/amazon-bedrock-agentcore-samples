"""Remove a Coinbase CDP policy attached by cdp_policy_setup.py.

Cleanup after testing: detach the policy from the account, then delete the
policy object. Detach and delete are independent — detaching leaves the account
with no account-scoped policy (project-scoped rules, if any, still apply);
deleting removes the policy object itself.

Requires the same CDP credentials (for the project that owns the wallet) as
cdp_policy_setup.py.

Usage:
    python setup/cdp_policy_remove.py <wallet_address> [policy_id]

If policy_id is omitted, the account is detached from whatever account-scoped
policy it currently has (read from the account), and that policy is deleted.
"""

import asyncio
import sys


async def main(wallet_address: str, policy_id: str | None) -> None:
    from cdp import CdpClient
    from cdp.update_account_types import UpdateAccountOptions

    async with CdpClient() as cdp:
        # Resolve the currently attached policy if not supplied.
        if not policy_id:
            acct = await cdp.evm.get_account(address=wallet_address)
            policy_id = getattr(acct, "policies", None) or getattr(
                acct, "account_policy", None
            )
            if not policy_id:
                print(f"No account-scoped policy attached to {wallet_address}.")
                return

        # 1) Detach: clear the account's policy reference.
        await cdp.evm.update_account(
            address=wallet_address,
            update=UpdateAccountOptions(account_policy=""),
        )
        print(f"Detached policy from {wallet_address}")

        # 2) Delete the policy object.
        await cdp.policies.delete_policy(id=policy_id)
        print(f"Deleted policy {policy_id}")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("Usage: python setup/cdp_policy_remove.py <wallet_address> [policy_id]")
    asyncio.run(main(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None))
