# Delegation frontend patch — attach the Privy policy to the agent signer

AgentCore creates a **user-owned** Privy embedded wallet. Only the wallet's owner
can put a policy on it, and the moment the user does so is **delegation**: in
Privy's [AgentCore SDK frontend](https://github.com/privy-io/aws-agentcore-sdk),
the **Connect agent** button adds your app's authorization key as a signer:

```ts
addSessionSigners({ address, signers: [{ signerId, policyIds: [] }] })
```

`policyIds` becomes the signer's `override_policy_ids` — the policies Privy
evaluates whenever the agent signs. Upstream passes an empty list, so the agent
signs with no wallet-level restriction. This patch changes two files:

| File | Change |
|---|---|
| `src/components/modals/connect-agent-modal.tsx` | pass the sample's policy in `policyIds`; if Privy reports the signer already exists, remove it and add it again with the policy (re-adding an existing signer is otherwise a no-op) |
| `src/app/api/check-signers/route.ts` | report the agent as connected only when the signer exists **and** carries the policy, so the **Connect agent** button reappears for a signer that was added without it |

The policy ID is a placeholder (`__PRIVY_POLICY_ID__`) filled in from the sample's
`.env` by `setup_frontend.sh`. The patch was tested against upstream commit
`c667b220c2579b20f7c5f6e32d2898840b7c7fca`.

## Use it

From the `privy/` sample folder, after `setup/privy_policy_setup.py` has written
`PRIVY_POLICY_ID` to `.env`:

```bash
bash frontend-patch/setup_frontend.sh            # default target: ../privy-agentcore-frontend
cd ../privy-agentcore-frontend && npx -y pnpm@9 dev
```

The script clones the pinned commit, applies the patch with your policy ID, writes
`.env.local` (`NEXT_PUBLIC_PRIVY_APP_ID`, `NEXT_PUBLIC_PRIVY_SIGNER_ID`,
`NEXT_PUBLIC_NETWORK_MODE=testnet`, `PRIVY_APP_SECRET`; mode 600), and installs
dependencies.

Then add `http://localhost:3000` to the Privy app's allowed origins, open it, log in
as the wallet's user, and click **Connect agent**. Verify with
`python setup/privy_policy_probe.py`.

To apply the patch by hand instead:

```bash
sed "s/__PRIVY_POLICY_ID__/<your-policy-id>/g" attach-policy.patch | git apply
```

## Notes

- The browser console shows Content Security Policy errors for
  `explorer-api.walletconnect.com`. They come from the frontend's own CSP blocking
  WalletConnect's wallet directory and do not affect login or **Connect agent**.
- Privy's embedded wallets need a secure context, so open the app on `localhost`
  (tunnel the port if it runs on another host: `ssh -N -L 3000:127.0.0.1:3000 <host>`),
  not on a plain-HTTP hostname.
- `.env.local` holds the app secret. Don't commit it.
