#!/usr/bin/env bash
# Set up the Privy AgentCore SDK frontend (the end user's wallet hub) so that
# "Connect agent" attaches this sample's Privy policy to the agent signer.
#
# Why: AgentCore creates a USER-OWNED Privy wallet. Only the owner can put a
# policy on it, and the only place the user does that is the delegation step,
# where the frontend calls addSessionSigners({ signers: [{ signerId, policyIds }] }).
# Upstream passes policyIds: [] — this patch passes the sample's policy, re-adds
# the signer if it already exists, and only reports "connected" when the signer
# carries the policy.
#
# Usage (from the privy/ sample folder, after setup/privy_policy_setup.py):
#   bash frontend-patch/setup_frontend.sh [target-dir]
#   cd <target-dir> && npx -y pnpm@9 dev        # http://localhost:3000
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SAMPLE="$(dirname "$HERE")"
TARGET="${1:-$SAMPLE/../privy-agentcore-frontend}"
UPSTREAM="https://github.com/privy-io/aws-agentcore-sdk.git"
PINNED="c667b220c2579b20f7c5f6e32d2898840b7c7fca"   # commit the patch was tested against

env_value() { grep -E "^$1=" "$SAMPLE/.env" | head -1 | cut -d= -f2-; }
POLICY_ID="$(env_value PRIVY_POLICY_ID)"
APP_ID="$(env_value PRIVY_APP_ID)"
SIGNER_ID="$(env_value PRIVY_AUTHORIZATION_ID)"
APP_SECRET="$(env_value PRIVY_APP_SECRET)"
for v in POLICY_ID APP_ID SIGNER_ID APP_SECRET; do
  [ -n "${!v}" ] || { echo "Missing $v in $SAMPLE/.env (run setup/privy_policy_setup.py first)"; exit 1; }
done

if [ ! -d "$TARGET/.git" ]; then
  git clone "$UPSTREAM" "$TARGET"
fi
cd "$TARGET"
git checkout -q "$PINNED"

sed "s/__PRIVY_POLICY_ID__/$POLICY_ID/g" "$HERE/attach-policy.patch" | git apply
echo "Patched: Connect agent attaches policy $POLICY_ID to signer $SIGNER_ID"

umask 077
cat > .env.local <<EOF
NEXT_PUBLIC_PRIVY_APP_ID=$APP_ID
NEXT_PUBLIC_PRIVY_SIGNER_ID=$SIGNER_ID
NEXT_PUBLIC_NETWORK_MODE=testnet
PRIVY_APP_SECRET=$APP_SECRET
EOF
echo "Wrote $TARGET/.env.local (mode 600; holds the app secret — do not commit)"

npx -y pnpm@9 install --frozen-lockfile
cat <<EOF

Next:
  1. In the Privy dashboard, add http://localhost:3000 to the app's allowed origins.
  2. cd $TARGET && npx -y pnpm@9 dev
  3. Open http://localhost:3000, log in as the wallet's user (LINKED_EMAIL), click "Connect agent".
  4. Verify:  python setup/privy_policy_probe.py
EOF
