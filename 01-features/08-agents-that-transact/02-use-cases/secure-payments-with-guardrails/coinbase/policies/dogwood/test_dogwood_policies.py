"""Test the Dogwood payment guardrails locally with the `dogwood` CLI.

Validates payment_guardrails.dw, then replays each trace in traces/ and checks
the verdict for every decision point against the expectations below. No AWS
calls — the CLI evaluates the policy set with the same semantics AgentCore uses
for temporal policies.

Install the CLI (Rust toolchain required):
    git clone https://github.com/dogwood-policy/dogwood && cd dogwood
    cargo build --release -p amzn-dogwood-cli    # binary: target/release/dogwood

Run:
    DOGWOOD=/path/to/dogwood python test_dogwood_policies.py
    # or put `dogwood` on PATH

Exit code 0 = every scenario matched; 1 = a mismatch or validation failure.
"""

import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(HERE, "payment_guardrails.dw")
ACTION_SCHEMA = os.path.join(HERE, "schema.cedarschema")
EVENT_SCHEMA = os.path.join(HERE, "agentcore.dwschema")

A, D = "ALLOW", "DENY"
Q = "quote"  # the get_merchant_quote lookup (always allowed)

# Expected verdict for each decision point, in order. `quote` marks a lookup.
EXPECTED = {
    "01_happy_path":                    [Q, A],
    "02_injected_recipient":            [Q, D],
    "03_no_lookup":                     [D],
    "04_lookup_expired":                [Q, D],
    "05_over_per_tx_cap":               [Q, D],
    "06_lookup_returns_unlisted":       [Q, D],
    "07_velocity":                      [Q, A, A, A, A, A, D, Q, A],
    "08_rolling_spend_cap":             [Q, A, A, A, D],
    "09_new_session_resets":            [Q, A, A, A, Q, A],
    "10_allowlisted_but_not_looked_up": [Q, D],
}

DESCRIPTIONS = {
    "01_happy_path":                    "pay the looked-up, allowlisted merchant $0.001",
    "02_injected_recipient":            "pay an address the lookup never returned",
    "03_no_lookup":                     "pay with no lookup in the session",
    "04_lookup_expired":                "pay 16+ minutes after the lookup",
    "05_over_per_tx_cap":               "single payment of $0.60 (> $0.50 cap)",
    "06_lookup_returns_unlisted":       "lookup returns a non-allowlisted payTo",
    "07_velocity":                      "6th payment within 10 minutes; allowed again after",
    "08_rolling_spend_cap":             "4th $0.50 payment reaches $2.00 in an hour",
    "09_new_session_resets":            "caveat: a new policy session starts a new count",
    "10_allowlisted_but_not_looked_up": "allowlisted address, but not this session's lookup",
}

# The point-in-time Cedar policy (../agentcore_policy.cedar) on the same traces.
# It has no lookup tool permit and no history, so the lookup is denied and a
# payment with no lookup is allowed — the gap the temporal rules close.
CEDAR_POLICY = os.path.join(os.path.dirname(HERE), "agentcore_policy.cedar")
CEDAR_EXPECTED = {
    "01_happy_path":         [D, A],
    "02_injected_recipient": [D, D],
    "03_no_lookup":          [A],
    "05_over_per_tx_cap":    [D, D],
}

VERDICT_RE = re.compile(r"^@\d+ \(time point \d+\): (ALLOW|DENY)")


def find_cli():
    cli = os.environ.get("DOGWOOD") or shutil.which("dogwood")
    if not cli:
        sys.exit("dogwood CLI not found. Set DOGWOOD=/path/to/dogwood or add it to PATH.")
    return cli


def run(cli, *args):
    return subprocess.run([cli, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)


def main():
    cli = find_cli()
    common = ["--policy-schema", ACTION_SCHEMA, "--event-schema", EVENT_SCHEMA]

    v = run(cli, "validate", POLICY, *common)
    print(f"validate: {v.stdout.strip()}")
    if v.returncode != 0:
        return 1

    failures = 0
    for name, expected in EXPECTED.items():
        trace = os.path.join(HERE, "traces", f"{name}.log")
        r = run(cli, "replay", POLICY, *common, "--trace", trace)
        got = [m.group(1) for m in map(VERDICT_RE.match, r.stdout.splitlines()) if m]
        # A lookup is a decision point too; it must be ALLOW.
        want = [A if e == Q else e for e in expected]
        ok = r.returncode == 0 and got == want
        payments = [g for g, e in zip(got, expected) if e != Q]
        print(f"{'PASS' if ok else 'FAIL'}  {name:34} {DESCRIPTIONS[name]:52} {' '.join(payments)}")
        if not ok:
            failures += 1
            print(f"      expected {want}\n      got      {got}\n{r.stdout}")

    print("\nPoint-in-time Cedar policy (../agentcore_policy.cedar):")
    v = run(cli, "validate", CEDAR_POLICY, "--policy-schema", ACTION_SCHEMA)
    print(f"validate: {v.stdout.strip()}")
    failures += v.returncode != 0
    for name, want in CEDAR_EXPECTED.items():
        trace = os.path.join(HERE, "traces", f"{name}.log")
        r = run(cli, "replay", CEDAR_POLICY, *common, "--trace", trace)
        got = [m.group(1) for m in map(VERDICT_RE.match, r.stdout.splitlines()) if m]
        ok = r.returncode == 0 and got == want
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:34} {' '.join(got)}")

    total = len(EXPECTED) + len(CEDAR_EXPECTED) + 1
    print(f"\n{total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
