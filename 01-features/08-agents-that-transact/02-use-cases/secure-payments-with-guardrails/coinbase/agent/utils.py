"""Small helpers shared by the setup scripts and the agent.

Deliberately minimal — anything the AgentCore Payments SDK already does
(sessions, instruments, balances) is called directly, not re-wrapped here.
"""

import os
import time
import uuid

from dotenv import load_dotenv

# Repo root = one directory up from this file (agent/ -> repo/).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(REPO_ROOT, ".env")


def client_token() -> str:
    """A fresh idempotency token for create_* calls (retry-safe)."""
    return str(uuid.uuid4())


def require_env(key: str) -> str:
    """Return a required env var, or raise a clear error for unset/placeholder values."""
    val = os.environ.get(key, "").strip()
    if not val or val.startswith("<"):
        raise ValueError(
            f"Missing or placeholder value for {key} in {ENV_FILE}. "
            f"Complete the setup steps in the README first."
        )
    return val


def load_env() -> dict:
    """Load .env and return the resolved config the agent needs."""
    load_dotenv(ENV_FILE, override=True)
    return {
        "region": require_env("AWS_REGION"),
        "payment_manager_arn": require_env("PAYMENT_MANAGER_ARN"),
        "payment_connector_id": os.environ.get("PAYMENT_CONNECTOR_ID", "").strip(),
        "instrument_id": require_env("INSTRUMENT_ID"),
        "user_id": require_env("USER_ID"),
        "network": os.environ.get("NETWORK", "ETHEREUM").strip(),
        "session_budget_usd": os.environ.get("SESSION_BUDGET_USD", "1.00").strip(),
        "per_tx_cap_usd": float(os.environ.get("PER_TX_CAP_USD", "0.50")),
        "recipient_allowlist": [
            a.strip().lower()
            for a in os.environ.get("RECIPIENT_ALLOWLIST", "").split(",")
            if a.strip()
        ],
    }


def idempotent_create(create_fn, conflict_msg: str = "already exists", **kwargs):
    """Call a control-plane create_* API, tolerating a re-run.

    Returns the API response, or None if the resource already existed
    (``ConflictException``, or ``ValidationException`` "already exists").
    Any other error propagates.
    """
    from botocore.exceptions import ClientError

    try:
        return create_fn(**kwargs)
    except ClientError as e:
        err = e.response.get("Error", {})
        # Most create_* calls return ConflictException for an existing resource;
        # CreatePaymentCredentialProvider returns ValidationException "... already exists".
        if err.get("Code") == "ConflictException" or (
            err.get("Code") == "ValidationException" and "already exists" in err.get("Message", "")
        ):
            print(f"  (skip) {conflict_msg}")
            return None
        raise


def wait_for_status(get_fn, expected: str, *, poll_interval: int = 5,
                    timeout: int = 180, **kwargs) -> dict:
    """Poll a Get* API until ``status`` reaches ``expected``.

    Raises on any ``*_FAILED`` status and on timeout. Reads the status from
    the top-level ``status`` field or a nested ``paymentInstrument.status``.
    """
    deadline = time.monotonic() + timeout
    while True:
        resp = get_fn(**kwargs)
        status = resp.get("status") or resp.get("paymentInstrument", {}).get("status")
        if status == expected:
            return resp
        if status and status.endswith("_FAILED"):
            raise RuntimeError(f"Reached terminal status {status} (wanted {expected})")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Timed out waiting for {expected} (last status: {status})")
        print(f"  … status={status}, waiting {poll_interval}s")
        time.sleep(poll_interval)


def print_summary(title: str, **fields) -> None:
    print(f"\n── {title} ──")
    for k, v in fields.items():
        print(f"  {k:24}: {v}")


def write_env_values(**pairs) -> None:
    """Upsert KEY=value pairs into the repo .env (used by the setup scripts)."""
    lines = []
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as fh:
            lines = fh.read().splitlines()
    keys = set(pairs)
    out, seen = [], set()
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            key = line.split("=", 1)[0].strip()
            if key in keys:
                out.append(f"{key}={pairs[key]}")
                seen.add(key)
                continue
        out.append(line)
    for key in keys - seen:
        out.append(f"{key}={pairs[key]}")
    with open(ENV_FILE, "w") as fh:
        fh.write("\n".join(out) + "\n")
