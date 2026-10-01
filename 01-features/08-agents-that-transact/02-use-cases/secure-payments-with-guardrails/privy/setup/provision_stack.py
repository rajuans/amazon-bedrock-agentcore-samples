"""Step 1 of setup — provision the shared AgentCore Payments stack with boto3.

This is the programmatic equivalent of the AgentCore CLI dance
(`agentcore add payment-manager` / `add payment-connector`). Modeled on the
public awslabs sample `agents-that-transact / 00-setup-agentcore-payments`
(the raw-boto3, 4-role IAM-separation reference), but wired to **Stripe (Privy)**
as the wallet provider instead of Coinbase CDP.

It creates, idempotently:
  1. four least-privilege IAM roles (privilege separation, see below),
  2. a Stripe (Privy) **payment credential provider** (holds the Privy secrets),
  3. a **payment manager** (AWS_IAM authorizer, execution role = the
     resource-retrieval role), waits for READY,
  4. a **payment connector** wiring the manager to the Privy credential provider,
     waits for READY,
and writes the resulting ARNs/IDs into .env.

Run this BEFORE `setup/provision_payments.py` (which creates the per-user wallet
+ budgeted session on top of the stack this script provisions).

    python setup/provision_stack.py

The four roles (why separate — no single persona can do everything):
  * ControlPlaneRole    — create/manage managers, connectors, credential
                          providers; write secrets; PassRole the exec role.
  * ManagementRole      — create instruments + sessions; explicitly DENIED
                          ProcessPayment.
  * ProcessPaymentRole  — the agent runtime persona: ProcessPayment + reads.
  * ResourceRetrievalRole — the manager's execution role (service-trusted);
                          reads secrets + issues workload/payment tokens.

Docs: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/payments-getting-started.html
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

from utils import (
    ENV_FILE,
    client_token,
    idempotent_create,
    print_summary,
    require_env,
    wait_for_status,
    write_env_values,
)

load_dotenv(ENV_FILE, override=True)

REGION = os.environ.get("AWS_REGION", "us-west-2").strip()
CREDENTIAL_PROVIDER_TYPE = os.environ.get("CREDENTIAL_PROVIDER_TYPE", "StripePrivy").strip()

MANAGER_NAME = os.environ.get("PAYMENT_MANAGER_NAME", "SecurePaymentManagerPrivy").strip()
CONNECTOR_NAME = os.environ.get("PAYMENT_CONNECTOR_NAME", "PrivyConnector").strip()
CRED_PROVIDER_NAME = os.environ.get("CREDENTIAL_PROVIDER_NAME", "PrivyCredentialProvider").strip()

# IAM role names (the 4-role privilege separation from the awslabs sample).
CONTROL_PLANE_ROLE = "AgentCorePaymentsControlPlaneRole"
MANAGEMENT_ROLE = "AgentCorePaymentsManagementRole"
PROCESS_PAYMENT_ROLE = "AgentCorePaymentsProcessPaymentRole"
RESOURCE_RETRIEVAL_ROLE = "AgentCorePaymentsResourceRetrievalRole"

SERVICE_PRINCIPAL = "bedrock-agentcore.amazonaws.com"


# ── IAM roles ────────────────────────────────────────────────────────────────
def _statement(sid, actions, resource, effect="Allow", condition=None):
    stmt = {"Sid": sid, "Effect": effect, "Action": actions, "Resource": resource}
    if condition:
        stmt["Condition"] = condition
    return stmt


def _ensure_role(iam, name, trust_policy, inline_policies):
    """Create the role (or update its trust policy if it exists); (re)put inline
    policies. Returns (role_arn, created)."""
    created = False
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust_policy))
        print(f"  role {name}: exists (trust updated)")
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Secure payment agent — AgentCore Payments (sample)",
        )["Role"]["Arn"]
        created = True
        print(f"  role {name}: created")
    for policy_name, doc in inline_policies.items():
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    return arn, created


def setup_payment_roles(session):
    """Idempotently create the four payment roles; return {role_key: arn}."""
    iam = session.client("iam")
    sts = session.client("sts")
    ident = sts.get_caller_identity()
    account_id = ident["Account"]
    caller_arn = ident["Arn"]

    # Let the current caller (and the account) assume the "human/agent" roles.
    account_principals = [f"arn:aws:iam::{account_id}:root"]
    if ":assumed-role/" in caller_arn:
        role_name = caller_arn.split(":assumed-role/")[1].split("/")[0]
        account_principals.append(f"arn:aws:iam::{account_id}:role/{role_name}")
    account_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": account_principals},
                       "Action": "sts:AssumeRole"}],
    }
    # The manager's execution role is assumed by the service, scoped to this account.
    service_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": SERVICE_PRINCIPAL},
                       "Action": "sts:AssumeRole",
                       "Condition": {"StringEquals": {"aws:SourceAccount": account_id}}}],
    }

    ac_resource = f"arn:aws:bedrock-agentcore:{REGION}:{account_id}:*"
    secrets_resource = f"arn:aws:secretsmanager:*:{account_id}:secret:*"
    retrieval_role_arn = f"arn:aws:iam::{account_id}:role/{RESOURCE_RETRIEVAL_ROLE}"

    # 4) Resource-retrieval (manager execution) role — service-trusted.
    retrieval_arn, r4 = _ensure_role(iam, RESOURCE_RETRIEVAL_ROLE, service_trust, {
        "AllowPolicy": {"Version": "2012-10-17", "Statement": [
            _statement("PaymentTokens", [
                "bedrock-agentcore:GetWorkloadAccessToken",
                "bedrock-agentcore:CreateWorkloadIdentity",
                "bedrock-agentcore:GetResourcePaymentToken",
            ], ac_resource),
            _statement("ReadSecrets", ["secretsmanager:GetSecretValue"], secrets_resource),
            _statement("SetContext", ["sts:SetContext"], f"arn:aws:sts::{account_id}:self"),
        ]},
    })

    # 1) Control-plane role — manages managers/connectors/credential providers.
    control_arn, _ = _ensure_role(iam, CONTROL_PLANE_ROLE, account_trust, {
        "AllowPolicy": {"Version": "2012-10-17", "Statement": [
            _statement("ManageStack", [
                "bedrock-agentcore:CreatePaymentManager", "bedrock-agentcore:GetPaymentManager",
                "bedrock-agentcore:ListPaymentManagers", "bedrock-agentcore:UpdatePaymentManager",
                "bedrock-agentcore:DeletePaymentManager",
                "bedrock-agentcore:CreatePaymentConnector", "bedrock-agentcore:GetPaymentConnector",
                "bedrock-agentcore:ListPaymentConnectors", "bedrock-agentcore:UpdatePaymentConnector",
                "bedrock-agentcore:DeletePaymentConnector",
                "bedrock-agentcore:CreatePaymentCredentialProvider",
                "bedrock-agentcore:GetPaymentCredentialProvider",
                "bedrock-agentcore:ListPaymentCredentialProviders",
                "bedrock-agentcore:UpdatePaymentCredentialProvider",
                "bedrock-agentcore:DeletePaymentCredentialProvider",
                "bedrock-agentcore:CreateTokenVault",
            ], ac_resource),
        ]},
        # CreateSecret targets not-yet-existing secrets, so it needs "*".
        "SecretsManagerWrite": {"Version": "2012-10-17", "Statement": [
            _statement("WriteSecrets", [
                "secretsmanager:CreateSecret", "secretsmanager:PutSecretValue",
                "secretsmanager:UpdateSecret", "secretsmanager:DeleteSecret",
                "secretsmanager:TagResource",
            ], "*"),
        ]},
        "PassRolePolicy": {"Version": "2012-10-17", "Statement": [
            _statement("PassExecRole", ["iam:PassRole"], retrieval_role_arn,
                       condition={"StringEquals": {"iam:PassedToService": SERVICE_PRINCIPAL}}),
        ]},
    })

    # 2) Management role — instruments + sessions, but NOT ProcessPayment.
    mgmt_arn, _ = _ensure_role(iam, MANAGEMENT_ROLE, account_trust, {
        "AllowPolicy": {"Version": "2012-10-17", "Statement": [
            _statement("ManageInstrumentsAndSessions", [
                "bedrock-agentcore:CreatePaymentInstrument", "bedrock-agentcore:GetPaymentInstrument",
                "bedrock-agentcore:ListPaymentInstruments", "bedrock-agentcore:DeletePaymentInstrument",
                "bedrock-agentcore:GetPaymentInstrumentBalance",
                "bedrock-agentcore:CreatePaymentSession", "bedrock-agentcore:GetPaymentSession",
                "bedrock-agentcore:ListPaymentSessions", "bedrock-agentcore:UpdatePaymentSession",
            ], ac_resource),
        ]},
        "DenyProcessPayment": {"Version": "2012-10-17", "Statement": [
            _statement("NoProcessPayment", ["bedrock-agentcore:ProcessPayment"], "*", effect="Deny"),
        ]},
    })

    # 3) Process-payment role — the agent runtime persona.
    process_arn, _ = _ensure_role(iam, PROCESS_PAYMENT_ROLE, account_trust, {
        "AllowPolicy": {"Version": "2012-10-17", "Statement": [
            _statement("Pay", [
                "bedrock-agentcore:ProcessPayment", "bedrock-agentcore:GetPaymentInstrument",
                "bedrock-agentcore:GetPaymentInstrumentBalance", "bedrock-agentcore:GetPaymentSession",
            ], ac_resource),
        ]},
    })

    if r4:
        print("  waiting 10s for IAM role propagation …")
        time.sleep(10)

    return {
        "CONTROL_PLANE_ROLE_ARN": control_arn,
        "MANAGEMENT_ROLE_ARN": mgmt_arn,
        "PROCESS_PAYMENT_ROLE_ARN": process_arn,
        "RESOURCE_RETRIEVAL_ROLE_ARN": retrieval_arn,
    }


def _assume(session, role_arn):
    """Assume a role for least-privilege control-plane calls; fall back to the
    caller's own session if assumption fails (e.g. still propagating)."""
    try:
        creds = session.client("sts").assume_role(
            RoleArn=role_arn, RoleSessionName="provision-stack"
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=REGION,
        )
    except ClientError as e:
        print(f"  (note) could not assume {role_arn.split('/')[-1]} "
              f"({e.response['Error']['Code']}); using caller credentials")
        return session


# ── Credential provider config (Stripe / Privy) ──────────────────────────────
def _provider_config():
    if CREDENTIAL_PROVIDER_TYPE != "StripePrivy":
        raise ValueError(f"This script provisions StripePrivy; got {CREDENTIAL_PROVIDER_TYPE}")
    # The P-256 authorization private key must be the RAW base64 value — strip
    # any "wallet-auth:" prefix Privy prepends when it displays the key.
    auth_key = require_env("PRIVY_AUTHORIZATION_PRIVATE_KEY")
    if auth_key.startswith("wallet-auth:"):
        raise ValueError(
            "PRIVY_AUTHORIZATION_PRIVATE_KEY must NOT start with 'wallet-auth:'. "
            "Store only the raw base64 value."
        )
    return {"stripePrivyConfiguration": {
        "appId": require_env("PRIVY_APP_ID"),
        "appSecret": require_env("PRIVY_APP_SECRET"),
        "authorizationId": require_env("PRIVY_AUTHORIZATION_ID"),
        "authorizationPrivateKey": auth_key,
    }}


def main():
    base = boto3.Session(region_name=REGION)

    print("1) IAM roles (privilege separation):")
    roles = setup_payment_roles(base)
    write_env_values(**roles)

    # Control-plane calls run under the least-privilege control-plane role.
    cp_session = _assume(base, roles["CONTROL_PLANE_ROLE_ARN"])
    cp = cp_session.client("bedrock-agentcore-control", region_name=REGION)

    print("\n2) Payment credential provider (Stripe / Privy):")
    provider = idempotent_create(
        cp.create_payment_credential_provider,
        conflict_msg=f"credential provider {CRED_PROVIDER_NAME} exists",
        name=CRED_PROVIDER_NAME,
        credentialProviderVendor=CREDENTIAL_PROVIDER_TYPE,
        providerConfigurationInput=_provider_config(),
    )
    if provider is None:
        cred_arn = require_env("CREDENTIAL_PROVIDER_ARN")  # reuse from a prior run
    else:
        cred_arn = provider["credentialProviderArn"]
    print(f"   credentialProviderArn: {cred_arn}")

    print("\n3) Payment manager (authorizer AWS_IAM):")
    manager = idempotent_create(
        cp.create_payment_manager,
        conflict_msg=f"payment manager {MANAGER_NAME} exists",
        name=MANAGER_NAME,
        description=f"{MANAGER_NAME} secure payment agent",
        authorizerType="AWS_IAM",
        roleArn=roles["RESOURCE_RETRIEVAL_ROLE_ARN"],
        clientToken=client_token(),
    )
    if manager is None:
        manager_arn = require_env("PAYMENT_MANAGER_ARN")
        manager_id = manager_arn.split("/")[-1]
    else:
        manager_arn, manager_id = manager["paymentManagerArn"], manager["paymentManagerId"]
    print(f"   paymentManagerId: {manager_id}")
    wait_for_status(cp.get_payment_manager, "READY", paymentManagerId=manager_id)
    print("   manager READY")

    write_env_values(
        AWS_REGION=REGION,
        CREDENTIAL_PROVIDER_TYPE=CREDENTIAL_PROVIDER_TYPE,
        CREDENTIAL_PROVIDER_ARN=cred_arn,
        PAYMENT_MANAGER_ARN=manager_arn,
        PAYMENT_MANAGER_ID=manager_id,
    )

    print("\n4) Payment connector (manager → Privy credential provider):")
    connector = idempotent_create(
        cp.create_payment_connector,
        conflict_msg=f"connector {CONNECTOR_NAME} exists",
        paymentManagerId=manager_id,
        name=CONNECTOR_NAME,
        description=f"{CONNECTOR_NAME} StripePrivy",
        type=CREDENTIAL_PROVIDER_TYPE,  # "StripePrivy"
        credentialProviderConfigurations=[{"stripePrivy": {"credentialProviderArn": cred_arn}}],
        clientToken=client_token(),
    )
    if connector is None:
        connector_id = require_env("PAYMENT_CONNECTOR_ID")
    else:
        connector_id = connector["paymentConnectorId"]
    print(f"   paymentConnectorId: {connector_id}")
    wait_for_status(
        cp.get_payment_connector, "READY",
        paymentManagerId=manager_id, paymentConnectorId=connector_id,
    )
    print("   connector READY")

    write_env_values(PAYMENT_CONNECTOR_ID=connector_id)

    print_summary(
        "Provisioned payment stack (written to .env)",
        region=REGION,
        payment_manager_arn=manager_arn,
        payment_manager_id=manager_id,
        credential_provider_arn=cred_arn,
        payment_connector_id=connector_id,
    )
    print("\nNext:  python setup/provision_payments.py   # per-user wallet + budgeted session")


if __name__ == "__main__":
    main()
