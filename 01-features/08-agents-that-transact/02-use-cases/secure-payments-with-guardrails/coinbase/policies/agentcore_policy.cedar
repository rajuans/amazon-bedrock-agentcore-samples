// AgentCore Policy (Cedar) — deterministic authorization for the payment tool.
//
// AgentCore Policy runs a policy engine that you associate with an AgentCore
// Gateway; it intercepts every tool call routed through the Gateway and
// evaluates it BEFORE execution (permit/forbid), logging each decision to
// CloudWatch. This is where per-transaction amount caps and recipient
// allowlists belong — NOT in the agent's prompt or tool logic, and not
// expressible by an AgentCore Payment Session (which only caps cumulative
// spend). Docs: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
//
// The payment tool is exposed through the Gateway as
// `PaymentsTarget___pay_merchant` (<TargetName>___<tool-name>), with inputs
// `amount` (Long, USDC base units: 500000 = $0.50) and `recipient` (String,
// lowercase x402 payTo). Replace the Gateway ARN with your own.
//
// Validated with:  dogwood validate agentcore_policy.cedar \
//                    --policy-schema dogwood/schema.cedarschema
// For rules over the agent's history (velocity, rolling cap, recipient
// provenance), see dogwood/payment_guardrails.dw — it replaces rule 1 below.

// 1) Baseline: allow the agent to call the payment tool.
@id("permit_pay_merchant")
permit (
    principal,
    action == AgentCore::Action::"PaymentsTarget___pay_merchant",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/payments-gateway"
);

// 2) Forbid any single payment above the per-transaction cap ($0.50).
//    Overrides the permit above — in Cedar, an explicit `forbid` always wins.
@id("forbid_over_per_tx_cap")
forbid (
    principal,
    action == AgentCore::Action::"PaymentsTarget___pay_merchant",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/payments-gateway"
)
when { context.input.amount > 500000 };

// 3) Forbid payments to any recipient not on the allowlist.
@id("forbid_recipient_not_allowlisted")
forbid (
    principal,
    action == AgentCore::Action::"PaymentsTarget___pay_merchant",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/payments-gateway"
)
unless {
    ["0xa27f7cb624b57c79d7f9de03ae9f5c705c2858db"]   // allowlisted merchant payTo (x402), not the USDC contract
        .contains(context.input.recipient)
};
