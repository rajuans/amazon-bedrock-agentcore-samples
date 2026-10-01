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
// Model here: the payment capability is exposed as a Gateway tool action
// `Action::"pay_merchant"` taking context attributes `amount_usd` (decimal)
// and `recipient` (string, lowercased 0x address). Adjust the principal /
// resource identifiers to match your Gateway + workload identity.

// 1) Baseline: allow the agent to call the payment tool.
permit (
    principal,
    action == Action::"pay_merchant",
    resource
);

// 2) Forbid any single payment above the per-transaction cap ($0.50).
//    Overrides the permit above — in Cedar, an explicit `forbid` always wins.
forbid (
    principal,
    action == Action::"pay_merchant",
    resource
)
when { context.amount_usd > decimal("0.50") };

// 3) Forbid payments to any recipient not on the allowlist.
forbid (
    principal,
    action == Action::"pay_merchant",
    resource
)
unless {
    context.recipient in [
        "0xa27f7cb624b57c79d7f9de03ae9f5c705c2858db"   // allowlisted merchant payTo (x402), not the USDC contract
    ]
};
