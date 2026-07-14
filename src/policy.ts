/**
 * policy.ts — the decision engine.
 *
 * Raw threat data is not a product. Agents cannot act on a 40-field JSON blob.
 * They need a verdict they can branch on, and a reason they can show the human.
 *
 * Output contract (stable, versioned):
 *   verdict:  "ALLOW" | "WARN" | "BLOCK"
 *   risk:     0-100 (higher = worse)
 *   findings: [{ code, severity, message }]
 *   summary:  one human-readable line
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "ALLOW" | "WARN" | "BLOCK";
export type RiskTolerance = "strict" | "balanced" | "degen";

export interface Finding {
  code: string;
  severity: Severity;
  message: string;
}

export interface Decision {
  verdict: Verdict;
  risk: number;
  tolerance: RiskTolerance;
  findings: Finding[];
  summary: string;
  data_complete: boolean;
  schema: "preflight.decision.v1";
}

const WEIGHT: Record<Severity, number> = {
  critical: 60,
  high: 25,
  medium: 10,
  low: 4,
  info: 0,
};

// risk score at/above which we BLOCK, given the caller's tolerance
const BLOCK_AT: Record<RiskTolerance, number> = {
  strict: 25,
  balanced: 50,
  degen: 70,
};
const WARN_AT: Record<RiskTolerance, number> = {
  strict: 5,
  balanced: 15,
  degen: 20,
};

const isTrue = (v: unknown) => v === "1" || v === 1 || v === true;
const num = (v: unknown) => {
  const n = parseFloat(String(v ?? ""));
  return Number.isFinite(n) ? n : null;
};

/** Rule table for token checks. Add rules here — engine picks them up automatically. */
const TOKEN_RULES: Array<{
  code: string;
  severity: Severity;
  message: string;
  hit: (d: Record<string, any>) => boolean;
}> = [
  {
    code: "HONEYPOT",
    severity: "critical",
    message: "Token is flagged as a honeypot. Buyers cannot sell.",
    hit: (d) => isTrue(d.is_honeypot),
  },
  {
    code: "CANNOT_SELL_ALL",
    severity: "critical",
    message: "Contract blocks selling the full balance.",
    hit: (d) => isTrue(d.cannot_sell_all),
  },
  {
    code: "BLACKLISTED",
    severity: "critical",
    message: "Contract can blacklist addresses, freezing your funds.",
    hit: (d) => isTrue(d.is_blacklisted),
  },
  {
    code: "TRANSFER_PAUSABLE",
    severity: "high",
    message: "Owner can pause all transfers at will.",
    hit: (d) => isTrue(d.transfer_pausable),
  },
  {
    code: "MINTABLE",
    severity: "high",
    message: "Supply is mintable. Owner can dilute holders at any time.",
    hit: (d) => isTrue(d.is_mintable),
  },
  {
    code: "PROXY_UPGRADEABLE",
    severity: "high",
    message: "Proxy contract. Logic can be swapped after you buy.",
    hit: (d) => isTrue(d.is_proxy),
  },
  {
    code: "HIDDEN_OWNER",
    severity: "high",
    message: "Ownership is obscured. Privileged control is hidden.",
    hit: (d) => isTrue(d.hidden_owner),
  },
  {
    code: "SELFDESTRUCT",
    severity: "high",
    message: "Contract can self-destruct.",
    hit: (d) => isTrue(d.selfdestruct),
  },
  {
    code: "TAX_CHANGEABLE",
    severity: "high",
    message: "Trading tax can be changed after launch (rug-pull vector).",
    hit: (d) => isTrue(d.slippage_modifiable),
  },
  {
    code: "SELL_TAX_EXTREME",
    severity: "critical",
    message: "Sell tax above 50%. Exiting the position destroys most value.",
    hit: (d) => (num(d.sell_tax) ?? 0) > 0.5,
  },
  {
    code: "SELL_TAX_HIGH",
    severity: "high",
    message: "Sell tax above 10%.",
    hit: (d) => {
      const t = num(d.sell_tax) ?? 0;
      return t > 0.1 && t <= 0.5;
    },
  },
  {
    code: "BUY_TAX_HIGH",
    severity: "medium",
    message: "Buy tax above 10%.",
    hit: (d) => (num(d.buy_tax) ?? 0) > 0.1,
  },
  {
    code: "NOT_OPEN_SOURCE",
    severity: "high",
    message: "Contract source is not verified. Behaviour cannot be audited.",
    hit: (d) => d.is_open_source !== undefined && !isTrue(d.is_open_source),
  },
  {
    code: "TRADING_COOLDOWN",
    severity: "medium",
    message: "Trading cooldown enforced. Exit timing is not under your control.",
    hit: (d) => isTrue(d.trading_cooldown),
  },
  {
    code: "ANTI_WHALE_MODIFIABLE",
    severity: "medium",
    message: "Max transaction limit can be changed by the owner.",
    hit: (d) => isTrue(d.anti_whale_modifiable),
  },
  {
    code: "OWNER_HIGH_BALANCE",
    severity: "high",
    message: "Owner holds over 20% of supply. Single-wallet dump risk.",
    hit: (d) => (num(d.owner_percent) ?? 0) > 0.2,
  },
  {
    code: "HOLDER_CONCENTRATION",
    severity: "medium",
    message: "Top holder controls over 30% of supply.",
    hit: (d) => {
      const top = Array.isArray(d.holders) ? d.holders[0] : null;
      return (num(top?.percent) ?? 0) > 0.3;
    },
  },
  {
    code: "LP_NOT_LOCKED",
    severity: "high",
    message: "Liquidity is not locked or burned. Liquidity can be pulled.",
    hit: (d) => {
      if (!Array.isArray(d.lp_holders) || d.lp_holders.length === 0) return false;
      const locked = d.lp_holders.reduce(
        (acc: number, h: any) =>
          acc + (isTrue(h.is_locked) ? num(h.percent) ?? 0 : 0),
        0
      );
      return locked < 0.5;
    },
  },
  {
    code: "NO_LIQUIDITY",
    severity: "high",
    message: "No detectable DEX liquidity. Position may be unexitable.",
    hit: (d) =>
      Array.isArray(d.dex) && d.dex.length === 0 && d.is_in_dex !== undefined,
  },
  {
    code: "AIRDROP_SCAM",
    severity: "critical",
    message: "Flagged as an airdrop scam token.",
    hit: (d) => isTrue(d.is_airdrop_scam),
  },
  {
    code: "FAKE_TOKEN",
    severity: "critical",
    message: "Impersonates a well-known token.",
    hit: (d) => isTrue(d.fake_token?.value ?? d.fake_token),
  },
  {
    code: "TRUSTED",
    severity: "info",
    message: "Token appears on a trusted-asset list.",
    hit: (d) => isTrue(d.trust_list),
  },
];

/** Rule table for counterparty / spender address checks. */
const ADDRESS_RULES: Array<{
  code: string;
  severity: Severity;
  message: string;
  hit: (d: Record<string, any>) => boolean;
}> = [
  { code: "SANCTIONED", severity: "critical", message: "Address is sanctioned.", hit: (d) => isTrue(d.sanctioned) },
  { code: "PHISHING", severity: "critical", message: "Address is linked to phishing activity.", hit: (d) => isTrue(d.phishing_activities) },
  { code: "STEALING", severity: "critical", message: "Address is linked to asset theft.", hit: (d) => isTrue(d.stealing_attack) },
  { code: "BLACKMAIL", severity: "critical", message: "Address is linked to blackmail activity.", hit: (d) => isTrue(d.blackmail_activities) },
  { code: "HONEYPOT_OWNER", severity: "critical", message: "Address has deployed honeypot tokens before.", hit: (d) => isTrue(d.honeypot_related_address) },
  { code: "MALICIOUS_MINING", severity: "high", message: "Address is linked to malicious mining.", hit: (d) => isTrue(d.malicious_mining_activities) },
  { code: "DARKWEB", severity: "high", message: "Address is linked to darkweb transactions.", hit: (d) => isTrue(d.darkweb_transactions) },
  { code: "MONEY_LAUNDERING", severity: "critical", message: "Address is linked to money laundering.", hit: (d) => isTrue(d.money_laundering) },
  { code: "MIXER", severity: "medium", message: "Address is a coin mixer. Counterparty funds are untraceable.", hit: (d) => isTrue(d.mixer) },
  { code: "FAKE_KYC", severity: "high", message: "Address is linked to fake KYC services.", hit: (d) => isTrue(d.fake_kyc) },
  { code: "CYBERCRIME", severity: "critical", message: "Address is linked to cybercrime.", hit: (d) => isTrue(d.cybercrime) },
  { code: "FINANCIAL_CRIME", severity: "critical", message: "Address is linked to financial crime.", hit: (d) => isTrue(d.financial_crime) },
  { code: "BLACKLIST_DOUBT", severity: "medium", message: "Address appears on third-party blacklists.", hit: (d) => isTrue(d.blacklist_doubt) },
  { code: "CONTRACT_ADDRESS", severity: "info", message: "Target is a contract, not an EOA.", hit: (d) => isTrue(d.contract_address) },
];

export function decide(
  intel: Record<string, any>,
  kind: "token" | "address" | "approval",
  tolerance: RiskTolerance = "balanced"
): Decision {
  const complete = intel._found !== false;
  const rules = kind === "address" ? ADDRESS_RULES : TOKEN_RULES;

  const findings: Finding[] = [];
  for (const r of rules) {
    let hit = false;
    try {
      hit = r.hit(intel);
    } catch {
      hit = false;
    }
    if (hit) findings.push({ code: r.code, severity: r.severity, message: r.message });
  }

  // Saturating combine, not a linear sum.
  //   risk = 100 * (1 - Π(1 - wᵢ/100))
  // A linear sum maxes out after four "high" findings, which would BLOCK every
  // ordinary memecoin even under a degen policy and make the tolerance dial a
  // no-op. Saturation keeps each additional finding meaningful without pinning
  // the score to 100.
  const combine = (severities: Severity[]) =>
    100 *
    (1 - severities.reduce((acc, s) => acc * (1 - WEIGHT[s] / 100), 1));

  let risk = combine(findings.map((f) => f.severity));

  if (!complete) {
    // Unknown is not safe. No data on a contract is itself a signal.
    findings.push({
      code: "NO_INTEL",
      severity: "high",
      message:
        "No security data available for this address. It may be brand new, on an unindexed chain, or not a token contract. Treat as unverified.",
    });
    risk = combine(findings.map((f) => f.severity));
  }

  // Trusted-asset listing pulls risk down, but never below zero and never
  // overrides a critical finding.
  const hasCritical = findings.some((f) => f.severity === "critical");
  if (findings.some((f) => f.code === "TRUSTED") && !hasCritical) {
    risk = Math.max(0, risk - 20);
  }

  risk = Math.max(0, Math.min(100, Math.round(risk)));

  let verdict: Verdict;
  if (hasCritical) verdict = "BLOCK";
  else if (risk >= BLOCK_AT[tolerance]) verdict = "BLOCK";
  else if (risk >= WARN_AT[tolerance]) verdict = "WARN";
  else verdict = "ALLOW";

  const top = [...findings]
    .filter((f) => f.severity !== "info")
    .sort((a, b) => WEIGHT[b.severity] - WEIGHT[a.severity])
    .slice(0, 3)
    .map((f) => f.message);

  const summary =
    verdict === "BLOCK"
      ? `BLOCK (risk ${risk}/100). Do not proceed. ${top.join(" ")}`
      : verdict === "WARN"
        ? `WARN (risk ${risk}/100). Proceed only with explicit human approval. ${top.join(" ")}`
        : `ALLOW (risk ${risk}/100). No blocking issues found under "${tolerance}" policy.`;

  return {
    verdict,
    risk,
    tolerance,
    findings,
    summary,
    data_complete: complete,
    schema: "preflight.decision.v1",
  };
}
