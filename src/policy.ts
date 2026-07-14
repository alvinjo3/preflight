/**
 * policy.ts — the decision engine.
 *
 * Raw threat data is not a product. Agents cannot act on a 40-field JSON blob.
 * They need a verdict they can branch on, and a reason they can show the human.
 *
 * Output contract (stable, versioned):
 *   verdict:  "ALLOW" | "WARN" | "BLOCK"
 *   risk:     0-100 (higher = worse)
 *   findings: [{ code, class, severity, message }]
 *   summary:  one human-readable line
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "ALLOW" | "WARN" | "BLOCK";
export type RiskTolerance = "strict" | "balanced" | "degen";

/**
 * The distinction the whole engine turns on.
 *
 *   scam   — hidden or deceptive. Designed to trap the holder. Never excusable.
 *   issuer — a centralised power the issuer openly holds (freeze, pause, mint).
 *            On an unknown memecoin this is a rug vector. On a regulated
 *            stablecoin it is a disclosed, expected, priced-in property.
 *            Same raw flag, opposite meaning. Context decides.
 *   market — liquidity and concentration risk.
 *   meta   — data quality signals.
 */
export type FindingClass = "scam" | "issuer" | "market" | "meta";

export interface Finding {
  code: string;
  class: FindingClass;
  severity: Severity;
  message: string;
}

export interface Decision {
  verdict: Verdict;
  risk: number;
  tolerance: RiskTolerance;
  issuer_type: "trusted" | "unknown";
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

interface Rule {
  code: string;
  class: FindingClass;
  severity: Severity;
  message: string;
  hit: (d: Record<string, any>) => boolean;
}

const TOKEN_RULES: Rule[] = [
  // ---- scam: deceptive by construction. Never downgraded, whatever the issuer.
  { code: "HONEYPOT", class: "scam", severity: "critical",
    message: "Token is flagged as a honeypot. Buyers cannot sell.",
    hit: (d) => isTrue(d.is_honeypot) },
  { code: "CANNOT_SELL_ALL", class: "scam", severity: "critical",
    message: "Contract blocks selling the full balance.",
    hit: (d) => isTrue(d.cannot_sell_all) },
  { code: "AIRDROP_SCAM", class: "scam", severity: "critical",
    message: "Flagged as an airdrop scam token.",
    hit: (d) => isTrue(d.is_airdrop_scam) },
  { code: "FAKE_TOKEN", class: "scam", severity: "critical",
    message: "Impersonates a well-known token.",
    hit: (d) => isTrue(d.fake_token?.value ?? d.fake_token) },
  { code: "SELL_TAX_EXTREME", class: "scam", severity: "critical",
    message: "Sell tax above 50%. Exiting the position destroys most value.",
    hit: (d) => (num(d.sell_tax) ?? 0) > 0.5 },
  { code: "HIDDEN_OWNER", class: "scam", severity: "high",
    message: "Ownership is obscured. Privileged control is hidden.",
    hit: (d) => isTrue(d.hidden_owner) },
  { code: "NOT_OPEN_SOURCE", class: "scam", severity: "high",
    message: "Contract source is not verified. Behaviour cannot be audited.",
    hit: (d) => d.is_open_source !== undefined && !isTrue(d.is_open_source) },
  { code: "SELFDESTRUCT", class: "scam", severity: "high",
    message: "Contract can self-destruct.",
    hit: (d) => isTrue(d.selfdestruct) },

  // ---- issuer: real centralised powers. Rug vector on an unknown token,
  //      disclosed and expected on a trusted one. Demoted when trust_list fires.
  { code: "BLACKLISTED", class: "issuer", severity: "high",
    message: "Contract can blacklist addresses, freezing your funds.",
    hit: (d) => isTrue(d.is_blacklisted) },
  { code: "TRANSFER_PAUSABLE", class: "issuer", severity: "high",
    message: "Owner can pause all transfers at will.",
    hit: (d) => isTrue(d.transfer_pausable) },
  { code: "MINTABLE", class: "issuer", severity: "high",
    message: "Supply is mintable. Owner can dilute holders at any time.",
    hit: (d) => isTrue(d.is_mintable) },
  { code: "PROXY_UPGRADEABLE", class: "issuer", severity: "high",
    message: "Proxy contract. Logic can be swapped after you buy.",
    hit: (d) => isTrue(d.is_proxy) },
  { code: "TAX_CHANGEABLE", class: "issuer", severity: "high",
    message: "Trading tax can be changed after launch (rug-pull vector).",
    hit: (d) => isTrue(d.slippage_modifiable) },
  { code: "OWNER_HIGH_BALANCE", class: "issuer", severity: "high",
    message: "Owner holds over 20% of supply. Single-wallet dump risk.",
    hit: (d) => (num(d.owner_percent) ?? 0) > 0.2 },
  { code: "ANTI_WHALE_MODIFIABLE", class: "issuer", severity: "medium",
    message: "Max transaction limit can be changed by the owner.",
    hit: (d) => isTrue(d.anti_whale_modifiable) },
  { code: "TRADING_COOLDOWN", class: "issuer", severity: "medium",
    message: "Trading cooldown enforced. Exit timing is not under your control.",
    hit: (d) => isTrue(d.trading_cooldown) },

  // ---- market
  { code: "SELL_TAX_HIGH", class: "market", severity: "high",
    message: "Sell tax above 10%.",
    hit: (d) => { const t = num(d.sell_tax) ?? 0; return t > 0.1 && t <= 0.5; } },
  { code: "BUY_TAX_HIGH", class: "market", severity: "medium",
    message: "Buy tax above 10%.",
    hit: (d) => (num(d.buy_tax) ?? 0) > 0.1 },
  { code: "LP_NOT_LOCKED", class: "market", severity: "high",
    message: "Liquidity is not locked or burned. Liquidity can be pulled.",
    hit: (d) => {
      if (!Array.isArray(d.lp_holders) || d.lp_holders.length === 0) return false;
      const locked = d.lp_holders.reduce(
        (acc: number, h: any) => acc + (isTrue(h.is_locked) ? num(h.percent) ?? 0 : 0), 0);
      return locked < 0.5;
    } },
  { code: "HOLDER_CONCENTRATION", class: "market", severity: "medium",
    message: "Top holder controls over 30% of supply.",
    hit: (d) => {
      const top = Array.isArray(d.holders) ? d.holders[0] : null;
      return (num(top?.percent) ?? 0) > 0.3;
    } },

  // ---- meta
  { code: "TRUSTED", class: "meta", severity: "info",
    message: "Token appears on a trusted-asset list.",
    hit: (d) => isTrue(d.trust_list) },
];

const ADDRESS_RULES: Rule[] = [
  { code: "SANCTIONED", class: "scam", severity: "critical", message: "Address is sanctioned.", hit: (d) => isTrue(d.sanctioned) },
  { code: "PHISHING", class: "scam", severity: "critical", message: "Address is linked to phishing activity.", hit: (d) => isTrue(d.phishing_activities) },
  { code: "STEALING", class: "scam", severity: "critical", message: "Address is linked to asset theft.", hit: (d) => isTrue(d.stealing_attack) },
  { code: "BLACKMAIL", class: "scam", severity: "critical", message: "Address is linked to blackmail activity.", hit: (d) => isTrue(d.blackmail_activities) },
  { code: "HONEYPOT_OWNER", class: "scam", severity: "critical", message: "Address has deployed honeypot tokens before.", hit: (d) => isTrue(d.honeypot_related_address) },
  { code: "MONEY_LAUNDERING", class: "scam", severity: "critical", message: "Address is linked to money laundering.", hit: (d) => isTrue(d.money_laundering) },
  { code: "CYBERCRIME", class: "scam", severity: "critical", message: "Address is linked to cybercrime.", hit: (d) => isTrue(d.cybercrime) },
  { code: "FINANCIAL_CRIME", class: "scam", severity: "critical", message: "Address is linked to financial crime.", hit: (d) => isTrue(d.financial_crime) },
  { code: "MALICIOUS_MINING", class: "scam", severity: "high", message: "Address is linked to malicious mining.", hit: (d) => isTrue(d.malicious_mining_activities) },
  { code: "DARKWEB", class: "scam", severity: "high", message: "Address is linked to darkweb transactions.", hit: (d) => isTrue(d.darkweb_transactions) },
  { code: "FAKE_KYC", class: "scam", severity: "high", message: "Address is linked to fake KYC services.", hit: (d) => isTrue(d.fake_kyc) },
  { code: "MIXER", class: "market", severity: "medium", message: "Address is a coin mixer. Counterparty funds are untraceable.", hit: (d) => isTrue(d.mixer) },
  { code: "BLACKLIST_DOUBT", class: "market", severity: "medium", message: "Address appears on third-party blacklists.", hit: (d) => isTrue(d.blacklist_doubt) },
  { code: "CONTRACT_ADDRESS", class: "meta", severity: "info", message: "Target is a contract, not an EOA.", hit: (d) => isTrue(d.contract_address) },
];

/**
 * Saturating combine, not a linear sum.
 *   risk = 100 * (1 - Π(1 - wᵢ/100))
 * A linear sum maxes out after four "high" findings, which would BLOCK every
 * ordinary memecoin even under a degen policy and make the tolerance dial a
 * no-op. Saturation keeps each extra finding meaningful without pinning to 100.
 */
const combine = (severities: Severity[]) =>
  100 * (1 - severities.reduce((acc, s) => acc * (1 - WEIGHT[s] / 100), 1));

export function decide(
  intel: Record<string, any>,
  kind: "token" | "address" | "approval",
  tolerance: RiskTolerance = "balanced"
): Decision {
  const complete = intel._found !== false;
  const rules = kind === "address" ? ADDRESS_RULES : TOKEN_RULES;

  let findings: Finding[] = [];
  for (const r of rules) {
    let hit = false;
    try { hit = r.hit(intel); } catch { hit = false; }
    if (hit) {
      findings.push({ code: r.code, class: r.class, severity: r.severity, message: r.message });
    }
  }

  const trusted = findings.some((f) => f.code === "TRUSTED");

  // The core correction.
  //
  // USDT can blacklist, pause, and mint. Those flags are TRUE, and a naive
  // engine BLOCKs the most-traded stablecoin on earth. But a regulated issuer's
  // freeze function is a disclosed property, not a hidden trap — every holder
  // already accepts it. Demote issuer powers on a trusted asset to advisory,
  // and say so plainly rather than silently dropping them: the agent still
  // deserves to know Tether can freeze its funds.
  //
  // Scam-class findings are NEVER demoted. A honeypot on a "trusted" token
  // means the trust signal is wrong, not the honeypot.
  if (trusted) {
    findings = findings.map((f) =>
      f.class === "issuer"
        ? {
            ...f,
            severity: "low" as Severity,
            message: `${f.message} Disclosed issuer power of a known asset, not a hidden trap — factored as advisory, not blocking.`,
          }
        : f
    );
  }

  if (!complete) {
    findings.push({
      code: "NO_INTEL",
      class: "meta",
      severity: "high",
      message:
        "No security data available for this address. It may be brand new, on an unindexed chain, or not a token contract. Treat as unverified.",
    });
  }

  let risk = combine(findings.map((f) => f.severity));
  if (trusted) risk = Math.max(0, risk - 20);
  risk = Math.max(0, Math.min(100, Math.round(risk)));

  // Critical is evaluated AFTER demotion, so a trusted asset's issuer powers
  // cannot force a block — but a genuine scam finding still can.
  const hasCritical = findings.some((f) => f.severity === "critical");

  let verdict: Verdict;
  if (hasCritical) verdict = "BLOCK";
  else if (risk >= BLOCK_AT[tolerance]) verdict = "BLOCK";
  else if (risk >= WARN_AT[tolerance]) verdict = "WARN";
  else verdict = "ALLOW";

  const blocking = [...findings]
    .filter((f) => f.severity !== "info" && f.severity !== "low")
    .sort((a, b) => WEIGHT[b.severity] - WEIGHT[a.severity])
    .slice(0, 3)
    .map((f) => f.message);

  const advisories = findings.filter((f) => f.severity === "low").length;

  const summary =
    verdict === "BLOCK"
      ? `BLOCK (risk ${risk}/100). Do not proceed. ${blocking.join(" ")}`
      : verdict === "WARN"
        ? `WARN (risk ${risk}/100). Proceed only with explicit human approval. ${blocking.join(" ")}`
        : `ALLOW (risk ${risk}/100). No blocking issues under "${tolerance}" policy.` +
          (advisories
            ? ` ${advisories} disclosed issuer power(s) noted — see findings.`
            : "");

  return {
    verdict,
    risk,
    tolerance,
    issuer_type: trusted ? "trusted" : "unknown",
    findings,
    summary,
    data_complete: complete,
    schema: "preflight.decision.v1",
  };
}
