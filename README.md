# Preflight — the safety gate agents call before they sign

**A2MCP service for OKX.AI.** An agent about to spend real money onchain asks Preflight one question: *is this safe?* Preflight answers with a decision, not a data dump.

```
check_token(0xdead...) → { verdict: "BLOCK", risk: 93, summary: "Do not proceed. Token is flagged as a honeypot..." }
```

## Why a decision, not data

Every other security API returns forty fields of JSON. An agent cannot branch on forty fields — it has to guess, and it guesses wrong. Preflight ships a **policy engine**: it takes raw intel, applies a rule table, and emits `ALLOW` / `WARN` / `BLOCK` plus a 0–100 risk score and human-readable reasons the agent can surface to its user.

The caller sets its own risk appetite:

| `risk_tolerance` | Blocks at | Use for |
|---|---|---|
| `strict` | risk ≥ 25 | Treasury, custody, anything holding user funds |
| `balanced` | risk ≥ 50 | Default |
| `degen` | risk ≥ 70 | Memecoin trading, where mintable supply is table stakes |

Any **critical** finding (honeypot, sanctioned counterparty, laundering, fake token) forces `BLOCK` regardless of tolerance. Missing data is treated as risk, never as safety — an unknown contract WARNs at minimum.

## Tools

| Tool | When the agent calls it |
|---|---|
| `check_token` | Before buying, swapping, or accepting a token as payment |
| `check_address` | Before sending funds to, or accepting funds from, a counterparty |
| `check_approval` | Before every `approve()` / `permit()` — drained allowances are the #1 agent exploit |

Chains: ethereum, bsc, polygon, arbitrum, optimism, base, avalanche, xlayer (or any numeric chain id).

## Run it

```bash
npm install
npm run build
npm start          # MCP streamable-HTTP at POST /mcp, health at GET /health
```

Stateless — no sessions, no sticky routing. Scales flat behind any load balancer.

## Deploy (pick one, ~5 min)

Needs a public HTTPS URL. Render / Railway / Fly all work:

```
Build command:  npm install && npm run build
Start command:  npm start
```

The server reads `PORT` from the environment, which is what every one of those hosts sets. Confirm it is live:

```bash
curl https://YOUR-URL/health          # {"status":"ok"}
```

Your MCP endpoint is then `https://YOUR-URL/mcp`.

## Register as an ASP on OKX.AI

Ship as a **free A2MCP endpoint** first. Free endpoints just return the result — no x402, no payment plumbing, nothing to get wrong before the deadline. Add pricing after you are listed and safe.

```bash
npx skills add okx/onchainos-skills --yes -g
```

Then **open a new agent session** and send these prompts in order:

1. `Log in to Agentic Wallet on Onchain OS with my email`
2. `Help me register an A2MCP ASP on OKX.AI using OKX Agent Identity from Onchain OS`
   — give it the endpoint `https://YOUR-URL/mcp`
3. `Help me list my ASP on OKX.AI using Onchain OS`

Review takes up to 24 hours. Result lands in the email tied to your Agentic Wallet.

> **The approval is a hard gate.** If your ASP is not approved and live, the hackathon submission is void. Submit for listing with a full day of slack, not on the last afternoon.

## Then submit

1. Post on X with **#OKXAI** — introduce the ASP, the use case, and a demo of **90 seconds or less**.
2. Fill the [Google form](https://forms.gle/mddEUagmDbyV37ws8) with your ASP details and a link to that X post.
3. Deadline: **Jul 17, 23:59 UTC**.

## Upgrading to paid (after you are listed)

A2MCP paid endpoints must speak x402. Use the OKX Payment SDK, price per call, and settlement is automatic. Suggested: keep `check_token` free as the funnel, charge on `check_approval` and `check_address`, which is where the money actually moves. Revenue during the campaign feeds the **Revenue Rocket** award.

## Extending

The rule tables in `src/policy.ts` are plain data. Add a rule, it's live:

```ts
{ code: "MY_RULE", severity: "high", message: "...", hit: (d) => isTrue(d.some_flag) }
```

Swap or add an intel source in `src/intel.ts` — the policy engine never touches the network and doesn't care where the fields came from.

---

Intel source: GoPlus Labs public API (no key required). Not financial advice; a clean verdict is not a guarantee.
