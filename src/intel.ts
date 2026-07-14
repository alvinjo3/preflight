/**
 * intel.ts — raw threat-intel fetchers.
 * Source: GoPlus Labs public API (no key required for basic tiers).
 * Swap or add sources here without touching the policy engine.
 */

const GOPLUS = "https://api.gopluslabs.io/api/v1";

export const CHAINS: Record<string, string> = {
  ethereum: "1",
  bsc: "56",
  polygon: "137",
  arbitrum: "42161",
  optimism: "10",
  base: "8453",
  avalanche: "43114",
  xlayer: "196",
};

export function resolveChain(chain: string): string {
  const key = chain.trim().toLowerCase();
  if (CHAINS[key]) return CHAINS[key];
  if (/^\d+$/.test(key)) return key; // raw chain id passed through
  throw new Error(
    `Unsupported chain "${chain}". Supported: ${Object.keys(CHAINS).join(", ")} (or a numeric chain id).`
  );
}

export function isAddress(v: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(v.trim());
}

/**
 * Serialised request queue with a minimum gap between upstream calls.
 *
 * GoPlus rate-limits the keyless tier. A caller scanning 20 tokens in a loop
 * will trip it, and a throttle error surfacing as a verdict is far worse than
 * a slightly slower answer. Queue the calls, space them, and retry transient
 * failures with backoff before ever giving up.
 */
const MIN_GAP_MS = 350;
let chain: Promise<unknown> = Promise.resolve();
let lastCall = 0;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function throttle<T>(fn: () => Promise<T>): Promise<T> {
  const run = chain.then(async () => {
    const wait = MIN_GAP_MS - (Date.now() - lastCall);
    if (wait > 0) await sleep(wait);
    lastCall = Date.now();
    return fn();
  });
  // keep the chain alive even when a call rejects
  chain = run.catch(() => {});
  return run as Promise<T>;
}

const RETRYABLE = /429|too many requests|rate.?limit|upstream 5\d\d/i;

async function fetchOnce(url: string, timeoutMs: number): Promise<any> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctl.signal,
      headers: { accept: "application/json" },
    });
    if (res.status === 429) throw new Error("upstream 429 too many requests");
    if (!res.ok) throw new Error(`upstream ${res.status}`);
    const body = await res.json();
    if (body?.code !== 1 && body?.code !== undefined && body?.code !== 0) {
      // GoPlus: code 1 == success. Non-1 still often carries partial data.
      if (!body?.result) throw new Error(body?.message || "upstream error");
    }
    return body;
  } finally {
    clearTimeout(t);
  }
}

async function getJson(url: string, timeoutMs = 8000): Promise<any> {
  return throttle(async () => {
    let lastErr: any;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        return await fetchOnce(url, timeoutMs);
      } catch (e: any) {
        lastErr = e;
        if (!RETRYABLE.test(String(e?.message ?? e))) throw e;
        await sleep(500 * 2 ** attempt); // 500ms, 1s
      }
    }
    throw lastErr;
  });
}

export type TokenIntel = Record<string, any> & { _found: boolean };

export async function fetchTokenIntel(
  chainId: string,
  address: string
): Promise<TokenIntel> {
  const url = `${GOPLUS}/token_security/${chainId}?contract_addresses=${address}`;
  const body = await getJson(url);
  const result = body?.result ?? {};
  const key = Object.keys(result).find(
    (k) => k.toLowerCase() === address.toLowerCase()
  );
  if (!key) return { _found: false };
  return { ...result[key], _found: true };
}

export type AddressIntel = Record<string, any> & { _found: boolean };

export async function fetchAddressIntel(
  chainId: string,
  address: string
): Promise<AddressIntel> {
  const url = `${GOPLUS}/address_security/${address}?chain_id=${chainId}`;
  const body = await getJson(url);
  const result = body?.result;
  if (!result) return { _found: false };
  return { ...result, _found: true };
}

export type ApprovalIntel = Record<string, any> & { _found: boolean };

export async function fetchApprovalIntel(
  chainId: string,
  spender: string
): Promise<ApprovalIntel> {
  const url = `${GOPLUS}/approval_security/${chainId}?contract_addresses=${spender}`;
  const body = await getJson(url);
  const result = body?.result;
  if (!result) return { _found: false };
  const row = Array.isArray(result) ? result[0] : result;
  if (!row) return { _found: false };
  return { ...row, _found: true };
}
