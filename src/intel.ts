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

async function getJson(url: string, timeoutMs = 8000): Promise<any> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctl.signal,
      headers: { accept: "application/json" },
    });
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
