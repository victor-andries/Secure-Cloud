import { signMessage } from "@wagmi/core";
import { wagmiConfig } from "./wagmi";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL;

export async function signAuth(
  address: string
): Promise<{ user_address: string; signature: string }> {
  if (!address) throw new Error("Wallet not connected — please connect your wallet first");
  const resp = await fetch(
    `${BASE_URL}/auth/nonce?address=${encodeURIComponent(address.toLowerCase())}`
  );
  if (!resp.ok) throw new Error("Failed to fetch authentication nonce");
  const { nonce } = (await resp.json()) as { nonce: string };
  const signature = await signMessage(wagmiConfig, { message: nonce });
  return { user_address: address, signature };
}
