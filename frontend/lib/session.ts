"use client";

import { signAuth } from "./auth";

const SESSION_KEY = "scp_session";
const BASE_URL = process.env.NEXT_PUBLIC_API_URL;

interface Session {
  token: string;
  address: string;
  expiresAt: number;
}

let _mem: Session | null = null;

function load(address: string): Session | null {
  if (
    _mem &&
    _mem.address.toLowerCase() === address.toLowerCase() &&
    Date.now() < _mem.expiresAt
  ) return _mem;
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as Session;
    if (s.address.toLowerCase() === address.toLowerCase() && Date.now() < s.expiresAt) {
      _mem = s;
      return s;
    }
  } catch {}
  return null;
}

function save(session: Session) {
  _mem = session;
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)); } catch {}
}

export function clearSession() {
  _mem = null;
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
}

export function getExistingSession(address: string): string | null {
  return load(address)?.token ?? null;
}

export async function getOrCreateSession(address: string): Promise<string> {
  const cached = load(address);
  if (cached) return cached.token;

  const { user_address, signature } = await signAuth(address);

  const resp = await fetch(`${BASE_URL}/auth/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_address, signature }),
  });
  if (!resp.ok) throw new Error("Failed to establish session — please try again");

  const { session_token, expires_in } = (await resp.json()) as {
    session_token: string;
    expires_in: number;
  };

  save({
    token: session_token,
    address: user_address,
    expiresAt: Date.now() + (expires_in - 60) * 1000,
  });

  return session_token;
}
