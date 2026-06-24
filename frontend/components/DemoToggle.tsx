"use client";

import { useState } from "react";
import { useAccount } from "wagmi";
import { reseedDemo } from "@/lib/api";

type Profile = "normal" | "night";

export default function DemoToggle() {
  const enabled =
    process.env.NODE_ENV !== "production" ||
    process.env.NEXT_PUBLIC_DEMO_MODE === "1";
  if (!enabled) return null;
  return <Panel />;
}

function Panel() {
  const { address } = useAccount();
  const [profile, setProfile] = useState<Profile>("normal");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function select(next: Profile) {
    if (busy || next === profile) return;
    setBusy(true);
    setError(null);
    try {
      await reseedDemo(next, address);
      setProfile(next);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Reseed failed");
    } finally {
      setBusy(false);
    }
  }

  const isNight = profile === "night";

  return (
    <div className="fixed bottom-4 right-4 z-50 w-64 rounded-xl border border-white/10 bg-zinc-900/90 p-3 font-mono text-xs text-zinc-300 shadow-xl backdrop-blur">
      <div className="mb-2 flex items-center justify-between">
        <span className="font-semibold tracking-wide text-zinc-200">ECOD baseline</span>
        <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-amber-300">
          DEMO
        </span>
      </div>

      <div className="grid grid-cols-2 gap-1 rounded-lg bg-black/30 p-1">
        <button
          type="button"
          onClick={() => select("normal")}
          disabled={busy}
          aria-pressed={!isNight}
          className={`rounded-md px-2 py-1.5 font-semibold transition disabled:opacity-50 ${
            !isNight ? "bg-emerald-500/90 text-black" : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Normal
        </button>
        <button
          type="button"
          onClick={() => select("night")}
          disabled={busy}
          aria-pressed={isNight}
          className={`rounded-md px-2 py-1.5 font-semibold transition disabled:opacity-50 ${
            isNight ? "bg-red-500/90 text-black" : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Night
        </button>
      </div>

      <p className="mt-2 text-[11px] leading-snug text-zinc-400">
        {busy
          ? "Reseeding ECOD…"
          : isNight
          ? "Weekend-night baseline — a daytime access reads as CRITICAL (blocked)."
          : "Weekday-daytime baseline — normal access is allowed."}
      </p>

      {!address && (
        <p className="mt-1 text-[10px] text-amber-400/80">
          Connect wallet to also reset its anomaly history on switch.
        </p>
      )}
      {error && <p className="mt-1 text-[10px] text-red-400">{error}</p>}
    </div>
  );
}
