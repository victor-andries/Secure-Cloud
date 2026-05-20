"use client";

import { getDefaultConfig } from "@rainbow-me/rainbowkit";
import { sepolia, arbitrumSepolia } from "wagmi/chains";

const projectId = process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID ?? "default-project-id";

export const wagmiConfig = getDefaultConfig({
  appName: "Secure Cloud Platform",
  projectId,
  chains: [sepolia, arbitrumSepolia],
  ssr: true
});

export const chains = [sepolia, arbitrumSepolia];
