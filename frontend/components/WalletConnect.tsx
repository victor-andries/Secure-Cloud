"use client";

import { ConnectButton } from "@rainbow-me/rainbowkit";

export default function WalletConnect() {
  return (
    <ConnectButton.Custom>
      {({
        account,
        chain,
        openAccountModal,
        openChainModal,
        openConnectModal,
        authenticationStatus,
        mounted
      }) => {
        const ready = mounted && authenticationStatus !== "loading";
        const connected =
          ready &&
          account &&
          chain &&
          (!authenticationStatus || authenticationStatus === "authenticated");

        return (
          <div
            {...(!ready && {
              "aria-hidden": true,
              style: { opacity: 0, pointerEvents: "none", userSelect: "none" }
            })}
          >
            {(() => {
              if (!connected) {
                return (
                  <button
                    onClick={openConnectModal}
                    type="button"
                    className="
                      px-4 py-2 rounded-xl text-sm font-semibold
                      bg-primary-600 hover:bg-primary-500
                      text-white transition-all duration-200
                      border border-primary-500/30
                      shadow-lg shadow-primary-500/20
                      hover:shadow-primary-500/40
                    "
                  >
                    Connect Wallet
                  </button>
                );
              }

              if (chain.unsupported) {
                return (
                  <button
                    onClick={openChainModal}
                    type="button"
                    className="
                      px-4 py-2 rounded-xl text-sm font-semibold
                      bg-danger-500 hover:bg-danger-600
                      text-white transition-all duration-200
                    "
                  >
                    Wrong network
                  </button>
                );
              }

              return (
                <div className="flex items-center gap-2">
                  <button
                    onClick={openChainModal}
                    type="button"
                    className="
                      flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium
                      bg-white/5 hover:bg-white/10
                      border border-white/10
                      text-gray-300 transition-all duration-200
                    "
                  >
                    {chain.hasIcon && chain.iconUrl && (
                      <img
                        alt={chain.name ?? "Chain icon"}
                        src={chain.iconUrl}
                        className="w-4 h-4 rounded-full"
                      />
                    )}
                    {chain.name}
                  </button>

                  <button
                    onClick={openAccountModal}
                    type="button"
                    className="
                      flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold
                      bg-primary-600/20 hover:bg-primary-600/30
                      border border-primary-500/30
                      text-primary-300 transition-all duration-200
                    "
                  >
                    <span className="w-2 h-2 rounded-full bg-success-500 animate-pulse" />
                    {account.displayName}
                  </button>
                </div>
              );
            })()}
          </div>
        );
      }}
    </ConnectButton.Custom>
  );
}
