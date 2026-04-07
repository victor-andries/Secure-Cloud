"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import WalletConnect from "@/components/WalletConnect";

const navLinks = [
  { href: "/",         label: "Dashboard" },
  { href: "/upload",   label: "Upload"    },
  { href: "/files",    label: "Files"     },
  { href: "/audit",    label: "Audit"     },
  { href: "/security", label: "Security"  }
];

export default function Navbar() {
  const pathname = usePathname();

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/10 bg-[#0f0f1a]/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">

          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-primary-600 flex items-center justify-center shadow-lg shadow-primary-500/30">
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
            </div>
            <span className="text-white font-bold text-lg tracking-tight">
              Secure<span className="text-gradient">Cloud</span>
            </span>
          </Link>

          {/* Nav links */}
          <div className="hidden md:flex items-center gap-1">
            {navLinks.map(({ href, label }) => {
              const isActive = pathname === href;
              return (
                <Link
                  key={href}
                  href={href}
                  className={`
                    px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200
                    ${isActive
                      ? "bg-primary-600/20 text-primary-300 border border-primary-500/30"
                      : "text-gray-400 hover:text-white hover:bg-white/5"
                    }
                  `}
                >
                  {label}
                </Link>
              );
            })}
          </div>

          {/* Wallet Connect */}
          <WalletConnect />
        </div>
      </div>
    </nav>
  );
}
