import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}"
  ],
  theme: {
    extend: {
      colors: {
        background: "#09090b",
        foreground: "#e4e4e8",
        card: {
          DEFAULT: "#0f1117",
          foreground: "#e4e4e8",
        },
        popover: {
          DEFAULT: "#0f1117",
          foreground: "#e4e4e8",
        },
        border: "#1e2030",
        input: "#161820",
        ring: "#fbbf24",
        muted: {
          DEFAULT: "#141420",
          foreground: "#6b7280",
        },
        accent: {
          DEFAULT: "#fbbf24",
          foreground: "#09090b",
        },
        destructive: {
          DEFAULT: "#ef4444",
          foreground: "#fef2f2",
        },
        primary: {
          DEFAULT: "#fbbf24",
          foreground: "#09090b",
          50: "#fffbeb",
          100: "#fef3c7",
          200: "#fde68a",
          300: "#fcd34d",
          400: "#fbbf24",
          500: "#f59e0b",
          600: "#d97706",
          700: "#b45309",
          800: "#92400e",
          900: "#78350f",
        },
        secondary: {
          DEFAULT: "#64748b",
          foreground: "#e4e4e8",
          500: "#64748b",
          600: "#475569",
        },
        danger: {
          DEFAULT: "#ef4444",
          500: "#ef4444",
          600: "#dc2626",
        },
        warning: {
          DEFAULT: "#f97316",
          500: "#f97316",
          600: "#ea580c",
        },
        success: {
          DEFAULT: "#10b981",
          500: "#10b981",
          600: "#059669",
        },
      },
      fontFamily: {
        heading: ["var(--font-heading)", "system-ui", "sans-serif"],
        body:    ["var(--font-body)",    "system-ui", "sans-serif"],
        mono:    ["var(--font-mono)",    "JetBrains Mono", "Fira Code", "monospace"],
        sans:    ["var(--font-body)",    "system-ui", "sans-serif"],
      },
      borderRadius: {
        "4xl": "2rem",
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "gradient-conic":  "conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))",
      },
    }
  },
  plugins: [],
};

export default config;
