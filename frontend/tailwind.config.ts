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
        primary: {
          DEFAULT: "#6366f1",
          50: "#eef2ff",
          100: "#e0e7ff",
          200: "#c7d2fe",
          300: "#a5b4fc",
          400: "#818cf8",
          500: "#6366f1",
          600: "#4f46e5",
          700: "#4338ca",
          800: "#3730a3",
          900: "#312e81"
        },
        secondary: {
          DEFAULT: "#8b5cf6",
          500: "#8b5cf6",
          600: "#7c3aed"
        },
        danger: {
          DEFAULT: "#ef4444",
          500: "#ef4444",
          600: "#dc2626"
        },
        warning: {
          DEFAULT: "#f59e0b",
          500: "#f59e0b",
          600: "#d97706"
        },
        success: {
          DEFAULT: "#10b981",
          500: "#10b981",
          600: "#059669"
        }
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "gradient-conic": "conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))"
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Consolas", "monospace"]
      }
    }
  },
  plugins: []
};

export default config;
