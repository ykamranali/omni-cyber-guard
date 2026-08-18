import type { Config } from "tailwindcss";

const withOpacity = (varName: string) =>
  `rgb(var(${varName}) / <alpha-value>)`;

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: withOpacity("--color-background"),
        surface: withOpacity("--color-surface"),
        "surface-hover": withOpacity("--color-surface-hover"),
        border: withOpacity("--color-border"),
        primary: {
          DEFAULT: withOpacity("--color-primary"),
          foreground: withOpacity("--color-primary-foreground"),
        },
        secondary: {
          DEFAULT: withOpacity("--color-secondary"),
          foreground: withOpacity("--color-secondary-foreground"),
        },
        critical: "#EF4444",
        high: "#F97316",
        medium: "#EAB308",
        low: "#22C55E",
        info: "#38BDF8",
        muted: withOpacity("--color-muted"),
        ink: withOpacity("--color-ink"),
      },
      backdropBlur: { xs: "2px" },
      boxShadow: {
        glass: "0 8px 32px 0 rgba(0, 0, 0, 0.37)",
        neon: "0 0 10px rgb(var(--color-primary)), 0 0 20px rgb(var(--color-primary))",
        "neon-critical": "0 0 10px #EF4444, 0 0 20px #EF4444",
      },
      borderRadius: {
        xl: "1rem",
        "2xl": "1.25rem",
      },
      animation: {
        "spin-slow": "spin 8s linear infinite",
        "pulse-glow": "pulse-glow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "hud-scan": "hud-scan 3s ease-in-out infinite alternate",
      },
      keyframes: {
        "pulse-glow": {
          "0%, 100%": { opacity: "1", transform: "scale(1)", filter: "brightness(1)" },
          "50%": { opacity: ".8", transform: "scale(1.05)", filter: "brightness(1.5)" },
        },
        "hud-scan": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
