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
      },
      borderRadius: {
        xl: "1rem",
        "2xl": "1.25rem",
      },
    },
  },
  plugins: [],
};

export default config;
