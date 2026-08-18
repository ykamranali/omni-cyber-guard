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
        "satellite-beam": "satellite-beam 3s linear infinite",
        "cyber-lines": "cyber-lines 15s linear infinite",
        "network-lightning": "network-lightning 8s ease-in-out infinite alternate",
        "energy-wave": "energy-wave 8s linear infinite",
        "float-particle": "float-particle 5s ease-in-out infinite alternate",
        "circuit-trace": "circuit-trace 2s linear forwards",
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
        "satellite-beam": {
          "0%": { transform: "translateY(-100%) scaleY(0.5)", opacity: "0" },
          "50%": { transform: "translateY(0%) scaleY(1)", opacity: "0.8" },
          "100%": { transform: "translateY(100%) scaleY(0.5)", opacity: "0" },
        },
        "cyber-lines": {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "100px 100px" },
        },
        "network-lightning": {
          "0%, 100%": { filter: "hue-rotate(0deg) brightness(1)", opacity: "0.6" },
          "25%": { filter: "hue-rotate(90deg) brightness(1.8)", opacity: "1", textShadow: "0 0 20px #EAB308" },
          "50%": { filter: "hue-rotate(180deg) brightness(1.2)", opacity: "0.8", textShadow: "0 0 20px #22C55E" },
          "75%": { filter: "hue-rotate(270deg) brightness(1.8)", opacity: "1", textShadow: "0 0 20px #EF4444" },
        },
        "energy-wave": {
          "0%": { transform: "translateX(-100%) skewX(-15deg)" },
          "100%": { transform: "translateX(100vw) skewX(-15deg)" },
        },
        "float-particle": {
          "0%": { transform: "translateY(0) scale(1)", opacity: "0.2" },
          "50%": { transform: "translateY(-20px) scale(1.2)", opacity: "1" },
          "100%": { transform: "translateY(10px) scale(0.8)", opacity: "0.2" },
        },
        "circuit-trace": {
          "0%": { strokeDashoffset: "100%" },
          "100%": { strokeDashoffset: "0" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
