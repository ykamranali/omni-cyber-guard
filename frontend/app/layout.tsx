import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "Omni Cyber Guard | Omni Digital Solution",
  description: "Enterprise Cybersecurity & Vulnerability Management Platform — Powered by Omni Digital Solution",
  icons: { icon: "/favicon.svg" },
};

// Runs before paint to apply the persisted theme choice and avoid a flash
// of the wrong theme. Reads the same zustand-persist key store/theme.ts writes.
const THEME_INIT_SCRIPT = `
(function() {
  try {
    var raw = localStorage.getItem("ocg-theme-storage");
    var theme = raw ? JSON.parse(raw).state.theme : "dark";
    document.documentElement.classList.toggle("light", theme === "light");
    document.documentElement.classList.toggle("dark", theme !== "light");
  } catch (e) {}
})();
`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
