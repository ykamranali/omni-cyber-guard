/**
 * Organization branding, applied to the running UI.
 *
 * Branding was already editable in two places and saved correctly to the
 * backend — and then nothing read it. `globals.css` hardcodes
 * `--color-primary: 14 165 233`, `tailwind.config.ts` binds every `primary`
 * utility to `rgb(var(--color-primary) / <alpha-value>)`, and the only writer
 * of that variable was the stylesheet. Saving a brand colour showed "Saved
 * successfully!" and changed nothing, including after a full reload.
 *
 * Two details make this work rather than half-work:
 *
 * The colour pickers produce hex (`#0EA5E9`). Tailwind's `<alpha-value>`
 * syntax needs a **space-separated RGB triple** (`14 165 233`) — assigning the
 * hex string directly would silently break every `bg-primary/10` opacity
 * modifier in the application. `toRgbTriple` is the conversion, and it refuses
 * anything it cannot parse rather than writing a value that would.
 *
 * And branding is cached in localStorage so a pre-paint script can apply it
 * before React mounts. Without that, every page load flashes the default blue
 * before the organization's colour arrives from the API.
 */

export interface Branding {
  name: string;
  logo_url: string | null;
  favicon_url: string | null;
  primary_color: string;
  secondary_color: string;
  footer_text: string;
}

export const BRANDING_STORAGE_KEY = "ocg-branding";

export const DEFAULT_BRANDING: Branding = {
  name: "Omni Cyber Guard",
  logo_url: null,
  favicon_url: null,
  primary_color: "#0EA5E9",
  secondary_color: "#7C3AED",
  footer_text: "Powered by Omni Digital Solution",
};

const HEX = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/i;

/**
 * `#0EA5E9` → `"14 165 233"`. Returns null for anything unparseable, so a bad
 * stored value leaves the stylesheet default in place instead of blanking the
 * variable and rendering the whole UI transparent.
 */
export function toRgbTriple(hex: string | null | undefined): string | null {
  if (!hex) return null;
  const match = HEX.exec(hex.trim());
  if (!match) return null;

  let value = match[1];
  if (value.length === 3) {
    value = value
      .split("")
      .map((char) => char + char)
      .join("");
  }

  const int = parseInt(value, 16);
  return `${(int >> 16) & 255} ${(int >> 8) & 255} ${int & 255}`;
}

/**
 * Pick a readable foreground for a background colour, using the WCAG relative
 * luminance formula rather than a naive brightness average — a saturated
 * yellow brand colour needs dark text and a mid-grey does not.
 */
export function foregroundFor(hex: string | null | undefined): string | null {
  const triple = toRgbTriple(hex);
  if (!triple) return null;

  const [r, g, b] = triple.split(" ").map(Number).map((channel) => {
    const normalised = channel / 255;
    return normalised <= 0.03928
      ? normalised / 12.92
      : ((normalised + 0.055) / 1.055) ** 2.4;
  });
  const luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;

  return luminance > 0.45 ? "17 24 39" : "255 255 255";
}

/** Write the branding colours onto the document root. */
export function applyBranding(branding: Partial<Branding> | null | undefined): void {
  if (typeof document === "undefined" || !branding) return;
  const root = document.documentElement;

  const primary = toRgbTriple(branding.primary_color);
  if (primary) {
    root.style.setProperty("--color-primary", primary);
    const foreground = foregroundFor(branding.primary_color);
    if (foreground) root.style.setProperty("--color-primary-foreground", foreground);
  }

  const secondary = toRgbTriple(branding.secondary_color);
  if (secondary) {
    root.style.setProperty("--color-secondary", secondary);
    const foreground = foregroundFor(branding.secondary_color);
    if (foreground) root.style.setProperty("--color-secondary-foreground", foreground);
  }

  if (branding.name) {
    document.title = `${branding.name} | Security Platform`;
  }

  if (branding.favicon_url) {
    let link = document.querySelector<HTMLLinkElement>("link[rel~='icon']");
    if (!link) {
      link = document.createElement("link");
      link.rel = "icon";
      document.head.appendChild(link);
    }
    link.href = branding.favicon_url;
  }
}

/** Remove every override, restoring the stylesheet defaults. */
export function resetBranding(): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  for (const name of [
    "--color-primary",
    "--color-primary-foreground",
    "--color-secondary",
    "--color-secondary-foreground",
  ]) {
    root.style.removeProperty(name);
  }
}

export function cacheBranding(branding: Branding): void {
  try {
    localStorage.setItem(BRANDING_STORAGE_KEY, JSON.stringify(branding));
  } catch {
    /* Private mode, or storage disabled. Branding still applies this session. */
  }
}

export function readCachedBranding(): Branding | null {
  try {
    const raw = localStorage.getItem(BRANDING_STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Branding) : null;
  } catch {
    return null;
  }
}

export function clearCachedBranding(): void {
  try {
    localStorage.removeItem(BRANDING_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * Applied in <head> before first paint, from the cached value. Kept as a
 * string because it has to run ahead of the React bundle; the colour
 * conversion is duplicated here for that reason and must stay in step with
 * `toRgbTriple` above.
 */
export const BRANDING_INIT_SCRIPT = `
(function () {
  try {
    var raw = localStorage.getItem("${BRANDING_STORAGE_KEY}");
    if (!raw) return;
    var branding = JSON.parse(raw);
    var root = document.documentElement;

    function triple(hex) {
      if (!hex) return null;
      var match = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(String(hex).trim());
      if (!match) return null;
      var value = match[1];
      if (value.length === 3) {
        value = value[0] + value[0] + value[1] + value[1] + value[2] + value[2];
      }
      var int = parseInt(value, 16);
      return ((int >> 16) & 255) + " " + ((int >> 8) & 255) + " " + (int & 255);
    }

    function foreground(hex) {
      var rgb = triple(hex);
      if (!rgb) return null;
      var parts = rgb.split(" ").map(function (channel) {
        var n = Number(channel) / 255;
        return n <= 0.03928 ? n / 12.92 : Math.pow((n + 0.055) / 1.055, 2.4);
      });
      var luminance = 0.2126 * parts[0] + 0.7152 * parts[1] + 0.0722 * parts[2];
      return luminance > 0.45 ? "17 24 39" : "255 255 255";
    }

    var primary = triple(branding.primary_color);
    if (primary) {
      root.style.setProperty("--color-primary", primary);
      var pf = foreground(branding.primary_color);
      if (pf) root.style.setProperty("--color-primary-foreground", pf);
    }
    var secondary = triple(branding.secondary_color);
    if (secondary) {
      root.style.setProperty("--color-secondary", secondary);
      var sf = foreground(branding.secondary_color);
      if (sf) root.style.setProperty("--color-secondary-foreground", sf);
    }
  } catch (e) {}
})();
`;
