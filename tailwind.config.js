/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class", ".dark-mode"],
  content: ["./src/**/*.{ts,tsx,js,jsx,html}"],
  theme: {
    extend: {
      colors: {
        "socx-night": "#050912",
        "socx-night-soft": "#0c1424",
        "socx-panel": "#161f32",
        "socx-cloud": "#f5f6fb",
        "socx-cloud-soft": "#eef1f7",
        "socx-paper": "#ffffff",
        "socx-border-dark": "#1f273a",
        "socx-border-light": "#e4e8f4",
        "socx-ink": "#111322",
        "socx-ink-soft": "#4b5568",
        "socx-muted-dark": "#9da7bf",
        "socx-muted": "#6b7280",
        "socx-accent": "#f5c242",
        "socx-accent-strong": "#ffd24d",
        "socx-accent-muted": "#d8a416",
        "socx-success": "#34d399",
        "socx-danger": "#f87171",
        "socx-info": "#38bdf8"
      },
      fontFamily: {
        inter: ["Inter", "system-ui", "sans-serif"]
      },
      borderRadius: {
        "socx-md": "0.75rem",
        "socx-lg": "1rem"
      },
      boxShadow: {
        "socx-focus": "0 0 0 3px rgba(245, 194, 66, 0.35)"
      }
    }
  },
  plugins: []
}
