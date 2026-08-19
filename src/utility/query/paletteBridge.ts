// Wiring between the background (which owns the library) and the content script
// (which owns the palette). Kept in its own module so the background never
// imports DOM code and the content script never imports storage code it does
// not need.

export const OPEN_QUERY_PALETTE_MESSAGE = "socx-open-query-palette"

export type OpenPaletteMessage = {
  name: typeof OPEN_QUERY_PALETTE_MESSAGE
  body?: {
    /** Pre-select a template, used by the context menu entries. */
    templateKey?: string
    /** Indicators taken from the selection the menu was opened on. */
    indicators?: string[]
    kind?: "ioc" | "standard"
  }
}

export const QUERY_PALETTE_ENABLED_KEY = "queryPaletteEnabled"
export const QUERY_MENU_ENABLED_KEY = "queryContextMenuEnabled"
export const QUERY_PALETTE_SCOPE_KEY = "queryPaletteScope"

export const DEFAULT_QUERY_PALETTE_ENABLED = true
export const DEFAULT_QUERY_MENU_ENABLED = true

/**
 * `matched` restricts the palette to the consoles a pack declares; `all` shows
 * every template everywhere. Matching is the default because a Splunk query has
 * no business appearing on the Defender console.
 */
export type PaletteScope = "matched" | "all"
export const DEFAULT_QUERY_PALETTE_SCOPE: PaletteScope = "matched"

export const resolveBooleanPreference = (
  value: unknown,
  fallback: boolean
): boolean => (typeof value === "boolean" ? value : fallback)

export const resolvePaletteScope = (value: unknown): PaletteScope =>
  value === "all" || value === "matched" ? value : DEFAULT_QUERY_PALETTE_SCOPE
