// Favourite templates.
//
// A favourite is nothing more than a palette entry key — the same
// `source::pack::template` namespaced key the group tree produces — kept in a
// short list in local storage. Storing the key rather than a copy of the
// template means a pack refresh keeps the favourite pointing at the current
// version of the query, and a template that disappears from a pack simply stops
// resolving instead of leaving a stale copy behind.

import { Storage } from "@plasmohq/storage"

export const QUERY_FAVORITES_KEY = "queryFavorites"

/** Enough for any realistic shortlist, small enough to stay a cheap read. */
export const MAX_FAVORITES = 200

// Built on demand: this module is imported by the palette, which runs inside a
// content script and must stay free of import time side effects.
const store = () => new Storage({ area: "local" })

/** Storage is untrusted input like anything else that survives an upgrade. */
export const normalizeFavorites = (value: unknown): string[] => {
  if (!Array.isArray(value)) return []
  const seen = new Set<string>()
  const keys: string[] = []
  for (const candidate of value) {
    if (typeof candidate !== "string") continue
    const key = candidate.trim()
    if (!key || key.length > 256 || seen.has(key)) continue
    seen.add(key)
    keys.push(key)
    if (keys.length >= MAX_FAVORITES) break
  }
  return keys
}

export const isFavoriteKey = (favorites: string[], key: string): boolean =>
  favorites.includes(key)

/**
 * Newly starred queries go to the front: the palette lists favourites in this
 * order, so the most recent choice is the one under the cursor.
 */
export const toggleFavoriteKey = (
  favorites: string[],
  key: string
): string[] => {
  if (!key) return favorites
  if (favorites.includes(key)) {
    return favorites.filter((candidate) => candidate !== key)
  }
  return [key, ...favorites].slice(0, MAX_FAVORITES)
}

export const readFavorites = async (): Promise<string[]> => {
  try {
    return normalizeFavorites(await store().get(QUERY_FAVORITES_KEY))
  } catch {
    return []
  }
}

export const writeFavorites = async (favorites: string[]): Promise<void> => {
  await store().set(QUERY_FAVORITES_KEY, normalizeFavorites(favorites))
}

/** Returns the list as it is after the toggle, so callers can render at once. */
export const toggleFavorite = async (key: string): Promise<string[]> => {
  const next = toggleFavoriteKey(await readFavorites(), key)
  await writeFavorites(next)
  return next
}
