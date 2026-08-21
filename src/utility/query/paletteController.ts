// Content script side of the palette: asks the background for the library that
// belongs to the current page, then renders every template locally.

import { sendToBackground } from "@plasmohq/messaging"

import { showToast } from "../toast"
import { extractIOCs, identifyIOC } from "../utils"
import { readFavorites, writeFavorites } from "./favorites"
import { buildGroupTree } from "./groups"
import type { PackKind, QueryPack } from "./packSchema"
import { entriesFromTree, openPalette } from "./palette"
import { entryPackKey } from "./paletteFilters"
import { readMergeTypes, writeMergeTypes } from "./paletteSettings"
import { createQueryViewRequest } from "./queryViewRequest"
import { bundledDialectMap } from "./render"

export type OpenPaletteOptions = {
  indicators?: string[]
  kind?: PackKind
  templateKey?: string
  scope?: "matched" | "all"
}

type LibraryResponse = {
  packs?: QueryPack[]
  platformLabel?: string
  platformPackKey?: string
  indicators?: string[]
  matched?: boolean
  paletteEnabled?: boolean
}

export const collectSelectionIndicators = (): string[] => {
  const selection = window.getSelection()?.toString() ?? ""
  if (!selection.trim()) return []
  return extractIOCs(selection) ?? []
}

export const openQueryPalette = async (
  options: OpenPaletteOptions = {}
): Promise<boolean> => {
  let response: LibraryResponse | undefined
  try {
    response = await sendToBackground<unknown, LibraryResponse>({
      name: "query-library",
      body: {
        pageUrl: location.href,
        kind: options.kind,
        matchPlatform: options.scope !== "all",
        includeIndicators: true
      }
    })
  } catch (error) {
    console.error("Unable to load the query library:", error)
  }

  if (response?.paletteEnabled === false) {
    showToast("The query palette is disabled in SOCx settings.", "info")
    return false
  }

  const packs = response?.packs ?? []
  if (packs.length === 0) {
    showToast(
      "No query pack available for this page. Add or refresh a source in SOCx settings.",
      "warning"
    )
    return false
  }

  const tree = buildGroupTree(packs)
  const entries = entriesFromTree(tree)
  if (entries.length === 0) {
    showToast("The enabled query packs contain no template.", "warning")
    return false
  }

  // Indicators come from the current selection first, then from whatever the
  // Bulk Check workspace holds, so the palette is useful with or without one.
  const selected = options.indicators ?? collectSelectionIndicators()
  const values = selected.length > 0 ? selected : (response?.indicators ?? [])
  const dialects = bundledDialectMap()
  // Read once: the palette keeps the list in memory and writes back on toggle,
  // so starring never waits on storage.
  const [favorites, mergeTypes] = await Promise.all([
    readFavorites(),
    readMergeTypes()
  ])

  const ordered = options.templateKey
    ? [
        ...entries.filter((entry) => entry.key === options.templateKey),
        ...entries.filter((entry) => entry.key !== options.templateKey)
      ]
    : entries

  openPalette(
    createQueryViewRequest({
      entries: ordered,
      dialects,
      platformLabel: response?.platformLabel,
      initialPackKey: options.templateKey
        ? entryPackKey(
            ordered.find((entry) => entry.key === options.templateKey) ??
              ordered[0]
          )
        : response?.platformPackKey,
      indicatorHint: values,
      initialKey: options.templateKey,
      favorites,
      onToggleFavorite: (_key, next) => {
        void writeFavorites(next).catch(() =>
          showToast("Could not save the favorite", "danger")
        )
      },
      mergeTypes,
      onMergeTypesChange: (value) => {
        void writeMergeTypes(value).catch(() => undefined)
      }
    })
  )
  return true
}
