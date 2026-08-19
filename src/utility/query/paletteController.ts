// Content script side of the palette: asks the background for the library that
// belongs to the current page, then renders every template locally.

import { sendToBackground } from "@plasmohq/messaging"

import { showToast } from "../toast"
import { extractIOCs, identifyIOC } from "../utils"
import { buildGroupTree } from "./groups"
import type { PackKind, QueryPack } from "./packSchema"
import { entriesFromTree, openPalette, type PaletteEntry } from "./palette"
import { bundledDialectMap, renderTemplate, toBindableType } from "./render"

export type OpenPaletteOptions = {
  indicators?: string[]
  kind?: PackKind
  templateKey?: string
  scope?: "matched" | "all"
}

type LibraryResponse = {
  packs?: QueryPack[]
  platformLabel?: string
  indicators?: string[]
  matched?: boolean
  paletteEnabled?: boolean
}

const toIndicators = (values: string[]) =>
  values
    .map((value) => {
      const type = toBindableType(identifyIOC(value), value)
      return type ? { value, type } : null
    })
    .filter((entry): entry is { value: string; type: any } => Boolean(entry))

export const collectSelectionIndicators = (): string[] => {
  const selection = window.getSelection()?.toString() ?? ""
  if (!selection.trim()) return []
  return extractIOCs(selection) ?? []
}

export const openQueryPalette = async (
  options: OpenPaletteOptions = {}
): Promise<void> => {
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
    return
  }

  const packs = response?.packs ?? []
  if (packs.length === 0) {
    showToast(
      "No query pack available for this page. Add or refresh a source in SOCx settings.",
      "warning"
    )
    return
  }

  const tree = buildGroupTree(packs)
  const entries = entriesFromTree(tree)
  if (entries.length === 0) {
    showToast("The enabled query packs contain no template.", "warning")
    return
  }

  // Indicators come from the current selection first, then from whatever the
  // Bulk Check workspace holds, so the palette is useful with or without one.
  const selected = options.indicators ?? collectSelectionIndicators()
  const values = selected.length > 0 ? selected : (response?.indicators ?? [])
  const indicators = toIndicators(values)
  const dialects = bundledDialectMap()

  const ordered = options.templateKey
    ? [
        ...entries.filter((entry) => entry.key === options.templateKey),
        ...entries.filter((entry) => entry.key !== options.templateKey)
      ]
    : entries

  openPalette({
    entries: ordered,
    platformLabel: response?.platformLabel,
    indicatorHint: values,
    onRender: (entry: PaletteEntry, variables) => {
      const outcome = renderTemplate({
        template: entry.template,
        pack: entry.pack,
        dialects,
        indicators,
        variables
      })

      return outcome.queries.map((query) => ({
        text: query.text,
        note:
          query.chunks > 1
            ? `Chunk ${query.chunk} of ${query.chunks} · ${query.count} indicators${
                query.type ? ` · ${query.type}` : ""
              }`
            : query.type
              ? `${query.count} ${query.type} indicators`
              : undefined,
        warning: query.overLength
          ? "Longer than this platform usually accepts — consider a smaller batch."
          : undefined
      }))
    }
  })

  if (indicators.length === 0) {
    showToast(
      "No indicator in the selection: only queries that need none will render.",
      "info"
    )
  }
}
