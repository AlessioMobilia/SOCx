// Content script side of the palette: asks the background for the library that
// belongs to the current page, then renders every template locally.

import { sendToBackground } from "@plasmohq/messaging"

import { showToast } from "../toast"
import { extractIOCs, identifyIOC } from "../utils"
import { readFavorites, writeFavorites } from "./favorites"
import { buildGroupTree } from "./groups"
import type { PackKind, QueryPack } from "./packSchema"
import { entriesFromTree, openPalette, type PaletteEntry } from "./palette"
import { readMergeTypes, writeMergeTypes } from "./paletteSettings"
import { bundledDialectMap, renderTemplate, type RenderedQuery } from "./render"
import { toWorkspaceIndicators } from "./workspace"

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

export const collectSelectionIndicators = (): string[] => {
  const selection = window.getSelection()?.toString() ?? ""
  if (!selection.trim()) return []
  return extractIOCs(selection) ?? []
}

/** What a rendered query covers, said the same way in every surface. */
const describeQuery = (query: RenderedQuery): string | undefined => {
  const types = query.types?.length
    ? query.types.join(", ")
    : (query.type ?? "")
  const covered = types ? `${query.count} indicators · ${types}` : undefined
  if (query.chunks > 1) {
    return `Chunk ${query.chunk} of ${query.chunks}${covered ? ` · ${covered}` : ""}`
  }
  return covered
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
  const dialects = bundledDialectMap()
  const dialectLabels = new Map(
    [...dialects.entries()].map(([id, dialect]) => [id, dialect.label])
  )
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

  openPalette({
    entries: ordered,
    platformLabel: response?.platformLabel,
    indicatorHint: values,
    initialKey: options.templateKey,
    favorites,
    dialectLabels,
    onToggleFavorite: (_key, next) => {
      void writeFavorites(next).catch(() =>
        showToast("Could not save the favorite", "danger")
      )
    },
    describeIndicators: (text) => {
      const parsed = toWorkspaceIndicators(text)
      if (parsed.length === 0) {
        return text.trim()
          ? "nothing recognisable yet"
          : "none — only queries that need no indicator will render"
      }
      const byType = new Map<string, number>()
      for (const indicator of parsed) {
        byType.set(indicator.type, (byType.get(indicator.type) ?? 0) + 1)
      }
      const breakdown = [...byType.entries()]
        .map(([type, count]) => `${count} ${type}`)
        .join(" · ")
      return `${parsed.length} indicator${parsed.length === 1 ? "" : "s"} · ${breakdown}`
    },
    mergeTypes,
    onMergeTypesChange: (value) => {
      void writeMergeTypes(value).catch(() => undefined)
    },
    onRender: (entry: PaletteEntry, input) => {
      const outcome = renderTemplate({
        template: entry.template,
        pack: entry.pack,
        dialects,
        // Parsed on every keystroke: the field is the single source of truth
        // for what ends up in the query, whoever filled it in.
        indicators: toWorkspaceIndicators(input.indicatorText),
        variables: input.variables,
        mergeTypes: input.mergeTypes
      })

      return outcome.queries.map((query, index) => ({
        text: query.text,
        note: describeQuery(query),
        warning:
          [
            query.overLength
              ? "Longer than this platform usually accepts — consider a smaller batch."
              : "",
            // Said once, on the first query, so the fallback is never silent.
            index === 0 && outcome.mergeRefusal
              ? `One query per type: ${outcome.mergeRefusal}.`
              : ""
          ]
            .filter(Boolean)
            .join(" ") || undefined
      }))
    }
  })
}
