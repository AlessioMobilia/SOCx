// Serves the assembled query library to whoever asks: the palette in a content
// script, the context menu handler, or the options page.

import type { PlasmoMessaging } from "@plasmohq/messaging"
import { Storage } from "@plasmohq/storage"

import type { PackKind, QueryPack } from "../../utility/query/packSchema"
import {
  DEFAULT_QUERY_PALETTE_ENABLED,
  QUERY_PALETTE_ENABLED_KEY,
  QUERY_PALETTE_SCOPE_KEY,
  resolveBooleanPreference,
  resolvePaletteScope
} from "../../utility/query/paletteBridge"
import {
  loadLibrary,
  matchPacksForUrl,
  refreshAllSources
} from "../../utility/query/registry"

const storage = new Storage({ area: "local" })

export type QueryLibraryRequest = {
  pageUrl?: string
  kind?: PackKind
  /** Restrict to the packs that belong to the console the analyst is on. */
  matchPlatform?: boolean
  refresh?: boolean
  includeIndicators?: boolean
}

export type QueryLibraryResponse = {
  packs: QueryPack[]
  platformLabel?: string
  indicators?: string[]
  matched: boolean
  paletteEnabled: boolean
}

const handler: PlasmoMessaging.MessageHandler<
  QueryLibraryRequest,
  QueryLibraryResponse
> = async (req, res) => {
  const body = req.body ?? {}

  if (body.refresh) {
    await refreshAllSources()
  }

  // The scope preference lives here rather than in the content script, so both
  // the palette and the context menu see the same answer.
  const [paletteSetting, scopeSetting] = await Promise.all([
    storage.get(QUERY_PALETTE_ENABLED_KEY),
    storage.get(QUERY_PALETTE_SCOPE_KEY)
  ])
  const paletteEnabled = resolveBooleanPreference(
    paletteSetting,
    DEFAULT_QUERY_PALETTE_ENABLED
  )
  const scope = resolvePaletteScope(scopeSetting)

  let library = await loadLibrary({ kind: body.kind })
  // Profiles restored from sync or development builds may have source rows but
  // no local cache. Make the first palette invocation self-healing.
  if (library.packs.length === 0) {
    await refreshAllSources()
    library = await loadLibrary({ kind: body.kind })
  }
  let packs = library.packs
  let platformLabel: string | undefined
  let matched = false

  if (scope === "matched" && body.matchPlatform !== false && body.pageUrl) {
    const matches = matchPacksForUrl(packs, body.pageUrl)
    const matchedPacks = new Set(matches.map((match) => match.pack))
    const hasPlatformMatcher = (pack: QueryPack) =>
      Boolean(
        pack.match?.hostnames?.length ||
        pack.match?.urlPatterns?.length ||
        pack.match?.pathHint
      )

    // Packs without a declared console include personal templates and generic
    // self-hosted platforms. Everything else must genuinely match this page.
    packs = packs.filter(
      (pack) => matchedPacks.has(pack) || !hasPlatformMatcher(pack)
    )
    if (matches.length > 0) {
      platformLabel = matches[0].pack.name
      matched = true
    }
  }

  let indicators: string[] | undefined
  if (body.includeIndicators) {
    const bulk = await storage.get<string[]>("bulkIOCList")
    indicators = Array.isArray(bulk) ? bulk : []
  }

  res.send({ packs, platformLabel, indicators, matched, paletteEnabled })
}

export default handler
