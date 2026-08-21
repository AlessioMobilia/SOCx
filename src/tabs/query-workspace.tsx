import { PencilSquareIcon } from "@heroicons/react/24/outline"
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react"

import { sendToBackground } from "@plasmohq/messaging"

import "../styles/tailwind.css"

import { USER_QUERY_LIBRARY_KEY } from "../utility/query/builder"
import { readFavorites, writeFavorites } from "../utility/query/favorites"
import { buildGroupTree } from "../utility/query/groups"
import type { QueryPack } from "../utility/query/packSchema"
import { QUERY_PACK_SOURCES_KEY } from "../utility/query/packSources"
import { entriesFromTree, mountQueryView } from "../utility/query/palette"
import {
  readMergeTypes,
  writeMergeTypes
} from "../utility/query/paletteSettings"
import { createQueryViewRequest } from "../utility/query/queryViewRequest"
import { QUERY_PACK_CACHE_KEY } from "../utility/query/registry"
import { bundledDialectMap } from "../utility/query/render"
import { parseQueryWorkspaceHash } from "../utility/query/workspace"
import { ensureIsDarkMode } from "../utility/theme"

type LibraryResponse = { packs?: QueryPack[]; indicators?: string[] }

const QueryWorkspace = () => {
  const launch = useMemo(() => parseQueryWorkspaceHash(location.hash), [])
  const dialects = useMemo(() => bundledDialectMap(), [])
  const [packs, setPacks] = useState<QueryPack[]>([])
  const [favorites, setFavorites] = useState<string[]>([])
  const [mergeTypes, setMergeTypes] = useState(true)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const viewHost = useRef<HTMLDivElement>(null)
  const loadInFlight = useRef(false)
  const indicatorText = useRef(launch.indicators.join("\n"))
  const selectedKey = useRef(launch.templateKey ?? "")

  const loadLibrary = useCallback(
    async (options: { initial?: boolean } = {}) => {
      if (loadInFlight.current) return
      loadInFlight.current = true
      try {
        const response = await sendToBackground<unknown, LibraryResponse>({
          name: "query-library",
          body: { matchPlatform: false, includeIndicators: true }
        })
        setPacks(response?.packs ?? [])
        setError("")
        if (
          options.initial &&
          !indicatorText.current &&
          response?.indicators?.length
        ) {
          indicatorText.current = response.indicators.join("\n")
        }
      } catch (loadError) {
        console.error("Unable to load the query library:", loadError)
        setError("Unable to load query packs. Refresh them from SOCx options.")
      } finally {
        loadInFlight.current = false
        setLoading(false)
      }
    },
    []
  )

  useEffect(() => {
    const start = async () => {
      try {
        const dark = await ensureIsDarkMode()
        document.body.className = dark ? "dark-mode" : "light-mode"
      } catch (themeError) {
        console.error("Unable to read the theme preference:", themeError)
      }
      const [storedFavorites, storedMergeTypes] = await Promise.all([
        readFavorites(),
        readMergeTypes()
      ])
      setFavorites(storedFavorites)
      setMergeTypes(storedMergeTypes)
      await loadLibrary({ initial: true })
    }
    void start()
  }, [loadLibrary])

  useEffect(() => {
    const watched = new Set([
      QUERY_PACK_CACHE_KEY,
      QUERY_PACK_SOURCES_KEY,
      USER_QUERY_LIBRARY_KEY
    ])
    const onStorageChange = (
      changes: Record<string, chrome.storage.StorageChange>,
      area: string
    ) => {
      if (
        area === "local" &&
        Object.keys(changes).some((key) => watched.has(key))
      ) {
        void loadLibrary()
      }
    }
    const onVisible = () => {
      if (document.visibilityState === "visible") void loadLibrary()
    }

    const storageChanges = globalThis.chrome?.storage?.onChanged
    storageChanges?.addListener(onStorageChange)
    document.addEventListener("visibilitychange", onVisible)
    return () => {
      storageChanges?.removeListener(onStorageChange)
      document.removeEventListener("visibilitychange", onVisible)
    }
  }, [loadLibrary])

  const entries = useMemo(() => entriesFromTree(buildGroupTree(packs)), [packs])

  useEffect(() => {
    const host = viewHost.current
    if (!host || loading || entries.length === 0) return

    return mountQueryView(
      createQueryViewRequest({
        entries,
        dialects,
        indicatorHint: [indicatorText.current],
        initialKey: selectedKey.current,
        favorites,
        mergeTypes,
        onToggleFavorite: (_key, next) => {
          void writeFavorites(next)
        },
        onMergeTypesChange: (value) => {
          void writeMergeTypes(value)
        },
        onIndicatorTextChange: (value) => {
          indicatorText.current = value
        },
        onSelectedKeyChange: (value) => {
          selectedKey.current = value
        }
      }),
      { mode: "workspace", host }
    )
  }, [dialects, entries, favorites, loading, mergeTypes])

  return (
    <main className="min-h-screen bg-socx-cloud px-4 py-3 font-inter text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="mx-auto flex w-full max-w-[1680px] flex-col gap-3">
        <header className="flex flex-wrap items-center justify-between gap-3 rounded-socx-lg border border-socx-border-light bg-white/90 px-4 py-2.5 dark:border-socx-border-dark dark:bg-socx-night-soft/80">
          <div className="flex min-w-0 items-center gap-3">
            <p className="shrink-0 text-[10px] font-semibold uppercase tracking-[0.4em] text-socx-muted dark:text-socx-muted-dark">
              SOCx
            </p>
            <span className="h-5 w-px bg-socx-border-light dark:bg-socx-border-dark" />
            <div className="min-w-0">
              <h1 className="text-base font-semibold leading-tight">
                Query workspace
              </h1>
              <p className="hidden truncate text-[11px] text-socx-muted dark:text-socx-muted-dark md:block">
                Browse templates, adjust inputs and generate a ready-to-use
                query.
              </p>
            </div>
          </div>
          <button
            type="button"
            className="inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-3 py-1.5 text-xs font-semibold transition hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark"
            onClick={() =>
              chrome.tabs.create({
                url: chrome.runtime.getURL("tabs/query-builder.html")
              })
            }>
            <PencilSquareIcon className="h-4 w-4" />
            Create custom query
          </button>
        </header>

        {error && (
          <p className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-sm text-rose-700 dark:text-rose-300">
            {error}
          </p>
        )}

        <div
          ref={viewHost}
          aria-busy={loading}
          className="h-[calc(100vh-5.75rem)] min-h-[36rem]">
          {loading && (
            <p className="rounded-xl border border-socx-border-light bg-white/90 p-6 text-center text-sm text-socx-muted dark:border-socx-border-dark dark:bg-socx-night-soft/80">
              Loading query packs…
            </p>
          )}
          {!loading && entries.length === 0 && !error && (
            <p className="rounded-xl border border-dashed border-socx-border-light p-6 text-center text-sm text-socx-muted dark:border-socx-border-dark">
              No query template is enabled. Add or refresh a source in SOCx
              options.
            </p>
          )}
        </div>
      </div>
    </main>
  )
}

export default QueryWorkspace
