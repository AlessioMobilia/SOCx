import {
  ClipboardDocumentListIcon,
  MagnifyingGlassIcon,
  PencilSquareIcon
} from "@heroicons/react/24/outline"
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react"

import { sendToBackground } from "@plasmohq/messaging"

import "../styles/tailwind.css"

import { writeIntelClipboardText } from "../utility/clipboard"
import { USER_QUERY_LIBRARY_KEY } from "../utility/query/builder"
import { readFavorites, toggleFavorite } from "../utility/query/favorites"
import { buildGroupTree } from "../utility/query/groups"
import {
  templateVariables,
  type PackKind,
  type QueryPack
} from "../utility/query/packSchema"
import { QUERY_PACK_SOURCES_KEY } from "../utility/query/packSources"
import { entriesFromTree, type PaletteEntry } from "../utility/query/palette"
import {
  ALL_FILTERS,
  applyPaletteFilters,
  buildFacets,
  dialectChipLabel,
  entryDialect,
  FAVORITES_LABEL,
  hasActiveFilters,
  KIND_LABELS,
  resolveEntryLabels,
  type PaletteFilterState
} from "../utility/query/paletteFilters"
import {
  readMergeTypes,
  writeMergeTypes
} from "../utility/query/paletteSettings"
import { QUERY_PACK_CACHE_KEY } from "../utility/query/registry"
import { bundledDialectMap, renderTemplate } from "../utility/query/render"
import {
  parseQueryWorkspaceHash,
  toWorkspaceIndicators
} from "../utility/query/workspace"
import { ensureIsDarkMode } from "../utility/theme"

const card =
  "rounded-socx-lg border border-socx-border-light bg-white/90 p-5 shadow-sm dark:border-socx-border-dark dark:bg-socx-night-soft/80"
const input =
  "w-full rounded-lg border border-socx-border-light bg-white/90 px-3 py-2 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
const button =
  "inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold transition hover:border-socx-accent hover:text-socx-accent disabled:opacity-40 dark:border-socx-border-dark"
const primaryButton =
  "inline-flex items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-2 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong disabled:opacity-40"

type LibraryResponse = { packs?: QueryPack[]; indicators?: string[] }

/** Templates listed per page: enough to scan, few enough to read. */
const PAGE_SIZE = 25

const QueryWorkspace = () => {
  const launch = useMemo(() => parseQueryWorkspaceHash(location.hash), [])
  const [packs, setPacks] = useState<QueryPack[]>([])
  const [iocText, setIocText] = useState(launch.indicators.join("\n"))
  const [filters, setFilters] = useState<PaletteFilterState>({
    ...ALL_FILTERS,
    labels: {}
  })
  const [favorites, setFavorites] = useState<string[]>([])
  const [mergeTypes, setMergeTypes] = useState(true)
  const [selectedKey, setSelectedKey] = useState(launch.templateKey ?? "")
  const [page, setPage] = useState(0)
  const [variables, setVariables] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  // One source change writes several keys in a row; a load already on its way
  // will pick all of them up, so there is no point queueing more.
  const loadInFlight = useRef(false)
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
        // Only the first load may fill the indicator box: a reload must never
        // overwrite what the analyst has typed since.
        if (
          options.initial &&
          launch.indicators.length === 0 &&
          response?.indicators?.length
        ) {
          setIocText(response.indicators.join("\n"))
        }
      } catch (loadError) {
        console.error("Unable to load the query library:", loadError)
        setError("Unable to load query packs. Refresh them from SOCx options.")
      } finally {
        loadInFlight.current = false
        setLoading(false)
      }
    },
    [launch.indicators]
  )

  useEffect(() => {
    const start = async () => {
      // The theme is cosmetic: a failure reading it must not keep the
      // catalogue from loading.
      try {
        const dark = await ensureIsDarkMode()
        document.body.className = dark ? "dark-mode" : "light-mode"
      } catch (themeError) {
        console.error("Unable to read the theme preference:", themeError)
      }
      await loadLibrary({ initial: true })
    }
    void start()
  }, [loadLibrary])

  // This page lives in its own browser tab, so the library it is showing can be
  // changed from somewhere else — sources enabled or disabled, technologies
  // selected, a pack refreshed, a personal template saved. Without this it would
  // keep serving whatever it read when it was opened.
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
      if (area !== "local") return
      if (Object.keys(changes).some((key) => watched.has(key))) {
        void loadLibrary()
      }
    }
    const onVisible = () => {
      if (document.visibilityState === "visible") void loadLibrary()
    }

    chrome.storage.onChanged.addListener(onStorageChange)
    document.addEventListener("visibilitychange", onVisible)
    return () => {
      chrome.storage.onChanged.removeListener(onStorageChange)
      document.removeEventListener("visibilitychange", onVisible)
    }
  }, [loadLibrary])

  useEffect(() => {
    void readFavorites().then(setFavorites)
    void readMergeTypes().then(setMergeTypes)
  }, [])

  const toggleMergeTypes = () => {
    setMergeTypes((previous) => {
      void writeMergeTypes(!previous)
      return !previous
    })
  }

  const entries = useMemo(() => entriesFromTree(buildGroupTree(packs)), [packs])
  const dialectLabels = useMemo(
    () =>
      new Map(
        [...bundledDialectMap().entries()].map(([id, dialect]) => [
          id,
          dialect.label
        ])
      ),
    []
  )
  const { entries: visibleEntries, favoriteCount } = useMemo(
    () => applyPaletteFilters(entries, filters, favorites),
    [entries, filters, favorites]
  )
  const facets = useMemo(
    () => buildFacets(entries, filters, favorites, dialectLabels),
    [dialectLabels, entries, filters, favorites]
  )

  const patchFilters = (patch: Partial<PaletteFilterState>) => {
    setFilters((previous) => ({ ...previous, ...patch }))
    setPage(0)
  }

  const pageCount = Math.max(1, Math.ceil(visibleEntries.length / PAGE_SIZE))
  const currentPage = Math.min(page, pageCount - 1)
  const firstOnPage = currentPage * PAGE_SIZE
  const pageEntries = visibleEntries.slice(firstOnPage, firstOnPage + PAGE_SIZE)

  // Turning the page has to start at the first row of it, not wherever the
  // previous page had been scrolled to.
  const listRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = 0
  }, [currentPage])

  const toggleStar = async (key: string) => {
    setFavorites(await toggleFavorite(key))
  }

  useEffect(() => {
    if (
      visibleEntries.length > 0 &&
      !visibleEntries.some((entry) => entry.key === selectedKey)
    ) {
      setSelectedKey(visibleEntries[0].key)
      setVariables({})
    }
  }, [selectedKey, visibleEntries])

  const selected =
    visibleEntries.find((entry) => entry.key === selectedKey) ??
    visibleEntries[0]
  const indicators = useMemo(() => toWorkspaceIndicators(iocText), [iocText])
  const dialects = useMemo(() => bundledDialectMap(), [])
  const rendered = useMemo(
    () =>
      selected
        ? renderTemplate({
            template: selected.template,
            pack: selected.pack,
            dialects,
            indicators,
            variables,
            mergeTypes
          })
        : { queries: [], uncoveredTypes: [], errors: [] },
    [dialects, indicators, mergeTypes, selected, variables]
  )
  const queryText = rendered.queries.map((query) => query.text).join("\n\n")

  const selectEntry = (entry: PaletteEntry) => {
    setSelectedKey(entry.key)
    setVariables({})
  }

  return (
    <main className="min-h-screen bg-socx-cloud px-4 py-6 font-inter text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-5">
        <header className={card}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
                SOCx
              </p>
              <h1 className="mt-1 text-2xl font-semibold">Query workspace</h1>
              <p className="mt-1 max-w-3xl text-sm text-socx-muted dark:text-socx-muted-dark">
                Paste indicators, browse every enabled template, and generate
                ready-to-use queries without opening a security console first.
              </p>
            </div>
            <button
              type="button"
              className={button}
              onClick={() =>
                chrome.tabs.create({
                  url: chrome.runtime.getURL("tabs/query-builder.html")
                })
              }>
              <PencilSquareIcon className="h-4 w-4" />
              Create custom query
            </button>
          </div>
        </header>

        {error && (
          <p className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-700 dark:text-rose-300">
            {error}
          </p>
        )}

        {/* A fixed height rather than a minimum: with a floor, a catalogue of a
            few hundred templates stretches the row and the page ends up
            scrolling instead of the list inside it. */}
        <div className="grid min-h-[32rem] gap-5 lg:h-[calc(100vh-13rem)] lg:grid-cols-[minmax(260px,0.75fr)_minmax(320px,1fr)_minmax(380px,1.35fr)]">
          <section
            className={`${card} flex min-h-0 flex-col gap-3 ${
              // A hunting playbook reads no indicator: the list stays in place,
              // so the layout does not jump, but says it is not being used.
              selected && !selected.template.requiresIocs ? "opacity-50" : ""
            }`}>
            <div>
              <h2 className="font-semibold">Indicator list</h2>
              <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                {selected && !selected.template.requiresIocs
                  ? "Not used by this hunting query."
                  : "Defanged values are normalized automatically."}
              </p>
            </div>
            <textarea
              className={`${input} socx-scroll min-h-52 flex-1 resize-none font-mono text-xs`}
              placeholder="8.8.8.8&#10;evil.example&#10;https://example.test/path"
              value={iocText}
              onChange={(event) => setIocText(event.target.value)}
            />
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                {indicators.length} unique indicators detected
              </p>
              <button
                type="button"
                aria-pressed={mergeTypes}
                onClick={toggleMergeTypes}
                title={
                  mergeTypes
                    ? "Every indicator type is compared in one query, each against its own field"
                    : "Each indicator type gets its own query"
                }
                className={`rounded-full border px-3 py-1 text-[11px] font-semibold transition ${
                  mergeTypes
                    ? "border-socx-accent bg-socx-accent/15"
                    : "border-socx-border-light text-socx-muted hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark dark:text-socx-muted-dark"
                }`}>
                {mergeTypes ? "Single query" : "One per type"}
              </button>
            </div>
          </section>

          <section className={`${card} flex min-h-0 flex-col gap-3`}>
            <div className="relative">
              <MagnifyingGlassIcon className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-socx-muted" />
              <input
                className={`${input} pl-9`}
                type="search"
                placeholder="Search a name, a description, a field or a value"
                value={filters.search}
                onChange={(event) =>
                  patchFilters({ search: event.target.value })
                }
              />
            </div>

            {/* IOC and hunting queries are two libraries, not two values of a
                filter, so they get a segmented control of their own — visually
                separated from the controls that narrow the list. */}
            <div
              role="tablist"
              aria-label="Query library"
              className="inline-flex w-full items-center gap-1 rounded-full border border-socx-border-light bg-socx-cloud-soft/60 p-1 dark:border-socx-border-dark dark:bg-socx-panel/50">
              {(
                [
                  { value: "all", label: "All queries" },
                  { value: "ioc", label: KIND_LABELS.ioc },
                  { value: "standard", label: KIND_LABELS.standard }
                ] as { value: "all" | PackKind; label: string }[]
              ).map((tab) => {
                const active = filters.kind === tab.value
                const count =
                  tab.value === "all"
                    ? facets.kinds.reduce((sum, row) => sum + row.count, 0)
                    : (facets.kinds.find((row) => row.value === tab.value)
                        ?.count ?? 0)
                return (
                  <button
                    key={tab.value}
                    type="button"
                    role="tab"
                    aria-selected={active}
                    onClick={() => patchFilters({ kind: tab.value })}
                    className={`inline-flex flex-1 items-center justify-center gap-1.5 rounded-full px-3 py-1 text-xs font-bold transition ${
                      active
                        ? "bg-socx-accent text-socx-ink"
                        : "text-socx-muted hover:text-socx-accent dark:text-socx-muted-dark"
                    }`}>
                    {tab.label}
                    <span className="tabular-nums opacity-70">{count}</span>
                  </button>
                )
              })}
            </div>

            <div className="grid gap-2 border-t border-socx-border-light pt-3 sm:grid-cols-2 dark:border-socx-border-dark">
              <button
                type="button"
                aria-pressed={filters.favoritesOnly}
                onClick={() =>
                  patchFilters({ favoritesOnly: !filters.favoritesOnly })
                }
                className={`inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-semibold transition ${
                  filters.favoritesOnly
                    ? "border-socx-accent bg-socx-accent/15"
                    : "border-socx-border-light text-socx-muted hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark dark:text-socx-muted-dark"
                }`}>
                ★ {FAVORITES_LABEL}
                <span className="tabular-nums opacity-70">
                  {facets.favorites}
                </span>
              </button>
              <select
                aria-label="Filter by query language"
                className={input}
                value={filters.dialect}
                onChange={(event) =>
                  patchFilters({ dialect: event.target.value })
                }>
                <option value="all">Language: all</option>
                {facets.dialects.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label} ({option.count})
                  </option>
                ))}
              </select>
              <select
                aria-label="Filter by category"
                className={input}
                value={filters.group}
                onChange={(event) =>
                  patchFilters({ group: event.target.value })
                }>
                <option value="all">Category: all</option>
                {facets.groups.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label} ({option.count})
                  </option>
                ))}
              </select>
              {facets.custom.map((facet) => {
                const selectedValue = filters.labels?.[facet.id] ?? "all"
                return (
                  <select
                    key={facet.id}
                    aria-label={`Filter by ${facet.label}`}
                    title={facet.description}
                    className={input}
                    value={selectedValue}
                    onChange={(event) =>
                      patchFilters({
                        labels: {
                          ...filters.labels,
                          [facet.id]: event.target.value
                        }
                      })
                    }>
                    <option value="all">{facet.label}: all</option>
                    {facet.options.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label} ({option.count})
                      </option>
                    ))}
                  </select>
                )
              })}
            </div>

            <div className="flex items-center justify-between gap-2">
              <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                {visibleEntries.length === 0
                  ? `0 of ${entries.length} templates`
                  : `${firstOnPage + 1}–${Math.min(
                      firstOnPage + PAGE_SIZE,
                      visibleEntries.length
                    )} of ${visibleEntries.length} templates`}
              </p>
              {hasActiveFilters(filters) && (
                <button
                  type="button"
                  className="text-xs font-semibold text-socx-muted underline transition hover:text-socx-accent dark:text-socx-muted-dark"
                  onClick={() => {
                    setFilters({ ...ALL_FILTERS, labels: {} })
                    setPage(0)
                  }}>
                  Clear filters
                </button>
              )}
            </div>

            <div
              ref={listRef}
              className="socx-scroll min-h-0 flex-1 space-y-1 overflow-y-auto pr-1">
              {loading ? (
                <p className="py-6 text-center text-sm text-socx-muted">
                  Loading query packs…
                </p>
              ) : visibleEntries.length === 0 ? (
                <p className="rounded-xl border border-dashed border-socx-border-light p-4 text-sm text-socx-muted dark:border-socx-border-dark">
                  {filters.favoritesOnly && favorites.length === 0
                    ? "No favorite yet. Star a query with the ☆ next to its name."
                    : "No query matches these filters."}
                </p>
              ) : (
                pageEntries.map((entry, indexOnPage) => {
                  const index = firstOnPage + indexOnPage
                  const starred = favorites.includes(entry.key)
                  const labels = Object.values(resolveEntryLabels(entry)).flat()
                  return (
                    <React.Fragment key={entry.key}>
                      {index === 0 && favoriteCount > 0 && (
                        <p className="px-1 pt-1 text-[10px] font-bold uppercase tracking-[0.12em] text-socx-accent">
                          ★ {FAVORITES_LABEL}
                        </p>
                      )}
                      {index === favoriteCount && favoriteCount > 0 && (
                        <p className="px-1 pt-3 text-[10px] font-bold uppercase tracking-[0.12em] text-socx-muted dark:text-socx-muted-dark">
                          All queries
                        </p>
                      )}
                      <div
                        className={`flex items-start gap-2 rounded-xl border px-3 py-2 transition ${
                          entry.key === selected?.key
                            ? "border-socx-accent bg-socx-accent/15"
                            : "border-socx-border-light hover:border-socx-accent dark:border-socx-border-dark"
                        }`}>
                        <button
                          type="button"
                          onClick={() => selectEntry(entry)}
                          className="min-w-0 flex-1 text-left">
                          <p className="truncate text-sm font-semibold">
                            {entry.template.name}
                          </p>
                          {entry.template.description && (
                            <p className="truncate text-[11px] text-socx-muted dark:text-socx-muted-dark">
                              {entry.template.description}
                            </p>
                          )}
                          <p className="truncate text-[11px] text-socx-muted dark:text-socx-muted-dark">
                            {entry.path.join(" › ")} · {entry.pack.name} ·{" "}
                            {dialectChipLabel(entryDialect(entry))}
                            {labels.length > 0 && ` · ${labels.join(" · ")}`}
                          </p>
                        </button>
                        <button
                          type="button"
                          aria-pressed={starred}
                          aria-label={
                            starred
                              ? "Remove from favorites"
                              : "Add to favorites"
                          }
                          title={
                            starred
                              ? "Remove from favorites"
                              : "Add to favorites"
                          }
                          onClick={() => void toggleStar(entry.key)}
                          className={`shrink-0 rounded-full px-1 text-base leading-none transition ${
                            starred
                              ? "text-socx-accent"
                              : "text-socx-muted hover:text-socx-accent dark:text-socx-muted-dark"
                          }`}>
                          {starred ? "★" : "☆"}
                        </button>
                      </div>
                    </React.Fragment>
                  )
                })
              )}
            </div>

            {pageCount > 1 && (
              <div className="flex items-center justify-between gap-2 border-t border-socx-border-light pt-3 dark:border-socx-border-dark">
                <button
                  type="button"
                  disabled={currentPage === 0}
                  onClick={() => setPage(currentPage - 1)}
                  className="rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark">
                  ‹ Previous
                </button>
                <p className="text-xs font-semibold text-socx-muted dark:text-socx-muted-dark">
                  Page {currentPage + 1} of {pageCount}
                </p>
                <button
                  type="button"
                  disabled={currentPage >= pageCount - 1}
                  onClick={() => setPage(currentPage + 1)}
                  className="rounded-full border border-socx-border-light px-3 py-1 text-xs font-semibold transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark">
                  Next ›
                </button>
              </div>
            )}
          </section>

          <section className={`${card} flex min-h-0 flex-col gap-3`}>
            {!selected ? (
              <p className="text-sm text-socx-muted">
                Select a query to preview it.
              </p>
            ) : (
              <>
                {/* Name, badges, description and variable fields share a
                    capped, scrollable band, so the query underneath keeps its
                    room however much of them a template carries. */}
                <div className="socx-scroll max-h-[40%] shrink space-y-3 overflow-y-auto pr-1">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-lg font-semibold">
                        {selected.template.name}
                      </h2>
                      <button
                        type="button"
                        aria-pressed={favorites.includes(selected.key)}
                        aria-label={
                          favorites.includes(selected.key)
                            ? "Remove from favorites"
                            : "Add to favorites"
                        }
                        onClick={() => void toggleStar(selected.key)}
                        className={`rounded-full text-lg leading-none transition ${
                          favorites.includes(selected.key)
                            ? "text-socx-accent"
                            : "text-socx-muted hover:text-socx-accent dark:text-socx-muted-dark"
                        }`}>
                        {favorites.includes(selected.key) ? "★" : "☆"}
                      </button>
                      {selected.pack.verified === true && (
                        <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700 dark:text-emerald-300">
                          verified
                        </span>
                      )}
                      {Object.entries(resolveEntryLabels(selected)).map(
                        ([facetId, values]) => (
                          <span
                            key={facetId}
                            title={facetId}
                            className="rounded-full bg-socx-accent/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-socx-muted dark:text-socx-muted-dark">
                            {values.join(" · ")}
                          </span>
                        )
                      )}
                    </div>
                    <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                      {selected.pack.name} ·{" "}
                      {selected.template.dialect ?? selected.pack.dialect}
                    </p>
                    {selected.template.description && (
                      <p className="mt-2 text-sm">
                        {selected.template.description}
                      </p>
                    )}
                  </div>

                  {/* Only the variables this template substitutes: a pack
                    declares them once for all of its queries, and offering a
                    field the selected query never reads makes it look as if
                    filling it in had no effect. */}
                  <div className="grid gap-2 sm:grid-cols-2">
                    {templateVariables(selected.pack, selected.template).map(
                      (variable) =>
                        variable.type === "checkbox" ? (
                          <label
                            key={variable.id}
                            className="flex items-center gap-2 rounded-lg border border-socx-border-light px-3 py-2 text-xs dark:border-socx-border-dark"
                            title={variable.description}>
                            <input
                              type="checkbox"
                              aria-label={variable.label}
                              className="h-4 w-4 accent-socx-teal"
                              checked={
                                (variables[variable.id] ??
                                  variable.default ??
                                  "false") === "true"
                              }
                              onChange={(event) =>
                                setVariables((previous) => ({
                                  ...previous,
                                  [variable.id]: String(event.target.checked)
                                }))
                              }
                            />
                            <span className="font-semibold">
                              {variable.label}
                            </span>
                          </label>
                        ) : (
                          <label
                            key={variable.id}
                            className="space-y-1 text-xs"
                            title={variable.description}>
                            <span className="font-semibold">
                              {variable.label}
                            </span>
                            {variable.options?.length ? (
                              <select
                                className={input}
                                value={
                                  variables[variable.id] ??
                                  variable.default ??
                                  ""
                                }
                                onChange={(event) =>
                                  setVariables((previous) => ({
                                    ...previous,
                                    [variable.id]: event.target.value
                                  }))
                                }>
                                {variable.options.map((option) => (
                                  <option key={option} value={option}>
                                    {option}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              <input
                                className={input}
                                value={
                                  variables[variable.id] ??
                                  variable.default ??
                                  ""
                                }
                                onChange={(event) =>
                                  setVariables((previous) => ({
                                    ...previous,
                                    [variable.id]: event.target.value
                                  }))
                                }
                              />
                            )}
                          </label>
                        )
                    )}
                  </div>
                </div>

                {(rendered.errors.length > 0 ||
                  rendered.uncoveredTypes.length > 0 ||
                  rendered.mergeRefusal) && (
                  <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-800 dark:text-amber-200">
                    {rendered.errors.map((message) => (
                      <p key={message}>{message}</p>
                    ))}
                    {rendered.uncoveredTypes.length > 0 && (
                      <p>
                        Not covered by this template:{" "}
                        {rendered.uncoveredTypes.join(", ")}
                      </p>
                    )}
                    {rendered.mergeRefusal && (
                      <p>One query per type: {rendered.mergeRefusal}.</p>
                    )}
                  </div>
                )}

                {/* min-h-0, so the preview scrolls inside the card instead of
                    pushing past it when the column has a fixed height. */}
                <div className="socx-scroll min-h-[8rem] flex-1 space-y-3 overflow-y-auto">
                  {rendered.queries.length === 0 ? (
                    <p className="rounded-xl border border-dashed border-socx-border-light p-4 text-sm text-socx-muted dark:border-socx-border-dark">
                      {selected.template.requiresIocs
                        ? "Add at least one supported indicator to generate this query."
                        : "This query could not be rendered."}
                    </p>
                  ) : (
                    rendered.queries.map((query, index) => (
                      <div key={`${query.type ?? "standard"}-${index}`}>
                        <p className="mb-1 text-[11px] text-socx-muted dark:text-socx-muted-dark">
                          {query.types?.length
                            ? `${query.types.join(", ")} · ${query.count} indicators`
                            : query.type
                              ? `${query.type} · ${query.count} indicators`
                              : "Standard query"}
                          {query.chunks > 1 &&
                            ` · chunk ${query.chunk}/${query.chunks}`}
                          {query.overLength && " · exceeds typical length"}
                        </p>
                        <pre className="whitespace-pre-wrap break-words rounded-xl bg-socx-cloud-soft/80 p-3 font-mono text-xs dark:bg-socx-panel/70">
                          {query.text}
                        </pre>
                      </div>
                    ))
                  )}
                </div>

                <button
                  type="button"
                  className={primaryButton}
                  disabled={!queryText}
                  onClick={() =>
                    writeIntelClipboardText(queryText, {
                      successMessage: "✔️ Query copied"
                    })
                  }>
                  <ClipboardDocumentListIcon className="h-4 w-4" />
                  Copy generated query
                </button>
              </>
            )}
          </section>
        </div>
      </div>
    </main>
  )
}

export default QueryWorkspace
