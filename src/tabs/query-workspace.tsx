import {
  AdjustmentsHorizontalIcon,
  ChevronDownIcon,
  ClipboardDocumentListIcon,
  MagnifyingGlassIcon,
  PencilSquareIcon,
  QuestionMarkCircleIcon
} from "@heroicons/react/24/outline"
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { createPortal } from "react-dom"

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
import QueryLanguageGuides from "./QueryLanguageGuides"

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

type TooltipPosition = { left: number; top: number; above: boolean }

const InfoTooltip = ({ text, label }: { text: string; label: string }) => {
  const buttonRef = useRef<HTMLButtonElement>(null)
  const tooltipId = React.useId()
  const [open, setOpen] = useState(false)
  const [position, setPosition] = useState<TooltipPosition>({
    left: 0,
    top: 0,
    above: false
  })

  const updatePosition = useCallback(() => {
    const button = buttonRef.current
    if (!button) return
    const rect = button.getBoundingClientRect()
    const tooltipWidth = 256
    const viewportMargin = 12
    const roomBelow = window.innerHeight - rect.bottom
    const above = roomBelow < 150 && rect.top > roomBelow
    setPosition({
      left: Math.min(
        window.innerWidth - tooltipWidth / 2 - viewportMargin,
        Math.max(tooltipWidth / 2 + viewportMargin, rect.left + rect.width / 2)
      ),
      top: above ? rect.top - 8 : rect.bottom + 8,
      above
    })
  }, [])

  const show = () => {
    updatePosition()
    setOpen(true)
  }

  useEffect(() => {
    if (!open) return
    updatePosition()
    window.addEventListener("resize", updatePosition)
    window.addEventListener("scroll", updatePosition, true)
    return () => {
      window.removeEventListener("resize", updatePosition)
      window.removeEventListener("scroll", updatePosition, true)
    }
  }, [open, updatePosition])

  return (
    <span className="inline-flex shrink-0">
      <button
        ref={buttonRef}
        type="button"
        aria-label={label}
        aria-describedby={open ? tooltipId : undefined}
        onMouseEnter={show}
        onMouseLeave={() => setOpen(false)}
        onFocus={show}
        onBlur={() => setOpen(false)}
        onKeyDown={(event) => {
          if (event.key === "Escape") setOpen(false)
        }}
        className="rounded-full text-socx-muted outline-none transition hover:text-socx-accent focus-visible:ring-2 focus-visible:ring-socx-accent dark:text-socx-muted-dark">
        <QuestionMarkCircleIcon className="h-4 w-4" />
      </button>
      {open &&
        createPortal(
          <span
            id={tooltipId}
            role="tooltip"
            style={{
              left: position.left,
              top: position.top,
              transform: `translate(-50%, ${position.above ? "-100%" : "0"})`
            }}
            className="pointer-events-none fixed z-[9999] w-64 rounded-lg border border-socx-border-light bg-white px-3 py-2 text-left text-[11px] font-normal leading-relaxed text-socx-ink shadow-xl dark:border-socx-border-dark dark:bg-socx-panel dark:text-white">
            {text}
          </span>,
          document.body
        )}
    </span>
  )
}

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

    const storageChanges = globalThis.chrome?.storage?.onChanged
    storageChanges?.addListener(onStorageChange)
    document.addEventListener("visibilitychange", onVisible)
    return () => {
      storageChanges?.removeListener(onStorageChange)
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
  const activeNarrowFilterCount =
    Number(filters.favoritesOnly) +
    Number(filters.dialect !== "all") +
    Number(filters.group !== "all") +
    Object.values(filters.labels ?? {}).filter((value) => value !== "all")
      .length

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
      <div className="mx-auto flex w-full max-w-[1680px] flex-col gap-5">
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
        <div className="grid min-h-[32rem] gap-5 lg:h-[calc(100vh-10.5rem)] lg:grid-cols-[minmax(220px,0.65fr)_minmax(360px,1.2fr)_minmax(330px,1fr)]">
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
              <span className="flex items-center gap-1.5">
                <button
                  type="button"
                  aria-pressed={mergeTypes}
                  onClick={toggleMergeTypes}
                  className={`rounded-full border px-3 py-1 text-[11px] font-semibold transition ${
                    mergeTypes
                      ? "border-socx-accent bg-socx-accent/15"
                      : "border-socx-border-light text-socx-muted hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark dark:text-socx-muted-dark"
                  }`}>
                  {mergeTypes ? "Single query" : "One per type"}
                </button>
                <InfoTooltip
                  label="About query splitting"
                  text={
                    mergeTypes
                      ? "Builds one query that compares every detected IOC type with its matching field. The renderer falls back to separate queries when the template cannot merge safely."
                      : "Builds a separate query for every detected IOC type, useful when a console or template cannot combine fields."
                  }
                />
              </span>
            </div>
          </section>

          <section className={`${card} flex min-h-0 flex-col gap-2 lg:p-4`}>
            <div className="space-y-1">
              <div className="flex items-center justify-between gap-2 text-xs font-semibold">
                <span className="inline-flex items-center gap-1.5">
                  <label htmlFor="query-template-search">Find a query</label>
                  <InfoTooltip
                    label="About query search"
                    text="Searches template names and descriptions first, then query text, fields, tables, operators, tags and ATT&CK identifiers. Separate terms must all match."
                  />
                </span>
                {hasActiveFilters(filters) && (
                  <button
                    type="button"
                    className="text-[11px] font-semibold text-socx-muted underline transition hover:text-socx-accent dark:text-socx-muted-dark"
                    onClick={() => {
                      setFilters({ ...ALL_FILTERS, labels: {} })
                      setPage(0)
                    }}>
                    Clear filters
                  </button>
                )}
              </div>
              <div className="relative">
                <MagnifyingGlassIcon className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-socx-muted" />
                <input
                  id="query-template-search"
                  className={`${input} pl-9`}
                  type="search"
                  placeholder="Name, field, command, value or ATT&CK ID"
                  value={filters.search}
                  onChange={(event) =>
                    patchFilters({ search: event.target.value })
                  }
                />
              </div>
            </div>

            {/* IOC and hunting queries are two libraries, not two values of a
                filter, so they get a segmented control of their own — visually
                separated from the controls that narrow the list. */}
            <div className="flex items-center gap-2">
              <div
                role="tablist"
                aria-label="Query library"
                className="inline-flex min-w-0 flex-1 items-center gap-1 rounded-full border border-socx-border-light bg-socx-cloud-soft/60 p-1 dark:border-socx-border-dark dark:bg-socx-panel/50">
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
                      title={
                        tab.value === "all"
                          ? "Show IOC templates and complete hunting playbooks"
                          : tab.value === "ioc"
                            ? "Show templates that insert the indicators from the left panel"
                            : "Show complete hunting playbooks, including queries that do not require indicators"
                      }
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
              <InfoTooltip
                label="About query types"
                text="IOC queries insert the indicators from the left panel. Hunting queries are complete playbooks and may not require any indicator."
              />
            </div>

            <details className="group/filters rounded-xl border border-socx-border-light bg-socx-cloud-soft/35 dark:border-socx-border-dark dark:bg-socx-panel/30">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-2 rounded-xl px-3 py-2 text-xs font-semibold marker:hidden transition hover:bg-socx-accent/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-socx-accent [&::-webkit-details-marker]:hidden">
                <span className="inline-flex items-center gap-2">
                  <AdjustmentsHorizontalIcon className="h-4 w-4 text-socx-muted" />
                  More filters
                  {activeNarrowFilterCount > 0 && (
                    <span className="rounded-full bg-socx-accent px-1.5 py-0.5 text-[10px] font-bold text-socx-ink">
                      {activeNarrowFilterCount} active
                    </span>
                  )}
                </span>
                <span className="inline-flex items-center gap-1 text-[10px] text-socx-muted dark:text-socx-muted-dark">
                  <span className="tabular-nums">
                    {visibleEntries.length} matches
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="group-open/filters:hidden">Show</span>
                  <span className="hidden group-open/filters:inline">Hide</span>
                  <ChevronDownIcon className="h-3.5 w-3.5 transition group-open/filters:rotate-180" />
                </span>
              </summary>
              <div className="grid gap-2 border-t border-socx-border-light px-3 py-3 dark:border-socx-border-dark sm:grid-cols-2">
                <div className="space-y-1">
                  <div className="flex items-center gap-1.5 text-[11px] font-semibold text-socx-muted dark:text-socx-muted-dark">
                    <span>Shortlist</span>
                    <InfoTooltip
                      label="About favorites filter"
                      text="Shows only templates you starred. Stars are stored in this browser and favorites are also kept at the top of unfiltered results."
                    />
                  </div>
                  <button
                    type="button"
                    aria-pressed={filters.favoritesOnly}
                    onClick={() =>
                      patchFilters({
                        favoritesOnly: !filters.favoritesOnly
                      })
                    }
                    className={`inline-flex w-full items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-semibold transition ${
                      filters.favoritesOnly
                        ? "border-socx-accent bg-socx-accent/15"
                        : "border-socx-border-light text-socx-muted hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark dark:text-socx-muted-dark"
                    }`}>
                    ★ {FAVORITES_LABEL}
                    <span className="tabular-nums opacity-70">
                      {facets.favorites}
                    </span>
                  </button>
                </div>
                <div className="space-y-1 text-[11px] font-semibold text-socx-muted dark:text-socx-muted-dark">
                  <span className="flex items-center gap-1.5">
                    <label htmlFor="query-language-filter">Language</label>
                    <InfoTooltip
                      label="About language filter"
                      text="Keeps templates written for one query dialect. Similar product names do not imply compatible syntax; Microsoft KQL and Elastic KQL are separate choices."
                    />
                  </span>
                  <select
                    id="query-language-filter"
                    aria-label="Filter by query language"
                    className={input}
                    value={filters.dialect}
                    onChange={(event) =>
                      patchFilters({ dialect: event.target.value })
                    }>
                    <option value="all">All languages</option>
                    {facets.dialects.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label} ({option.count})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="space-y-1 text-[11px] font-semibold text-socx-muted dark:text-socx-muted-dark">
                  <span className="flex items-center gap-1.5">
                    <label htmlFor="query-category-filter">Category</label>
                    <InfoTooltip
                      label="About category filter"
                      text="Keeps templates from one top-level investigation category, such as network, endpoint, identity or email. Categories come from the enabled packs."
                    />
                  </span>
                  <select
                    id="query-category-filter"
                    aria-label="Filter by category"
                    className={input}
                    value={filters.group}
                    onChange={(event) =>
                      patchFilters({ group: event.target.value })
                    }>
                    <option value="all">All categories</option>
                    {facets.groups.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label} ({option.count})
                      </option>
                    ))}
                  </select>
                </div>
                {facets.custom.map((facet) => {
                  const selectedValue = filters.labels?.[facet.id] ?? "all"
                  return (
                    <div
                      key={facet.id}
                      className="space-y-1 text-[11px] font-semibold text-socx-muted dark:text-socx-muted-dark">
                      <span className="flex items-center gap-1.5">
                        <label htmlFor={`query-facet-${facet.id}`}>
                          {facet.label}
                        </label>
                        <InfoTooltip
                          label={`About ${facet.label} filter`}
                          text={
                            facet.description ||
                            `Keeps templates tagged with one ${facet.label} value declared by the enabled query packs.`
                          }
                        />
                      </span>
                      <select
                        id={`query-facet-${facet.id}`}
                        aria-label={`Filter by ${facet.label}`}
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
                        <option value="all">
                          All {facet.label.toLowerCase()}
                        </option>
                        {facet.options.map((option) => (
                          <option key={option.value} value={option.value}>
                            {option.label} ({option.count})
                          </option>
                        ))}
                      </select>
                    </div>
                  )
                })}
              </div>
            </details>

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
                          <p className="break-words text-sm font-semibold leading-snug">
                            {entry.template.name}
                          </p>
                          {entry.template.description &&
                            entry.key === selected?.key && (
                              <p className="mt-0.5 line-clamp-1 text-[11px] leading-relaxed text-socx-muted dark:text-socx-muted-dark">
                                {entry.template.description}
                              </p>
                            )}
                          <span className="mt-1 flex flex-wrap items-center gap-1 text-[10px] text-socx-muted dark:text-socx-muted-dark">
                            <span className="max-w-full break-words">
                              {entry.path.join(" › ")}
                            </span>
                            <span aria-hidden="true">·</span>
                            <span className="max-w-full break-words">
                              {entry.pack.name}
                            </span>
                            <span className="rounded-full bg-socx-accent/10 px-1.5 py-0.5 font-semibold">
                              {dialectChipLabel(entryDialect(entry))}
                            </span>
                            {labels.map((label, labelIndex) => (
                              <span
                                key={`${label}-${labelIndex}`}
                                className="rounded-full border border-socx-border-light px-1.5 py-0.5 dark:border-socx-border-dark">
                                {label}
                              </span>
                            ))}
                          </span>
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
                          className={`shrink-0 rounded-full p-1.5 text-base leading-none transition ${
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
                          <div
                            key={variable.id}
                            className="flex items-center justify-between gap-2 rounded-lg border border-socx-border-light px-3 py-2 text-xs dark:border-socx-border-dark">
                            <label className="flex min-w-0 cursor-pointer items-center gap-2">
                              <input
                                type="checkbox"
                                role="switch"
                                aria-label={variable.label}
                                className="peer sr-only"
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
                              <span className="relative h-5 w-9 shrink-0 rounded-full border border-socx-border-light bg-socx-cloud-soft transition after:absolute after:left-0.5 after:top-0.5 after:h-3.5 after:w-3.5 after:rounded-full after:bg-socx-muted after:transition peer-checked:border-socx-accent peer-checked:bg-socx-accent/25 peer-checked:after:translate-x-4 peer-checked:after:bg-socx-accent-muted peer-focus-visible:ring-2 peer-focus-visible:ring-socx-accent dark:border-socx-border-dark dark:bg-socx-panel" />
                              <span className="truncate font-semibold">
                                {variable.label}
                              </span>
                            </label>
                            <InfoTooltip
                              label={`About ${variable.label}`}
                              text={
                                variable.description ||
                                `Turns ${variable.label} on or off in the generated query.`
                              }
                            />
                          </div>
                        ) : (
                          <div key={variable.id} className="space-y-1 text-xs">
                            <span className="flex items-center gap-1.5 font-semibold">
                              <label htmlFor={`query-variable-${variable.id}`}>
                                {variable.label}
                              </label>
                              <InfoTooltip
                                label={`About ${variable.label}`}
                                text={
                                  variable.description ||
                                  `Sets the ${variable.label} value inserted into the generated query.`
                                }
                              />
                            </span>
                            {variable.options?.length ? (
                              <select
                                id={`query-variable-${variable.id}`}
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
                                id={`query-variable-${variable.id}`}
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
                          </div>
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

        <QueryLanguageGuides dialects={dialects} />
      </div>
    </main>
  )
}

export default QueryWorkspace
