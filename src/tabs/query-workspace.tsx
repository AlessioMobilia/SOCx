import {
  ClipboardDocumentListIcon,
  MagnifyingGlassIcon,
  PencilSquareIcon
} from "@heroicons/react/24/outline"
import React, { useEffect, useMemo, useState } from "react"

import { sendToBackground } from "@plasmohq/messaging"

import "../styles/tailwind.css"

import { writeIntelClipboardText } from "../utility/clipboard"
import { buildGroupTree } from "../utility/query/groups"
import type { PackKind, QueryPack } from "../utility/query/packSchema"
import {
  entriesFromTree,
  rankEntries,
  type PaletteEntry
} from "../utility/query/palette"
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

const QueryWorkspace = () => {
  const launch = useMemo(() => parseQueryWorkspaceHash(location.hash), [])
  const [packs, setPacks] = useState<QueryPack[]>([])
  const [iocText, setIocText] = useState(launch.indicators.join("\n"))
  const [search, setSearch] = useState("")
  const [kind, setKind] = useState<"all" | PackKind>("all")
  const [selectedKey, setSelectedKey] = useState(launch.templateKey ?? "")
  const [variables, setVariables] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  useEffect(() => {
    const load = async () => {
      const dark = await ensureIsDarkMode()
      document.body.className = dark ? "dark-mode" : "light-mode"
      try {
        const response = await sendToBackground<unknown, LibraryResponse>({
          name: "query-library",
          body: { matchPlatform: false, includeIndicators: true }
        })
        setPacks(response?.packs ?? [])
        if (launch.indicators.length === 0 && response?.indicators?.length) {
          setIocText(response.indicators.join("\n"))
        }
      } catch (loadError) {
        console.error("Unable to load the query library:", loadError)
        setError("Unable to load query packs. Refresh them from SOCx options.")
      } finally {
        setLoading(false)
      }
    }
    void load()
  }, [launch.indicators])

  const entries = useMemo(() => entriesFromTree(buildGroupTree(packs)), [packs])
  const visibleEntries = useMemo(() => {
    const scoped =
      kind === "all"
        ? entries
        : entries.filter((entry) => entry.pack.kind === kind)
    return rankEntries(scoped, search)
  }, [entries, kind, search])

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
            variables
          })
        : { queries: [], uncoveredTypes: [], errors: [] },
    [dialects, indicators, selected, variables]
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

        <div className="grid min-h-[68vh] gap-5 lg:grid-cols-[minmax(260px,0.75fr)_minmax(320px,1fr)_minmax(380px,1.35fr)]">
          <section className={`${card} flex min-h-0 flex-col gap-3`}>
            <div>
              <h2 className="font-semibold">Indicator list</h2>
              <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                Defanged values are normalized automatically.
              </p>
            </div>
            <textarea
              className={`${input} socx-scroll min-h-52 flex-1 resize-none font-mono text-xs`}
              placeholder="8.8.8.8&#10;evil.example&#10;https://example.test/path"
              value={iocText}
              onChange={(event) => setIocText(event.target.value)}
            />
            <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
              {indicators.length} unique indicators detected
            </p>
          </section>

          <section className={`${card} flex min-h-0 flex-col gap-3`}>
            <div className="relative">
              <MagnifyingGlassIcon className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-socx-muted" />
              <input
                className={`${input} pl-9`}
                type="search"
                placeholder="Search name, pack, tag or group"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>
            <select
              className={input}
              value={kind}
              onChange={(event) =>
                setKind(event.target.value as "all" | PackKind)
              }>
              <option value="all">All query types</option>
              <option value="ioc">IOC queries</option>
              <option value="standard">Standard hunting queries</option>
            </select>
            <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
              {visibleEntries.length} of {entries.length} templates
            </p>
            <div className="socx-scroll min-h-0 flex-1 space-y-1 overflow-y-auto pr-1">
              {loading ? (
                <p className="py-6 text-center text-sm text-socx-muted">
                  Loading query packs…
                </p>
              ) : visibleEntries.length === 0 ? (
                <p className="rounded-xl border border-dashed border-socx-border-light p-4 text-sm text-socx-muted dark:border-socx-border-dark">
                  No query matches these filters.
                </p>
              ) : (
                visibleEntries.map((entry) => (
                  <button
                    type="button"
                    key={entry.key}
                    onClick={() => selectEntry(entry)}
                    className={`w-full rounded-xl border px-3 py-2 text-left transition ${
                      entry.key === selected?.key
                        ? "border-socx-accent bg-socx-accent/15"
                        : "border-socx-border-light hover:border-socx-accent dark:border-socx-border-dark"
                    }`}>
                    <p className="text-sm font-semibold">
                      {entry.template.name}
                    </p>
                    <p className="truncate text-[11px] text-socx-muted dark:text-socx-muted-dark">
                      {entry.path.join(" › ")} · {entry.pack.name} ·{" "}
                      {entry.template.dialect ?? entry.pack.dialect}
                    </p>
                  </button>
                ))
              )}
            </div>
          </section>

          <section className={`${card} flex min-h-0 flex-col gap-3`}>
            {!selected ? (
              <p className="text-sm text-socx-muted">
                Select a query to preview it.
              </p>
            ) : (
              <>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-lg font-semibold">
                      {selected.template.name}
                    </h2>
                    {selected.pack.verified === true && (
                      <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700 dark:text-emerald-300">
                        verified
                      </span>
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

                {(selected.pack.variables ?? []).map((variable) => (
                  <label key={variable.id} className="space-y-1 text-xs">
                    <span className="font-semibold">{variable.label}</span>
                    {variable.options?.length ? (
                      <select
                        className={input}
                        value={variables[variable.id] ?? variable.default ?? ""}
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
                        value={variables[variable.id] ?? variable.default ?? ""}
                        onChange={(event) =>
                          setVariables((previous) => ({
                            ...previous,
                            [variable.id]: event.target.value
                          }))
                        }
                      />
                    )}
                  </label>
                ))}

                {(rendered.errors.length > 0 ||
                  rendered.uncoveredTypes.length > 0) && (
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
                  </div>
                )}

                <div className="socx-scroll min-h-52 flex-1 space-y-3 overflow-y-auto">
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
                          {query.type
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
