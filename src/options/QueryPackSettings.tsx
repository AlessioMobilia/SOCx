import {
  ArrowPathIcon,
  ArrowTopRightOnSquareIcon,
  ArrowUpTrayIcon,
  CheckCircleIcon,
  CommandLineIcon,
  MagnifyingGlassIcon,
  PlusCircleIcon,
  TrashIcon
} from "@heroicons/react/24/outline"
import React, { useCallback, useEffect, useState } from "react"

import { sendToBackground } from "@plasmohq/messaging"

import type { PackKind } from "../utility/query/packSchema"
import {
  QUERY_PACK_REPOSITORY,
  toRawPackUrl,
  type PackSource
} from "../utility/query/packSources"
import { readUserLibrary, writeUserLibrary } from "../utility/query/registry"
import { QUERY_COMMAND, shortcutSettingsUrl } from "../utility/query/shortcut"
import { importUserPackText } from "../utility/query/userImport"

const cardClass =
  "rounded-socx-lg border border-socx-border-light bg-white/90 p-6 shadow-sm dark:border-socx-border-dark dark:bg-socx-night-soft/80"
const labelClass =
  "text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark"
const inputClass =
  "w-full rounded-lg border border-socx-border-light bg-white/85 px-3 py-2 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
const buttonClass =
  "inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-3 py-1.5 text-xs font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white"

type Outcome = {
  sourceId: string
  status: string
  message?: string
  packCount?: number
}

export interface QueryPackSettingsProps {
  paletteEnabled: boolean
  menuEnabled: boolean
  paletteScope: "matched" | "all"
  onPaletteToggle: (value: boolean) => void
  onMenuToggle: (value: boolean) => void
  onPaletteScopeChange: (value: "matched" | "all") => void
}

const STATUS_TONE: Record<string, string> = {
  ok: "text-emerald-600 dark:text-emerald-400",
  changed: "text-amber-600 dark:text-amber-400",
  error: "text-rose-600 dark:text-rose-400",
  html: "text-rose-600 dark:text-rose-400",
  never: "text-socx-muted dark:text-socx-muted-dark"
}

const QueryPackSettings: React.FC<QueryPackSettingsProps> = ({
  paletteEnabled,
  menuEnabled,
  paletteScope,
  onPaletteToggle,
  onMenuToggle,
  onPaletteScopeChange
}) => {
  const [sources, setSources] = useState<PackSource[]>([])
  const [outcomes, setOutcomes] = useState<Record<string, Outcome>>({})
  const [busy, setBusy] = useState(false)
  const [newUrl, setNewUrl] = useState("")
  const [newLabel, setNewLabel] = useState("")
  const [newToken, setNewToken] = useState("")
  const [newKind, setNewKind] = useState<PackKind>("ioc")
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [shortcut, setShortcut] = useState("")

  const call = useCallback(async (body: unknown) => {
    setBusy(true)
    try {
      const response = await sendToBackground<
        unknown,
        { sources?: PackSource[]; outcomes?: Outcome[]; error?: string }
      >({ name: "query-sources", body })
      setError(response?.error ?? "")
      if (response?.sources) setSources(response.sources)
      if (response?.outcomes) {
        setOutcomes((previous) => {
          const next = { ...previous }
          for (const outcome of response.outcomes!) {
            next[outcome.sourceId] = outcome
          }
          return next
        })
      }
      return response
    } finally {
      setBusy(false)
    }
  }, [])

  useEffect(() => {
    void call({ action: "list" })
    chrome.commands.getAll((commands) => {
      const command = commands.find((entry) => entry.name === QUERY_COMMAND)
      setShortcut(command?.shortcut ?? "Not assigned")
    })
  }, [call])

  const rewrite = toRawPackUrl(newUrl)

  const handleAdd = async () => {
    if (!newUrl.trim()) return
    await call({
      action: "add",
      source: {
        url: newUrl.trim(),
        kind: newKind,
        enabled: true,
        label: newLabel.trim() || undefined,
        token: newToken.trim() || undefined
      }
    })
    setNewUrl("")
    setNewLabel("")
    setNewToken("")
  }

  const handleFileImport = async (file?: File) => {
    if (!file) return
    const current = await readUserLibrary()
    const result = importUserPackText(await file.text(), current)
    if (result.errors.length > 0) {
      setError(result.errors.join(" · "))
      return
    }
    await writeUserLibrary(result.templates)
    setError("")
    setNotice(
      `${result.imported} custom quer${result.imported === 1 ? "y" : "ies"} imported.`
    )
  }

  const openShortcutSettings = () => {
    const manifest = chrome.runtime.getManifest() as chrome.runtime.Manifest & {
      browser_specific_settings?: { gecko?: unknown }
    }
    void chrome.tabs
      .create({
        url: shortcutSettingsUrl(
          Boolean(manifest.browser_specific_settings?.gecko),
          navigator.userAgent
        )
      })
      .catch(() =>
        setError(
          "The browser blocked its shortcuts page. Open the extension shortcut manager manually."
        )
      )
  }

  const renderList = (kind: PackKind) => {
    const rows = sources.filter((source) => source.kind === kind)
    if (rows.length === 0) {
      return (
        <p className="rounded-xl border border-dashed border-socx-border-light px-3 py-3 text-xs text-socx-muted dark:border-socx-border-dark dark:text-socx-muted-dark">
          No source configured.
        </p>
      )
    }

    return (
      <div className="space-y-2">
        {rows.map((source) => {
          const outcome = outcomes[source.id]
          const status = outcome?.status ?? source.lastStatus ?? "never"
          return (
            <div
              key={source.id}
              className="space-y-1 rounded-xl border border-socx-border-light px-3 py-2 dark:border-socx-border-dark">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-sm font-semibold">
                    {source.label ?? source.url}
                    {source.builtIn && (
                      <span className="ml-2 rounded-full bg-socx-accent/20 px-2 py-0.5 text-[10px] uppercase tracking-[0.2em]">
                        built-in
                      </span>
                    )}
                  </p>
                  <p className="break-all text-[11px] text-socx-muted dark:text-socx-muted-dark">
                    {source.url}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    className={buttonClass}
                    onClick={() =>
                      call({
                        action: "update",
                        id: source.id,
                        patch: { enabled: !source.enabled }
                      })
                    }>
                    {source.enabled ? "Disable" : "Enable"}
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    className={buttonClass}
                    onClick={() => call({ action: "refresh", id: source.id })}>
                    <ArrowPathIcon className="h-3.5 w-3.5" />
                    Refresh
                  </button>
                  {status === "changed" && (
                    <button
                      type="button"
                      disabled={busy}
                      className={buttonClass}
                      onClick={() =>
                        call({
                          action: "refresh",
                          id: source.id,
                          acceptChange: true
                        })
                      }>
                      <CheckCircleIcon className="h-3.5 w-3.5" />
                      Accept change
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={busy}
                    className={`${buttonClass} text-socx-danger`}
                    onClick={() => call({ action: "remove", id: source.id })}>
                    <TrashIcon className="h-3.5 w-3.5" />
                    {source.builtIn ? "Turn off" : "Remove"}
                  </button>
                </div>
              </div>
              <p
                className={`text-[11px] ${STATUS_TONE[status] ?? STATUS_TONE.never}`}>
                {status === "ok" &&
                  `${outcome?.packCount ?? source.packCount ?? 0} packs loaded${
                    source.lastFetched
                      ? ` · ${new Date(source.lastFetched).toLocaleString()}`
                      : ""
                  }`}
                {status === "changed" &&
                  "Content changed since it was last accepted — review before adopting."}
                {(status === "error" || status === "html") &&
                  (outcome?.message ?? "Last refresh failed.")}
                {status === "never" && "Never fetched."}
                {!source.enabled && " · disabled"}
              </p>
            </div>
          )
        })}
      </div>
    )
  }

  return (
    <section className={`${cardClass} space-y-5`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className={labelClass}>Query packs</p>
          <p className="mt-1 text-sm text-socx-muted dark:text-socx-muted-dark">
            Turn a list of indicators into the query your platform expects, and
            keep a library of hunting queries that need no indicator at all.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className={buttonClass}
            onClick={() =>
              chrome.tabs.create({
                url: chrome.runtime.getURL("tabs/query-workspace.html")
              })
            }>
            <MagnifyingGlassIcon className="h-3.5 w-3.5" />
            Query workspace
          </button>
          <button
            type="button"
            className={buttonClass}
            onClick={() =>
              chrome.tabs.create({
                url: chrome.runtime.getURL("tabs/query-builder.html")
              })
            }>
            <PlusCircleIcon className="h-3.5 w-3.5" />
            Create manually
          </button>
          <label className={`${buttonClass} cursor-pointer`}>
            <ArrowUpTrayIcon className="h-3.5 w-3.5" />
            Import from file
            <input
              className="hidden"
              type="file"
              accept=".json,application/json"
              onChange={(event) => {
                void handleFileImport(event.target.files?.[0])
                event.target.value = ""
              }}
            />
          </label>
          <a
            href={QUERY_PACK_REPOSITORY}
            target="_blank"
            rel="noreferrer"
            className={buttonClass}>
            <ArrowTopRightOnSquareIcon className="h-3.5 w-3.5" />
            Community packs
          </a>
        </div>
      </div>

      <div className="flex flex-col gap-3 rounded-xl border border-socx-border-light bg-white/80 px-4 py-3 dark:border-socx-border-dark dark:bg-socx-panel/50 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold">
            <CommandLineIcon className="h-4 w-4" />
            Query shortcut: {shortcut || "Loading…"}
          </p>
          <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
            Browsers only allow shortcut reassignment from their native
            extension shortcuts page.
          </p>
        </div>
        <button
          type="button"
          className={buttonClass}
          onClick={openShortcutSettings}>
          Customize shortcut
        </button>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        {[
          {
            id: "palette",
            title: "Query palette",
            helper:
              "Opens only when you ask for it: keyboard shortcut, context menu, or the SOCx UI.",
            enabled: paletteEnabled,
            onToggle: () => onPaletteToggle(!paletteEnabled)
          },
          {
            id: "menu",
            title: "Query context menu",
            helper:
              "Adds an Insert query submenu inside text fields, filtered by the console you are on.",
            enabled: menuEnabled,
            onToggle: () => onMenuToggle(!menuEnabled)
          }
        ].map((row) => (
          <div
            key={row.id}
            className="flex items-center justify-between rounded-xl border border-socx-border-light bg-white/80 px-4 py-3 dark:border-socx-border-dark dark:bg-socx-panel/50">
            <div>
              <p className="text-sm font-semibold">{row.title}</p>
              <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                {row.helper}
              </p>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={row.enabled}
              onClick={row.onToggle}
              className={`relative inline-flex h-7 w-12 items-center rounded-full border transition ${
                row.enabled
                  ? "border-socx-accent bg-socx-accent/90"
                  : "border-socx-border-light bg-white dark:border-socx-border-dark dark:bg-socx-panel"
              }`}>
              <span
                className={`inline-block h-5 w-5 rounded-full bg-white shadow transition ${
                  row.enabled ? "translate-x-5" : "translate-x-1"
                }`}
              />
            </button>
          </div>
        ))}
      </div>

      <div className="flex flex-col gap-2 rounded-xl border border-socx-border-light bg-white/80 px-4 py-3 dark:border-socx-border-dark dark:bg-socx-panel/50 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-sm font-semibold">Which packs the palette shows</p>
          <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
            Matching keeps a Splunk query from appearing on the Defender
            console. Your own templates are always available.
          </p>
        </div>
        <select
          value={paletteScope}
          onChange={(event) =>
            onPaletteScopeChange(event.target.value as "matched" | "all")
          }
          className="rounded-lg border border-socx-border-light bg-white/85 px-3 py-2 text-sm dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white">
          <option value="matched">Only the recognised console</option>
          <option value="all">Every pack, everywhere</option>
        </select>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-2">
          <p className="text-sm font-semibold">Indicator packs</p>
          {renderList("ioc")}
        </div>
        <div className="space-y-2">
          <p className="text-sm font-semibold">Standard query packs</p>
          {renderList("standard")}
        </div>
      </div>

      <div className="space-y-2 rounded-xl border border-socx-border-light p-4 dark:border-socx-border-dark">
        <p className="text-sm font-semibold">Add custom queries from a link</p>
        <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
          A GitHub or GitLab link, a gist, or an internal HTTPS server. Links
          copied from the browser address bar are rewritten to their raw form
          automatically.
        </p>
        <div className="grid gap-2 md:grid-cols-4">
          <input
            className={`${inputClass} md:col-span-2`}
            placeholder="https://github.com/org/repo/blob/main/index.json"
            value={newUrl}
            onChange={(event) => setNewUrl(event.target.value)}
          />
          <input
            className={inputClass}
            placeholder="Label (optional)"
            value={newLabel}
            onChange={(event) => setNewLabel(event.target.value)}
          />
          <select
            className={inputClass}
            value={newKind}
            onChange={(event) => setNewKind(event.target.value as PackKind)}>
            <option value="ioc">Indicator pack</option>
            <option value="standard">Standard queries</option>
          </select>
          <input
            className={`${inputClass} md:col-span-3`}
            placeholder="Access token for a private repository (optional)"
            type="password"
            value={newToken}
            onChange={(event) => setNewToken(event.target.value)}
          />
          <button
            type="button"
            disabled={busy || !newUrl.trim()}
            onClick={handleAdd}
            className="inline-flex items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-2 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong disabled:cursor-not-allowed disabled:opacity-50">
            <PlusCircleIcon className="h-4 w-4" />
            Add source
          </button>
        </div>
        {rewrite.rewritten && (
          <p className="text-[11px] text-socx-muted dark:text-socx-muted-dark">
            {rewrite.reason}: <span className="break-all">{rewrite.url}</span>
          </p>
        )}
        {error && <p className="text-xs text-socx-danger">{error}</p>}
        {notice && <p className="text-xs text-emerald-600">{notice}</p>}
      </div>
    </section>
  )
}

export default QueryPackSettings
