import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ClipboardDocumentListIcon,
  PlusCircleIcon,
  TrashIcon
} from "@heroicons/react/24/outline"
import React, { useCallback, useEffect, useMemo, useState } from "react"

import { sendToBackground } from "@plasmohq/messaging"

import "../styles/tailwind.css"

import { writeIntelClipboardText } from "../utility/clipboard"
import {
  buildPack,
  importPackIntoLibrary,
  suggestTemplateId,
  type UserQueryTemplate
} from "../utility/query/builder"
import { buildGroupTree } from "../utility/query/groups"
import type {
  BindableIocType,
  PackKind,
  QueryPack
} from "../utility/query/packSchema"
import { BINDABLE_IOC_TYPES } from "../utility/query/packSchema"
import { readUserLibrary, writeUserLibrary } from "../utility/query/registry"
import {
  BUNDLED_DIALECTS,
  bundledDialectMap,
  renderTemplate,
  toBindableType
} from "../utility/query/render"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"
import { extractIOCs, identifyIOC } from "../utility/utils"

const card =
  "rounded-socx-lg border border-socx-border-light bg-white/90 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/80"
const label =
  "text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark"
const input =
  "w-full rounded-lg border border-socx-border-light bg-white/90 px-3 py-2 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
const button =
  "inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent disabled:cursor-not-allowed disabled:opacity-40 dark:border-socx-border-dark dark:text-white"
const primaryButton =
  "inline-flex items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-2 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong disabled:cursor-not-allowed disabled:opacity-50"

const SAMPLE_INDICATORS = "203.0.113.10\nevil.example.com\n" + "a".repeat(64)

const emptyDraft = (): UserQueryTemplate => {
  const now = new Date().toISOString()
  return {
    id: "",
    name: "",
    description: "",
    dialect: "kql",
    kind: "ioc",
    group: "",
    body: "",
    byType: {},
    variables: [],
    createdAt: now,
    updatedAt: now
  }
}

const QueryBuilder = () => {
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [library, setLibrary] = useState<UserQueryTemplate[]>([])
  const [draft, setDraft] = useState<UserQueryTemplate>(emptyDraft)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [sampleText, setSampleText] = useState(SAMPLE_INDICATORS)
  const [message, setMessage] = useState("")
  const [remotePacks, setRemotePacks] = useState<QueryPack[]>([])

  const dialects = useMemo(() => bundledDialectMap(), [])

  useEffect(() => {
    const load = async () => {
      setLibrary(await readUserLibrary())
      const dark = await ensureIsDarkMode()
      setIsDarkMode(dark)
      document.body.className = dark ? "dark-mode" : "light-mode"
      try {
        const response = await sendToBackground<
          unknown,
          { packs?: QueryPack[] }
        >({ name: "query-library", body: {} })
        setRemotePacks(response?.packs ?? [])
      } catch {
        setRemotePacks([])
      }
    }
    void load()
  }, [])

  useEffect(() => {
    persistIsDarkMode(isDarkMode)
    document.body.className = isDarkMode ? "dark-mode" : "light-mode"
  }, [isDarkMode])

  const persist = useCallback(async (next: UserQueryTemplate[]) => {
    setLibrary(next)
    await writeUserLibrary(next)
  }, [])

  const sampleIndicators = useMemo(() => {
    const values = extractIOCs(sampleText) ?? []
    return values
      .map((value) => {
        const type = toBindableType(identifyIOC(value), value)
        return type ? { value, type } : null
      })
      .filter((entry): entry is { value: string; type: BindableIocType } =>
        Boolean(entry)
      )
  }, [sampleText])

  // Live preview: the draft is wrapped in a throwaway pack so it goes through
  // exactly the same validation and rendering path as a published one.
  const preview = useMemo(() => {
    if (!draft.body.trim() || !draft.name.trim()) {
      return { queries: [] as string[], errors: [] as string[] }
    }
    const candidate: UserQueryTemplate = {
      ...draft,
      id: draft.id || suggestTemplateId(draft.name)
    }
    const built = buildPack(
      [candidate],
      candidate.kind,
      { id: "preview", name: "Preview" },
      { knownDialects: new Set(dialects.keys()) }
    )
    if (!built.ok) {
      return {
        queries: [],
        errors: built.errors.map((error) => error.message)
      }
    }
    const outcome = renderTemplate({
      template: built.pack.templates[0],
      pack: built.pack,
      dialects,
      indicators: sampleIndicators
    })
    return {
      queries: outcome.queries.map((query) => query.text),
      errors: outcome.errors
    }
  }, [dialects, draft, sampleIndicators])

  const handleSave = useCallback(async () => {
    if (!draft.name.trim() || !draft.body.trim()) {
      setMessage("A template needs a name and a body.")
      return
    }
    const id =
      editingId ??
      suggestTemplateId(
        draft.name,
        library.map((template) => template.id)
      )
    const now = new Date().toISOString()
    const entry: UserQueryTemplate = { ...draft, id, updatedAt: now }
    const validation = buildPack(
      [entry],
      entry.kind,
      { id: "saved-query", name: "Saved query" },
      { knownDialects: new Set(dialects.keys()) }
    )
    if (!validation.ok) {
      setMessage(validation.errors.map((error) => error.message).join(" · "))
      return
    }
    const next = editingId
      ? library.map((template) =>
          template.id === editingId ? entry : template
        )
      : [...library, entry]
    await persist(next)
    setDraft(emptyDraft())
    setEditingId(null)
    setMessage(editingId ? "Template updated." : "Template saved.")
  }, [dialects, draft, editingId, library, persist])

  const handleExport = useCallback(
    (kind: PackKind) => {
      const built = buildPack(
        library,
        kind,
        {
          id: `my-${kind}-queries`,
          name: kind === "ioc" ? "My IOC queries" : "My hunting queries",
          description: "Exported from SOCx."
        },
        { knownDialects: new Set(dialects.keys()) }
      )
      if (!built.ok) {
        setMessage(built.errors.map((error) => error.message).join(" · "))
        return
      }
      const blob = new Blob([built.json], { type: "application/json" })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement("a")
      anchor.href = url
      anchor.download = `socx-${kind}-pack.json`
      anchor.click()
      URL.revokeObjectURL(url)
      setMessage(`Exported ${built.pack.templates.length} ${kind} templates.`)
    },
    [dialects, library]
  )

  const handleImport = useCallback(
    (file: File | undefined) => {
      if (!file) return
      const reader = new FileReader()
      reader.onload = async (event) => {
        try {
          const parsed = JSON.parse(String(event.target?.result ?? ""))
          const result = importPackIntoLibrary(parsed, library, {
            knownDialects: new Set(dialects.keys())
          })
          if (result.errors.length > 0) {
            setMessage(result.errors.map((error) => error.message).join(" · "))
            return
          }
          await persist([...library, ...result.templates])
          setMessage(`Imported ${result.templates.length} templates.`)
        } catch (error) {
          setMessage("That file is not a valid pack.")
        }
      }
      reader.readAsText(file)
    },
    [dialects, library, persist]
  )

  const setBinding = (type: BindableIocType, key: string, value: string) => {
    setDraft((previous) => {
      const byType = { ...(previous.byType ?? {}) }
      const binding = { ...(byType[type] ?? {}) }
      if (value) {
        ;(binding as Record<string, string>)[key] = value
      } else {
        delete (binding as Record<string, string>)[key]
      }
      if (Object.keys(binding).length === 0) {
        delete byType[type]
      } else {
        byType[type] = binding
      }
      return { ...previous, byType }
    })
  }

  const toggleType = (type: BindableIocType) => {
    setDraft((previous) => {
      const byType = { ...(previous.byType ?? {}) }
      if (byType[type]) {
        delete byType[type]
      } else {
        byType[type] = { field: "", op: "" }
      }
      return { ...previous, byType }
    })
  }

  const updateVariable = (
    index: number,
    patch: Partial<NonNullable<UserQueryTemplate["variables"]>[number]>
  ) => {
    setDraft((previous) => {
      const variables = [...(previous.variables ?? [])]
      variables[index] = { ...variables[index], ...patch }
      return { ...previous, variables }
    })
  }

  const addVariable = () => {
    setDraft((previous) => ({
      ...previous,
      variables: [
        ...(previous.variables ?? []),
        {
          id: `variable-${(previous.variables?.length ?? 0) + 1}`,
          label: "Variable"
        }
      ]
    }))
  }

  const remoteTree = useMemo(() => buildGroupTree(remotePacks), [remotePacks])
  const remoteTemplateCount = useMemo(
    () => remotePacks.reduce((total, pack) => total + pack.templates.length, 0),
    [remotePacks]
  )

  return (
    <div className="min-h-screen bg-socx-cloud px-4 py-6 font-inter text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className={card}>
          <p className={label}>SOCx</p>
          <h1 className="mt-1 text-2xl font-semibold">Query rule builder</h1>
          <p className="text-sm text-socx-muted dark:text-socx-muted-dark">
            Compose a template, preview it against sample indicators, then
            export it as a pack your team — or the community repository — can
            load.
          </p>
          <p className="mt-2 text-xs text-socx-muted dark:text-socx-muted-dark">
            {remotePacks.length} packs loaded · {remoteTemplateCount} templates
            available · {remoteTree.length} top level groups
          </p>
        </header>

        {message && (
          <div className="rounded-socx-lg border border-socx-border-light bg-socx-cloud-soft/60 px-4 py-3 text-sm dark:border-socx-border-dark dark:bg-socx-panel/50">
            {message}
          </div>
        )}

        <div className="grid gap-6 lg:grid-cols-2">
          <section className={`${card} space-y-3`}>
            <p className={label}>Template</p>

            <input
              className={input}
              placeholder="Name — the question it answers"
              value={draft.name}
              onChange={(event) =>
                setDraft({ ...draft, name: event.target.value })
              }
            />
            <input
              className={input}
              placeholder="Description shown in the palette"
              value={draft.description ?? ""}
              onChange={(event) =>
                setDraft({ ...draft, description: event.target.value })
              }
            />

            <div className="grid gap-3 sm:grid-cols-3">
              <select
                className={input}
                value={draft.kind}
                onChange={(event) =>
                  setDraft({
                    ...draft,
                    kind: event.target.value as PackKind,
                    byType:
                      event.target.value === "standard" ? {} : draft.byType
                  })
                }>
                <option value="ioc">Needs indicators</option>
                <option value="standard">Standard query</option>
              </select>

              <select
                className={input}
                value={draft.dialect}
                onChange={(event) =>
                  setDraft({ ...draft, dialect: event.target.value })
                }>
                {BUNDLED_DIALECTS.map((dialect) => (
                  <option key={dialect.id} value={dialect.id}>
                    {dialect.label}
                  </option>
                ))}
              </select>

              <input
                className={input}
                placeholder="group/subgroup"
                value={draft.group ?? ""}
                onChange={(event) =>
                  setDraft({ ...draft, group: event.target.value })
                }
              />
            </div>

            {draft.kind === "ioc" && (
              <div className="space-y-2 rounded-xl border border-socx-border-light p-3 dark:border-socx-border-dark">
                <p className="text-xs font-semibold">
                  Where each indicator type lives
                </p>
                <div className="flex flex-wrap gap-2">
                  {BINDABLE_IOC_TYPES.map((type) => (
                    <button
                      type="button"
                      key={type}
                      onClick={() => toggleType(type)}
                      className={`socx-chip ${
                        draft.byType?.[type]
                          ? "socx-chip-active"
                          : "border-socx-border-light bg-white/90 dark:border-socx-border-dark dark:bg-socx-panel/40"
                      }`}>
                      {type}
                    </button>
                  ))}
                </div>
                {Object.keys(draft.byType ?? {}).map((rawType) => {
                  const type = rawType as BindableIocType
                  const binding = draft.byType?.[type] ?? {}
                  return (
                    <div key={type} className="grid gap-2 sm:grid-cols-4">
                      <span className="self-center text-xs font-semibold">
                        {type}
                      </span>
                      <input
                        className={input}
                        placeholder="field"
                        value={binding.field ?? ""}
                        onChange={(event) =>
                          setBinding(type, "field", event.target.value)
                        }
                      />
                      <input
                        className={input}
                        placeholder="operator"
                        value={binding.op ?? ""}
                        onChange={(event) =>
                          setBinding(type, "op", event.target.value)
                        }
                      />
                      <input
                        className={input}
                        placeholder="table (optional)"
                        value={binding.table ?? ""}
                        onChange={(event) =>
                          setBinding(type, "table", event.target.value)
                        }
                      />
                    </div>
                  )
                })}
              </div>
            )}

            <div className="space-y-2 rounded-xl border border-socx-border-light p-3 dark:border-socx-border-dark">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <p className="text-xs font-semibold">Template variables</p>
                  <p className="text-[11px] text-socx-muted dark:text-socx-muted-dark">
                    Optional values rendered through {"{{var:id}}"}.
                  </p>
                </div>
                <button type="button" className={button} onClick={addVariable}>
                  <PlusCircleIcon className="h-4 w-4" />
                  Add variable
                </button>
              </div>
              {(draft.variables ?? []).map((variable, index) => (
                <div
                  key={`${variable.id}-${index}`}
                  className="grid gap-2 sm:grid-cols-5">
                  <input
                    className={input}
                    placeholder="id"
                    value={variable.id}
                    onChange={(event) =>
                      updateVariable(index, { id: event.target.value })
                    }
                  />
                  <input
                    className={input}
                    placeholder="label"
                    value={variable.label}
                    onChange={(event) =>
                      updateVariable(index, { label: event.target.value })
                    }
                  />
                  <input
                    className={input}
                    placeholder="default"
                    value={variable.default ?? ""}
                    onChange={(event) =>
                      updateVariable(index, {
                        default: event.target.value || undefined
                      })
                    }
                  />
                  <input
                    className={input}
                    placeholder="options, comma separated"
                    value={(variable.options ?? []).join(", ")}
                    onChange={(event) =>
                      updateVariable(index, {
                        options: event.target.value
                          .split(",")
                          .map((option) => option.trim())
                          .filter(Boolean)
                      })
                    }
                  />
                  <button
                    type="button"
                    className={`${button} text-socx-danger`}
                    onClick={() =>
                      setDraft((previous) => ({
                        ...previous,
                        variables: (previous.variables ?? []).filter(
                          (_entry, variableIndex) => variableIndex !== index
                        )
                      }))
                    }>
                    <TrashIcon className="h-4 w-4" />
                    Remove
                  </button>
                </div>
              ))}
            </div>

            <textarea
              className={`${input} socx-scroll h-48 font-mono text-xs`}
              placeholder={
                "Query body. Use {{iocs}}, {{field}}, {{op}}, {{table}}, {{var:name}}"
              }
              value={draft.body}
              onChange={(event) =>
                setDraft({ ...draft, body: event.target.value })
              }
            />

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={handleSave}
                className={primaryButton}>
                <PlusCircleIcon className="h-4 w-4" />
                {editingId ? "Update template" : "Save to my library"}
              </button>
              <button
                type="button"
                className={button}
                onClick={() => {
                  setDraft(emptyDraft())
                  setEditingId(null)
                }}>
                Clear
              </button>
            </div>
          </section>

          <section className={`${card} space-y-3`}>
            <p className={label}>Preview</p>
            <textarea
              className={`${input} socx-scroll h-24 font-mono text-xs`}
              value={sampleText}
              onChange={(event) => setSampleText(event.target.value)}
            />
            <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
              {sampleIndicators.length} sample indicators detected
            </p>

            {preview.errors.length > 0 && (
              <ul className="space-y-1 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300">
                {preview.errors.map((error) => (
                  <li key={error}>{error}</li>
                ))}
              </ul>
            )}

            {preview.queries.length === 0 ? (
              <p className="rounded-xl border border-dashed border-socx-border-light px-3 py-4 text-xs text-socx-muted dark:border-socx-border-dark dark:text-socx-muted-dark">
                Fill in a name and a body to see the rendered query.
              </p>
            ) : (
              preview.queries.map((query, index) => (
                <div key={index} className="space-y-2">
                  <pre className="socx-scroll whitespace-pre-wrap break-words rounded-xl bg-socx-cloud-soft/70 p-3 text-[11px] dark:bg-socx-panel/70">
                    {query}
                  </pre>
                  <button
                    type="button"
                    className={button}
                    onClick={() =>
                      writeIntelClipboardText(query, {
                        successMessage: "✔️ Query copied"
                      })
                    }>
                    <ClipboardDocumentListIcon className="h-4 w-4" />
                    Copy
                  </button>
                </div>
              ))
            )}
          </section>
        </div>

        <section className={`${card} space-y-3`}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className={label}>My library ({library.length})</p>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                className={button}
                onClick={() => handleExport("ioc")}>
                <ArrowDownTrayIcon className="h-4 w-4" />
                Export IOC pack
              </button>
              <button
                type="button"
                className={button}
                onClick={() => handleExport("standard")}>
                <ArrowDownTrayIcon className="h-4 w-4" />
                Export standard pack
              </button>
              <label className={`${button} cursor-pointer`}>
                <ArrowPathIcon className="h-4 w-4" />
                Import pack
                <input
                  type="file"
                  accept=".json"
                  className="hidden"
                  onChange={(event) => {
                    handleImport(event.target.files?.[0])
                    event.target.value = ""
                  }}
                />
              </label>
            </div>
          </div>

          {library.length === 0 ? (
            <p className="rounded-xl border border-dashed border-socx-border-light px-3 py-4 text-xs text-socx-muted dark:border-socx-border-dark dark:text-socx-muted-dark">
              Nothing saved yet. Templates saved here show up in the palette
              alongside the community packs.
            </p>
          ) : (
            <div className="space-y-2">
              {library.map((template) => (
                <div
                  key={template.id}
                  className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-socx-border-light px-3 py-2 dark:border-socx-border-dark">
                  <div className="min-w-0">
                    <p className="text-sm font-semibold">{template.name}</p>
                    <p className="text-[11px] uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                      {template.dialect} · {template.kind} ·{" "}
                      {template.group || "uncategorised"}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      className={button}
                      onClick={() => {
                        setDraft(template)
                        setEditingId(template.id)
                        setMessage(`Editing "${template.name}".`)
                      }}>
                      Edit
                    </button>
                    <button
                      type="button"
                      className={`${button} text-socx-danger`}
                      onClick={() =>
                        persist(
                          library.filter((entry) => entry.id !== template.id)
                        )
                      }>
                      <TrashIcon className="h-4 w-4" />
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

export default QueryBuilder
