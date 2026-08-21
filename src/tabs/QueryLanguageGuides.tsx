import {
  ArrowTopRightOnSquareIcon,
  ChevronDownIcon,
  MagnifyingGlassIcon
} from "@heroicons/react/24/outline"
import React, { useMemo, useState } from "react"

import {
  filterQueryLanguageGuides,
  QUERY_LANGUAGE_GUIDES
} from "../utility/query/guides"
import type { QueryDialect } from "../utility/query/packSchema"

const guideInput =
  "w-full rounded-lg border border-socx-border-light bg-white/90 px-3 py-2 text-sm text-socx-ink outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"

type QueryLanguageGuidesProps = {
  dialects: Map<string, QueryDialect>
}

const productLabel = (dialect?: QueryDialect): string =>
  dialect?.vendors?.length ? dialect.vendors.join(" · ") : "Generic target"

const QueryLanguageGuides = ({ dialects }: QueryLanguageGuidesProps) => {
  const [dialectFilter, setDialectFilter] = useState("all")
  const [search, setSearch] = useState("")
  const orderedGuides = useMemo(
    () =>
      [...QUERY_LANGUAGE_GUIDES].sort((a, b) =>
        (dialects.get(a.dialectId)?.label ?? a.dialectId).localeCompare(
          dialects.get(b.dialectId)?.label ?? b.dialectId
        )
      ),
    [dialects]
  )
  const visibleGuides = useMemo(
    () =>
      filterQueryLanguageGuides(
        orderedGuides,
        dialectFilter,
        search,
        (dialectId) => productLabel(dialects.get(dialectId))
      ),
    [dialectFilter, dialects, orderedGuides, search]
  )

  return (
    <details className="group rounded-socx-lg border border-socx-border-light bg-white/90 shadow-sm dark:border-socx-border-dark dark:bg-socx-night-soft/80">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-4 rounded-socx-lg px-5 py-4 marker:hidden transition hover:bg-socx-cloud-soft/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-socx-accent dark:hover:bg-socx-panel/50 [&::-webkit-details-marker]:hidden">
        <div>
          <h2 className="font-semibold">Query language mini guides</h2>
          <p className="mt-1 text-xs text-socx-muted dark:text-socx-muted-dark">
            Commands, key fields and official documentation for all{" "}
            {QUERY_LANGUAGE_GUIDES.length} supported languages. Closed until you
            need it.
          </p>
        </div>
        <span className="inline-flex shrink-0 items-center gap-2 text-xs font-semibold text-socx-muted dark:text-socx-muted-dark">
          <span className="group-open:hidden">Open guide</span>
          <span className="hidden group-open:inline">Close guide</span>
          <ChevronDownIcon className="h-4 w-4 transition group-open:rotate-180" />
        </span>
      </summary>

      <div className="border-t border-socx-border-light px-5 py-5 dark:border-socx-border-dark">
        <div className="grid gap-3 md:grid-cols-[minmax(240px,0.8fr)_minmax(280px,1.2fr)]">
          <label className="space-y-1 text-xs font-semibold">
            <span>Language and product</span>
            <select
              className={guideInput}
              value={dialectFilter}
              onChange={(event) => setDialectFilter(event.target.value)}>
              <option value="all">All languages and products</option>
              {orderedGuides.map((guide) => {
                const dialect = dialects.get(guide.dialectId)
                return (
                  <option key={guide.dialectId} value={guide.dialectId}>
                    {dialect?.label ?? guide.dialectId} —{" "}
                    {productLabel(dialect)}
                  </option>
                )
              })}
            </select>
          </label>

          <label className="space-y-1 text-xs font-semibold">
            <span>Find a command, operator or field</span>
            <span className="relative block">
              <MagnifyingGlassIcon className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-socx-muted" />
              <input
                className={`${guideInput} pl-9`}
                type="search"
                placeholder="Try where, stats, regex, source.ip…"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </span>
          </label>
        </div>

        <p className="mt-3 text-xs text-socx-muted dark:text-socx-muted-dark">
          {visibleGuides.length} of {QUERY_LANGUAGE_GUIDES.length} guides
        </p>

        <div className="mt-3 grid gap-3 xl:grid-cols-2">
          {visibleGuides.length === 0 ? (
            <p className="rounded-xl border border-dashed border-socx-border-light p-4 text-sm text-socx-muted dark:border-socx-border-dark dark:text-socx-muted-dark xl:col-span-2">
              No guide contains every search term. Try a command name, an
              operator, a field or a product.
            </p>
          ) : (
            visibleGuides.map((guide) => {
              const dialect = dialects.get(guide.dialectId)
              return (
                <details
                  key={guide.dialectId}
                  className="group/guide self-start rounded-xl border border-socx-border-light bg-socx-cloud-soft/45 dark:border-socx-border-dark dark:bg-socx-panel/35">
                  <summary className="flex cursor-pointer list-none items-start justify-between gap-3 rounded-xl px-4 py-3 marker:hidden hover:bg-socx-accent/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-socx-accent [&::-webkit-details-marker]:hidden">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-full bg-socx-accent/15 px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wide">
                          {guide.dialectId}
                        </span>
                        <h3 className="text-sm font-semibold">
                          {dialect?.label ?? guide.dialectId}
                        </h3>
                      </div>
                      <p className="mt-1 text-[11px] text-socx-muted dark:text-socx-muted-dark">
                        {productLabel(dialect)}
                      </p>
                    </div>
                    <ChevronDownIcon className="mt-0.5 h-4 w-4 shrink-0 text-socx-muted transition group-open/guide:rotate-180" />
                  </summary>

                  <div className="space-y-4 border-t border-socx-border-light px-4 py-4 text-xs dark:border-socx-border-dark">
                    <p className="text-sm leading-relaxed">{guide.summary}</p>

                    <div className="grid gap-4 sm:grid-cols-2">
                      <div>
                        <h4 className="mb-2 font-semibold">Main fields</h4>
                        <dl className="space-y-2">
                          {guide.fields.map((field) => (
                            <div key={field.term}>
                              <dt className="font-mono font-semibold text-socx-ink dark:text-white">
                                {field.term}
                              </dt>
                              <dd className="mt-0.5 leading-relaxed text-socx-muted dark:text-socx-muted-dark">
                                {field.description}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </div>

                      <div>
                        <h4 className="mb-2 font-semibold">
                          Commands and operators
                        </h4>
                        <dl className="space-y-2">
                          {guide.commands.map((command) => (
                            <div key={command.term}>
                              <dt className="font-mono font-semibold text-socx-ink dark:text-white">
                                {command.term}
                              </dt>
                              <dd className="mt-0.5 leading-relaxed text-socx-muted dark:text-socx-muted-dark">
                                {command.description}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    </div>

                    {guide.caution && (
                      <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 leading-relaxed text-amber-900 dark:text-amber-200">
                        {guide.caution}
                      </p>
                    )}

                    <a
                      href={guide.documentationUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 font-semibold text-socx-muted underline decoration-socx-accent decoration-2 underline-offset-4 transition hover:text-socx-accent dark:text-socx-muted-dark">
                      {guide.documentationLabel}
                      <ArrowTopRightOnSquareIcon className="h-3.5 w-3.5" />
                      <span className="sr-only"> (opens in a new tab)</span>
                    </a>
                  </div>
                </details>
              )
            })
          )}
        </div>
      </div>
    </details>
  )
}

export default QueryLanguageGuides
