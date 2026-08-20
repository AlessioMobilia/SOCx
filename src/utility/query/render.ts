// The rendering engine: turns a template plus a list of indicators into the
// query text an analyst can paste into a console.
//
// All the correctness critical logic lives here rather than in the packs:
// quoting, escaping, list construction and chunking are decided by the dialect,
// so a template author writes plain text and cannot get the escaping wrong.

import bundledDialects from "./dialects.json"
import type {
  BindableIocType,
  EscapeStrategy,
  QueryDialect,
  QueryPack,
  QueryTemplate,
  TypeBinding
} from "./packSchema"

export const BUNDLED_DIALECTS: QueryDialect[] =
  (bundledDialects as { dialects: QueryDialect[] }).dialects ?? []

export const bundledDialectMap = (): Map<string, QueryDialect> =>
  new Map(BUNDLED_DIALECTS.map((dialect) => [dialect.id, dialect]))

// ------------------------------------------------------------------ escaping

const LUCENE_RESERVED = /([+\-!(){}\[\]^"~*?:\\/]|&&|\|\|)/g
const REGEX_RESERVED = /[.*+?^${}()|[\]\\/-]/g

export const escapeValue = (
  value: string,
  strategy: EscapeStrategy,
  quote: string
): string => {
  switch (strategy) {
    case "backslash": {
      let escaped = value.replace(/\\/g, "\\\\")
      if (quote) {
        escaped = escaped.split(quote).join(`\\${quote}`)
      }
      return escaped
    }
    case "sql-quote":
      return value.split("'").join("''")
    case "lucene":
      return value.replace(LUCENE_RESERVED, "\\$1")
    case "regex":
      return value.replace(REGEX_RESERVED, "\\$&")
    case "json": {
      const json = JSON.stringify(value)
      return json.slice(1, -1)
    }
    case "none":
    default:
      return value
  }
}

const quoteValue = (value: string, dialect: QueryDialect): string => {
  const escaped = escapeValue(value, dialect.escape, dialect.quote)
  return dialect.quote ? `${dialect.quote}${escaped}${dialect.quote}` : escaped
}

// ------------------------------------------------------------------- filters

export type RenderContext = {
  dialect: QueryDialect
  binding?: TypeBinding
  values: string[]
  variables: Record<string, string>
  chunk: number
  chunks: number
  /** Filled in for `open` templates only. */
  query?: string
}

const joinValues = (values: string[], dialect: QueryDialect): string => {
  if (dialect.listStrategy === "regex-alternation") {
    return values
      .map((value) => escapeValue(value, "regex", ""))
      .join(dialect.separator ?? "|")
  }
  return values
    .map((value) => quoteValue(value, dialect))
    .join(dialect.separator ?? ", ")
}

const orValues = (
  values: string[],
  dialect: QueryDialect,
  binding: TypeBinding | undefined,
  fieldOverride?: string
): string => {
  const field = fieldOverride ?? binding?.field ?? ""
  const op = binding?.op ?? dialect.operators?.equals ?? "="
  const suffix = binding?.suffix ? ` ${binding.suffix}` : ""
  const separator = ` ${dialect.operators?.or ?? "OR"} `
  return values
    .map((value) =>
      `${field} ${op} ${quoteValue(value, dialect)}${suffix}`.trim()
    )
    .join(separator)
}

const applyEncoding = (value: string, filter: string): string => {
  switch (filter) {
    case "urlencode":
      return encodeURIComponent(value)
    case "base64":
      return typeof btoa === "function"
        ? btoa(unescape(encodeURIComponent(value)))
        : value
    case "gzip_base64url":
      // Compression needs an async stream, which a synchronous renderer cannot
      // use. The caller compresses before opening; here the value is passed on
      // untouched so the placeholder is still visible in the preview.
      return value
    case "upper":
      return value.toUpperCase()
    case "lower":
      return value.toLowerCase()
    default:
      return value
  }
}

const renderPlaceholder = (
  name: string,
  filters: string[],
  context: RenderContext
): string => {
  const { dialect, binding, values, variables } = context

  const listFilter = filters.find((filter) =>
    ["raw", "json", "regex", "newline", "or-values", "or-terms"].includes(
      filter.split(":")[0]
    )
  )

  let rendered: string

  if (name === "iocs") {
    const [filterName, filterArg] = (listFilter ?? "").split(":")
    switch (filterName) {
      case "raw":
        rendered = values.join(dialect.separator ?? ", ")
        break
      case "json":
        rendered = JSON.stringify(values)
        break
      case "regex":
        rendered = `(${values
          .map((value) => escapeValue(value, "regex", ""))
          .join("|")})`
        break
      case "newline":
        rendered = values.join("\n")
        break
      case "or-values":
        rendered = orValues(values, dialect, binding, filterArg)
        break
      case "or-terms":
        rendered = values
          .map((value) => quoteValue(value, dialect))
          .join(` ${dialect.operators?.or ?? "OR"} `)
        break
      default:
        rendered = joinValues(values, dialect)
    }
  } else if (name === "ioc") {
    rendered = values.length > 0 ? quoteValue(values[0], dialect) : ""
  } else if (name === "field") {
    rendered = binding?.field ?? ""
  } else if (name === "table") {
    rendered = binding?.table ?? ""
  } else if (name === "op") {
    rendered = binding?.op ?? dialect.operators?.equals ?? "="
  } else if (name === "count") {
    rendered = String(values.length)
  } else if (name === "chunk") {
    rendered = String(context.chunk)
  } else if (name === "chunks") {
    rendered = String(context.chunks)
  } else if (name === "now") {
    rendered = new Date().toISOString()
  } else if (name === "query") {
    rendered = context.query ?? ""
  } else if (name.startsWith("var:")) {
    rendered = variables[name.slice(4)] ?? ""
  } else {
    rendered = ""
  }

  for (const filter of filters) {
    rendered = applyEncoding(rendered, filter.split(":")[0])
  }

  return rendered
}

const PLACEHOLDER = /\{\{([^}]+)\}\}/g

export const renderBody = (body: string, context: RenderContext): string =>
  body.replace(PLACEHOLDER, (_match, expression: string) => {
    const parts = String(expression)
      .split("|")
      .map((part) => part.trim())
    return renderPlaceholder(parts[0], parts.slice(1), context)
  })

// --------------------------------------------------------- merging the types
//
// A template is written once and rendered once per indicator type, because an
// IP and a hash live in different columns. Analysts usually want the opposite:
// one query that covers the whole selection, with each type compared against
// its own field. That is possible whenever the body carries a single
// `{{field}} … {{iocs}}` comparison — the only part that changes per type — so
// the comparison is rendered once per type and the copies are joined with the
// dialect's OR. Everything else in the body is rendered exactly once.

export type PredicateSpan = { start: number; end: number }

type PlaceholderToken = { name: string; start: number; end: number }

const scanPlaceholders = (body: string): PlaceholderToken[] => {
  const tokens: PlaceholderToken[] = []
  const pattern = new RegExp(PLACEHOLDER.source, "g")
  let match: RegExpExecArray | null
  while ((match = pattern.exec(body)) !== null) {
    tokens.push({
      name: match[1].split("|")[0].trim(),
      start: match.index,
      end: match.index + match[0].length
    })
  }
  return tokens
}

/**
 * The stretch of the body that has to be repeated per type, or `null` when the
 * template is not shaped in a way that can be merged safely. Deliberately
 * strict: one comparison, on one line, with nothing but an operator inside it,
 * and no table placeholder anywhere — a template SOCx cannot read confidently
 * is rendered the old way rather than guessed at.
 */
export const findPredicateSpan = (body: string): PredicateSpan | null => {
  const tokens = scanPlaceholders(body)
  const fields = tokens.filter((token) => token.name === "field")
  const lists = tokens.filter(
    (token) => token.name === "iocs" || token.name === "ioc"
  )
  if (fields.length !== 1 || lists.length !== 1) return null
  if (tokens.some((token) => token.name === "table")) return null

  const field = fields[0]
  const list = lists[0]
  if (list.start < field.end) return null
  if (body.slice(field.end, list.start).includes("\n")) return null
  const inside = tokens.filter(
    (token) => token.start > field.start && token.start < list.start
  )
  if (inside.some((token) => token.name !== "op")) return null

  // A comparison that opened brackets has to keep them: `in~ ({{iocs}})`.
  const opened = body.slice(field.start, list.end)
  let missing =
    (opened.match(/\(/g) ?? []).length - (opened.match(/\)/g) ?? []).length
  let end = list.end
  while (missing > 0) {
    const next = body.indexOf(")", end)
    if (next < 0 || body.slice(end, next).trim() !== "") return null
    end = next + 1
    missing -= 1
  }
  return { start: field.start, end }
}

export const MERGE_REFUSALS = {
  singleType:
    "only one indicator type is covered, so there is nothing to merge",
  shape:
    "this template does not compare one field to one list, so its types cannot share a query",
  tables: "the indicator types are read from different tables"
} as const

/** Placeholders whose value depends on which indicator type is rendered. */
const PER_TYPE_PLACEHOLDERS = ["field", "table", "op"]

const bindingSignature = (binding: TypeBinding | undefined): string =>
  JSON.stringify([
    binding?.table ?? "",
    binding?.field ?? "",
    binding?.op ?? "",
    binding?.suffix ?? ""
  ])

/**
 * Whether the template reads nothing that distinguishes one indicator type from
 * another: no `{{field}}`, `{{table}}` or `{{op}}`, and bindings that are all
 * the same — typically empty, as in a search that matches raw terms anywhere in
 * the event.
 *
 * Such a template renders byte for byte the same text whatever type a value
 * happens to be, so splitting the selection per type produces several queries
 * that differ only in which indicators they left out. The whole selection goes
 * into one query instead.
 */
export const isTypeAgnostic = (
  body: string,
  bindings: (TypeBinding | undefined)[]
): boolean => {
  if (
    scanPlaceholders(body).some((token) =>
      PER_TYPE_PLACEHOLDERS.includes(token.name)
    )
  ) {
    return false
  }
  const first = bindingSignature(bindings[0])
  return bindings.every((binding) => bindingSignature(binding) === first)
}

/** Why a merge is impossible, or `null` when it can go ahead. */
export const explainMergeRefusal = (
  body: string,
  bindings: (TypeBinding | undefined)[]
): string | null => {
  if (bindings.length < 2) return MERGE_REFUSALS.singleType
  // Nothing to merge and nothing to refuse: the body never asks which type it
  // is rendering, so one query already covers the whole selection.
  if (isTypeAgnostic(body, bindings)) return null
  if (!findPredicateSpan(body)) return MERGE_REFUSALS.shape
  const tables = new Set(bindings.map((binding) => binding?.table ?? ""))
  if (tables.size > 1) return MERGE_REFUSALS.tables
  return null
}

// ------------------------------------------------------------------ chunking

export const chunkValues = (values: string[], maxItems: number): string[][] => {
  if (values.length === 0) return []
  const size = Math.max(1, maxItems)
  const chunks: string[][] = []
  for (let index = 0; index < values.length; index += size) {
    chunks.push(values.slice(index, index + size))
  }
  return chunks
}

// -------------------------------------------------------------------- render

export type RenderedIndicator = { value: string; type: BindableIocType }

export type RenderedQuery = {
  templateId: string
  templateName: string
  packId: string
  dialectId: string
  /** Absent for indicator free templates and for merged ones. */
  type?: BindableIocType
  /** Every type the query covers, in the order they are compared. */
  types?: BindableIocType[]
  chunk: number
  chunks: number
  count: number
  text: string
  openUrl?: string
  /** True when the query exceeded the dialect length budget. */
  overLength: boolean
}

export type RenderOutcome = {
  queries: RenderedQuery[]
  /** Indicator types no binding of this template covers. */
  uncoveredTypes: BindableIocType[]
  errors: string[]
  /** Set when a merge was asked for and could not be done. */
  mergeRefusal?: string
}

const PRIVATE_IPV4 =
  /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/

const isPrivateAddress = (value: string): boolean =>
  PRIVATE_IPV4.test(value) ||
  value.toLowerCase().startsWith("fe80:") ||
  value.toLowerCase().startsWith("fc") ||
  value.toLowerCase().startsWith("fd") ||
  value === "::1"

export const renderTemplate = ({
  template,
  pack,
  dialects,
  indicators,
  variables = {},
  mergeTypes = false
}: {
  template: QueryTemplate
  pack: QueryPack
  dialects: Map<string, QueryDialect>
  indicators: RenderedIndicator[]
  variables?: Record<string, string>
  /** Produce one query covering every type instead of one query per type. */
  mergeTypes?: boolean
}): RenderOutcome => {
  const dialectId = template.dialect ?? pack.dialect
  const dialect = dialects.get(dialectId)
  if (!dialect) {
    return {
      queries: [],
      uncoveredTypes: [],
      errors: [`Unknown dialect "${dialectId}"`]
    }
  }

  const resolvedVariables: Record<string, string> = {}
  for (const variable of pack.variables ?? []) {
    resolvedVariables[variable.id] = variable.default ?? ""
  }
  Object.assign(resolvedVariables, variables)

  const maxLength = dialect.maxLength ?? 8000

  const buildQuery = (
    values: string[],
    binding: TypeBinding | undefined,
    type: BindableIocType | undefined,
    chunk: number,
    chunks: number,
    /** Ready made body, used when the per-type comparisons were merged. */
    body = template.body,
    types?: BindableIocType[]
  ): RenderedQuery => {
    const context: RenderContext = {
      dialect,
      binding,
      values,
      variables: resolvedVariables,
      chunk,
      chunks
    }
    const text = renderBody(body, context)
    const openUrl = template.open
      ? renderBody(template.open, { ...context, query: text })
      : undefined

    return {
      templateId: template.id,
      templateName: template.name,
      packId: pack.id,
      dialectId,
      type,
      types,
      chunk,
      chunks,
      count: values.length,
      text,
      openUrl,
      overLength: text.length > maxLength
    }
  }

  if (!template.requiresIocs) {
    return {
      queries: [buildQuery([], undefined, undefined, 1, 1)],
      uncoveredTypes: [],
      errors: []
    }
  }

  const byType = template.byType ?? {}
  const grouped = new Map<BindableIocType, string[]>()
  const uncovered = new Set<BindableIocType>()

  for (const indicator of indicators) {
    if (!byType[indicator.type]) {
      uncovered.add(indicator.type)
      continue
    }
    if (template.excludePrivate && isPrivateAddress(indicator.value)) {
      continue
    }
    const bucket = grouped.get(indicator.type) ?? []
    if (!bucket.includes(indicator.value)) {
      bucket.push(indicator.value)
    }
    grouped.set(indicator.type, bucket)
  }

  const queries: RenderedQuery[] = []
  const maxItems = template.maxItems ?? dialect.maxItems ?? 100

  if (mergeTypes && grouped.size > 0) {
    const types = [...grouped.keys()]
    const refusal = explainMergeRefusal(
      template.body,
      types.map((type) => byType[type])
    )
    if (!refusal) {
      // A body that never asks which type it is rendering needs no comparison
      // surgery: every indicator goes into one list, chunked as one selection.
      if (
        isTypeAgnostic(
          template.body,
          types.map((type) => byType[type])
        )
      ) {
        const values: string[] = []
        for (const type of types) {
          for (const value of grouped.get(type) ?? []) {
            if (!values.includes(value)) values.push(value)
          }
        }
        const chunks = chunkValues(values, maxItems)
        chunks.forEach((chunkValuesList, index) => {
          queries.push(
            buildQuery(
              chunkValuesList,
              byType[types[0]],
              undefined,
              index + 1,
              chunks.length,
              template.body,
              types
            )
          )
        })
        return { queries, uncoveredTypes: [...uncovered], errors: [] }
      }

      const span = findPredicateSpan(template.body)!
      const separator = ` ${dialect.operators?.or ?? "OR"} `
      // A sentinel keeps the merged comparisons out of the second pass, so a
      // value that happens to contain braces is never read as a placeholder.
      const SENTINEL = " socx-merged "
      const outerBody =
        template.body.slice(0, span.start) +
        SENTINEL +
        template.body.slice(span.end)
      const comparison = template.body.slice(span.start, span.end)

      // Chunking spans the whole selection, so one query stays one query for as
      // long as the platform allows it.
      const pairs = types.flatMap((type) =>
        (grouped.get(type) ?? []).map((value) => ({ type, value }))
      )
      const chunks: { type: BindableIocType; value: string }[][] = []
      for (
        let index = 0;
        index < pairs.length;
        index += Math.max(1, maxItems)
      ) {
        chunks.push(pairs.slice(index, index + Math.max(1, maxItems)))
      }

      chunks.forEach((pairsInChunk, index) => {
        const perType = new Map<BindableIocType, string[]>()
        for (const pair of pairsInChunk) {
          perType.set(pair.type, [
            ...(perType.get(pair.type) ?? []),
            pair.value
          ])
        }
        const merged = [...perType.entries()]
          .map(([type, values]) =>
            renderBody(comparison, {
              dialect,
              binding: byType[type],
              values,
              variables: resolvedVariables,
              chunk: index + 1,
              chunks: chunks.length
            })
          )
          .join(separator)

        const query = buildQuery(
          pairsInChunk.map((pair) => pair.value),
          byType[types[0]],
          undefined,
          index + 1,
          chunks.length,
          outerBody,
          [...perType.keys()]
        )
        query.text = query.text.split(SENTINEL).join(merged)
        query.openUrl = query.openUrl?.split(SENTINEL).join(merged)
        query.overLength = query.text.length > maxLength
        queries.push(query)
      })

      return { queries, uncoveredTypes: [...uncovered], errors: [] }
    }

    // Merging was asked for and refused: fall back to one query per type and
    // say why, rather than silently producing something else.
    if (refusal !== MERGE_REFUSALS.singleType) {
      return {
        ...renderPerType(),
        mergeRefusal: refusal
      }
    }
  }

  function renderPerType(): RenderOutcome {
    const perType: RenderedQuery[] = []
    for (const [type, values] of grouped) {
      const chunks = chunkValues(values, maxItems)
      chunks.forEach((chunkValuesList, index) => {
        perType.push(
          buildQuery(
            chunkValuesList,
            byType[type],
            type,
            index + 1,
            chunks.length
          )
        )
      })
    }
    return { queries: perType, uncoveredTypes: [...uncovered], errors: [] }
  }

  return renderPerType()
}

/**
 * Renders every template of a selection, which is what the palette does when
 * the analyst picks a whole group.
 */
export const renderSelection = ({
  templates,
  dialects,
  indicators,
  variables = {}
}: {
  templates: { template: QueryTemplate; pack: QueryPack }[]
  dialects: Map<string, QueryDialect>
  indicators: RenderedIndicator[]
  variables?: Record<string, string>
}): RenderOutcome => {
  const queries: RenderedQuery[] = []
  const uncovered = new Set<BindableIocType>()
  const errors: string[] = []

  for (const { template, pack } of templates) {
    const outcome = renderTemplate({
      template,
      pack,
      dialects,
      indicators,
      variables
    })
    queries.push(...outcome.queries)
    outcome.uncoveredTypes.forEach((type) => uncovered.add(type))
    errors.push(...outcome.errors)
  }

  // A type is only really uncovered when no template in the selection binds it.
  const covered = new Set(queries.map((query) => query.type))
  return {
    queries,
    uncoveredTypes: [...uncovered].filter((type) => !covered.has(type)),
    errors
  }
}

// ------------------------------------------------------- indicator preparation

const HASH_TYPE_BY_LENGTH: Record<number, BindableIocType> = {
  32: "MD5",
  40: "SHA1",
  64: "SHA256"
}

/**
 * Maps the IOC type SOCx detects onto the finer grained types a query template
 * binds: a hash has to become MD5, SHA1 or SHA256 because they live in
 * different columns.
 */
export const toBindableType = (
  type: string | null,
  value: string
): BindableIocType | null => {
  if (!type) return null
  if (type === "Private IP") return "IP"
  if (type === "Hash") {
    return HASH_TYPE_BY_LENGTH[value.trim().length] ?? "Hash"
  }
  return (BINDABLE as readonly string[]).includes(type)
    ? (type as BindableIocType)
    : null
}

const BINDABLE = [
  "IP",
  "Domain",
  "URL",
  "Email",
  "ASN",
  "MAC",
  "CVE",
  "Hash",
  "SHA256",
  "SHA1",
  "MD5"
] as const
