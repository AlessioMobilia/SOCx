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
  /** Absent for indicator free templates. */
  type?: BindableIocType
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
  variables = {}
}: {
  template: QueryTemplate
  pack: QueryPack
  dialects: Map<string, QueryDialect>
  indicators: RenderedIndicator[]
  variables?: Record<string, string>
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
    chunks: number
  ): RenderedQuery => {
    const context: RenderContext = {
      dialect,
      binding,
      values,
      variables: resolvedVariables,
      chunk,
      chunks
    }
    const text = renderBody(template.body, context)
    const openUrl = template.open
      ? renderBody(template.open, { ...context, query: text })
      : undefined

    return {
      templateId: template.id,
      templateName: template.name,
      packId: pack.id,
      dialectId,
      type,
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

  for (const [type, values] of grouped) {
    const chunks = chunkValues(values, maxItems)
    chunks.forEach((chunkValuesList, index) => {
      queries.push(
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

  return {
    queries,
    uncoveredTypes: [...uncovered],
    errors: []
  }
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
