import { describe, expect, it } from "vitest"

import {
  templateVariables,
  type QueryPack,
  type QueryTemplate
} from "./packSchema"
import { bundledDialectMap, isTypeAgnostic, renderTemplate } from "./render"

const dialects = bundledDialectMap()

// The two templates below are the ones reported from a Splunk pack: one that
// uses two of the pack's variables, and one that searches raw terms without
// binding any field.
const volumeTemplate: QueryTemplate = {
  id: "log-volume-trend",
  name: "General log volume trend",
  requiresIocs: false,
  body: "index={{var:index}}\n| bin _time span={{var:time-span}}\n| stats count by _time\n| timechart span={{var:time-span}} max(count) as count"
}

const correlationTemplate: QueryTemplate = {
  id: "generic-ioc-correlation",
  name: "Generic IOC correlation across normalised fields",
  requiresIocs: true,
  byType: {
    IP: {},
    Domain: {},
    URL: {},
    Email: {},
    MD5: {},
    SHA1: {},
    SHA256: {},
    Hash: {}
  },
  body: "search index={{var:index}} {{var:pre-filter}} ({{iocs|or-terms}})\n| stats count by index, src_ip"
}

const pack: QueryPack = {
  schema: "socx.querypack/v1",
  id: "splunk-generic",
  kind: "ioc",
  name: "Splunk generic",
  dialect: "spl",
  variables: [
    { id: "index", label: "Index", default: "main" },
    { id: "time-span", label: "Time span", default: "1h" },
    { id: "pre-filter", label: "Pre-filter", default: "" },
    { id: "dest-domain", label: "Destination domain", default: "" }
  ],
  templates: [volumeTemplate, correlationTemplate]
}

describe("templateVariables", () => {
  it("offers only the variables the template substitutes", () => {
    expect(
      templateVariables(pack, volumeTemplate).map((variable) => variable.id)
    ).toEqual(["index", "time-span"])
    expect(
      templateVariables(pack, correlationTemplate).map(
        (variable) => variable.id
      )
    ).toEqual(["index", "pre-filter"])
  })

  it("counts a variable used only by the open template", () => {
    expect(
      templateVariables(pack, {
        body: "index=main",
        open: "https://console.test/?tenant={{var:dest-domain}}"
      }).map((variable) => variable.id)
    ).toEqual(["dest-domain"])
  })

  it("returns nothing when the pack declares no variable", () => {
    expect(templateVariables({}, volumeTemplate)).toEqual([])
  })
})

describe("templates that never ask which type they render", () => {
  it("recognises a body with no per-type placeholder and equal bindings", () => {
    expect(isTypeAgnostic(correlationTemplate.body, [{}, {}, {}])).toBe(true)
    // A field comparison is type specific, and so is a differing binding.
    expect(isTypeAgnostic("| where {{field}} in ({{iocs}})", [{}, {}])).toBe(
      false
    )
    expect(
      isTypeAgnostic("search ({{iocs|or-terms}})", [
        { field: "src_ip" },
        { field: "domain" }
      ])
    ).toBe(false)
    // `or-values` reads the binding, which is why equal bindings are required.
    expect(
      isTypeAgnostic("search ({{iocs|or-values}})", [
        { field: "term" },
        { field: "term" }
      ])
    ).toBe(true)
  })

  it("renders the whole selection as one query", () => {
    const outcome = renderTemplate({
      template: correlationTemplate,
      pack,
      dialects,
      indicators: [
        { value: "203.0.113.10", type: "IP" },
        { value: "evil.test", type: "Domain" },
        { value: "a".repeat(64), type: "SHA256" }
      ],
      variables: { index: "main", "pre-filter": "" },
      mergeTypes: true
    })

    expect(outcome.mergeRefusal).toBeUndefined()
    expect(outcome.queries).toHaveLength(1)
    expect(outcome.queries[0].count).toBe(3)
    expect(outcome.queries[0].types).toEqual(["IP", "Domain", "SHA256"])
    expect(outcome.queries[0].text).toContain(
      '("203.0.113.10" OR "evil.test" OR "' + "a".repeat(64) + '")'
    )
  })

  it("still chunks one big selection, and still splits when asked to", () => {
    const indicators = Array.from({ length: 5 }, (_, index) => ({
      value: `198.51.100.${index}`,
      type: "IP" as const
    })).concat(
      Array.from({ length: 3 }, (_, index) => ({
        value: `host${index}.test`,
        type: "Domain" as const
      })) as never[]
    )

    const chunked = renderTemplate({
      template: { ...correlationTemplate, maxItems: 3 },
      pack,
      dialects,
      indicators,
      mergeTypes: true
    })
    expect(chunked.queries.map((query) => query.count)).toEqual([3, 3, 2])
    expect(chunked.queries[0].chunks).toBe(3)

    const perType = renderTemplate({
      template: correlationTemplate,
      pack,
      dialects,
      indicators,
      mergeTypes: false
    })
    expect(perType.queries.map((query) => query.type)).toEqual(["IP", "Domain"])
  })
})
