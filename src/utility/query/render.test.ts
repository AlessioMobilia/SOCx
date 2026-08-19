import { describe, expect, it } from "vitest"

import { validateQueryPack, type QueryPack } from "./packSchema"
import {
  BUNDLED_DIALECTS,
  bundledDialectMap,
  chunkValues,
  escapeValue,
  renderSelection,
  renderTemplate,
  toBindableType
} from "./render"

const dialects = bundledDialectMap()

// Raw shape on purpose: everything goes through the validator, which is what
// fills in defaults such as requiresIocs.
const buildPack = (overrides: Record<string, unknown> = {}): QueryPack => {
  const raw = {
    schema: "socx.querypack/v1",
    id: "test-pack",
    kind: "ioc",
    name: "Test",
    dialect: "kql",
    variables: [{ id: "range", label: "Range", default: "7d" }],
    templates: [
      {
        id: "network",
        name: "Network",
        byType: {
          IP: { field: "RemoteIP", op: "in~" },
          Domain: { field: "RemoteUrl", op: "has_any" }
        },
        body: "DeviceNetworkEvents\n| where Timestamp > ago({{var:range}})\n| where {{field}} {{op}} ({{iocs}})"
      }
    ],
    ...overrides
  }
  const result = validateQueryPack(raw, {
    knownDialects: new Set(dialects.keys())
  })
  if (!result.ok) {
    throw new Error(result.errors.map((error) => error.message).join("; "))
  }
  return result.value
}

describe("bundled dialects", () => {
  it("ships every language the community packs reference", () => {
    expect(BUNDLED_DIALECTS.length).toBeGreaterThanOrEqual(20)
    for (const id of [
      "kql",
      "spl",
      "udm",
      "logscale",
      "xql",
      "esql",
      "regex"
    ]) {
      expect(dialects.has(id)).toBe(true)
    }
  })
})

describe("escaping", () => {
  it("escapes quotes and backslashes for backslash dialects", () => {
    expect(escapeValue('a"b\\c', "backslash", '"')).toBe('a\\"b\\\\c')
  })

  it("doubles single quotes for SQL style dialects", () => {
    expect(escapeValue("O'Brien", "sql-quote", "'")).toBe("O''Brien")
  })

  it("escapes Lucene reserved characters", () => {
    expect(escapeValue("a:b(c)", "lucene", '"')).toBe("a\\:b\\(c\\)")
  })

  it("escapes regex metacharacters", () => {
    expect(escapeValue("evil.com", "regex", "")).toBe("evil\\.com")
  })

  it("leaves values alone when the dialect asks for none", () => {
    expect(escapeValue("1.2.3.4", "none", "")).toBe("1.2.3.4")
  })
})

describe("renderTemplate", () => {
  it("renders one query per bound indicator type", () => {
    const pack = buildPack()
    const outcome = renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators: [
        { value: "203.0.113.10", type: "IP" },
        { value: "198.51.100.7", type: "IP" },
        { value: "evil.com", type: "Domain" }
      ]
    })

    expect(outcome.queries).toHaveLength(2)
    const ipQuery = outcome.queries.find((query) => query.type === "IP")
    expect(ipQuery?.text).toContain(
      'where RemoteIP in~ ("203.0.113.10", "198.51.100.7")'
    )
    expect(ipQuery?.text).toContain("ago(7d)")
    const domainQuery = outcome.queries.find((query) => query.type === "Domain")
    expect(domainQuery?.text).toContain('where RemoteUrl has_any ("evil.com")')
  })

  it("reports the indicator types no binding covers", () => {
    const pack = buildPack()
    const outcome = renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators: [
        { value: "203.0.113.10", type: "IP" },
        { value: "CVE-2021-44228", type: "CVE" }
      ]
    })
    expect(outcome.uncoveredTypes).toEqual(["CVE"])
  })

  it("overrides pack variables with the analyst values", () => {
    const pack = buildPack()
    const outcome = renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators: [{ value: "203.0.113.10", type: "IP" }],
      variables: { range: "30d" }
    })
    expect(outcome.queries[0].text).toContain("ago(30d)")
  })

  it("deduplicates indicators before rendering", () => {
    const pack = buildPack()
    const outcome = renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators: [
        { value: "203.0.113.10", type: "IP" },
        { value: "203.0.113.10", type: "IP" }
      ]
    })
    expect(outcome.queries[0].count).toBe(1)
  })

  it("splits long lists into chunks", () => {
    const pack = buildPack({
      templates: [
        {
          id: "network",
          name: "Network",
          maxItems: 2,
          byType: { IP: { field: "RemoteIP", op: "in~" } },
          body: "// chunk {{chunk}}/{{chunks}} — {{count}} indicators\n| where {{field}} {{op}} ({{iocs}})"
        }
      ]
    })
    const outcome = renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators: [
        { value: "203.0.113.1", type: "IP" },
        { value: "203.0.113.2", type: "IP" },
        { value: "203.0.113.3", type: "IP" }
      ]
    })
    expect(outcome.queries).toHaveLength(2)
    expect(outcome.queries[0].text).toContain("chunk 1/2 — 2 indicators")
    expect(outcome.queries[1].count).toBe(1)
  })

  it("drops private addresses when the template asks for it", () => {
    const pack = buildPack({
      templates: [
        {
          id: "egress",
          name: "Egress",
          excludePrivate: true,
          byType: { IP: { field: "RemoteIP", op: "in~" } },
          body: "| where {{field}} {{op}} ({{iocs}})"
        }
      ]
    })
    const outcome = renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators: [
        { value: "10.0.0.5", type: "IP" },
        { value: "192.168.1.1", type: "IP" },
        { value: "203.0.113.10", type: "IP" }
      ]
    })
    expect(outcome.queries[0].text).toBe(
      '| where RemoteIP in~ ("203.0.113.10")'
    )
  })

  it("renders an indicator free template once", () => {
    const pack = buildPack({
      kind: "standard",
      templates: [
        {
          id: "encoded",
          name: "Encoded PowerShell",
          requiresIocs: false,
          body: "DeviceProcessEvents | where Timestamp > ago({{var:range}})"
        }
      ]
    })
    const outcome = renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators: []
    })
    expect(outcome.queries).toHaveLength(1)
    expect(outcome.queries[0].text).toContain("ago(7d)")
  })

  it("flags a query that exceeds the dialect length budget", () => {
    const pack = buildPack()
    const indicators = Array.from({ length: 100 }, (_, index) => ({
      value: `203.0.113.${index}`.padEnd(120, "x"),
      type: "IP" as const
    }))
    const outcome = renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators
    })
    expect(outcome.queries.some((query) => query.overLength)).toBe(true)
  })
})

describe("dialect specific list rendering", () => {
  const render = (dialect: string, body: string, extra: any = {}) => {
    const pack = buildPack({
      dialect,
      templates: [
        {
          id: "t",
          name: "T",
          byType: { IP: { field: "dest", op: "=", ...extra } },
          body
        }
      ]
    })
    return renderTemplate({
      template: pack.templates[0],
      pack,
      dialects,
      indicators: [
        { value: "203.0.113.1", type: "IP" },
        { value: "203.0.113.2", type: "IP" }
      ]
    }).queries[0].text
  }

  it("joins with OR for or-expansion dialects", () => {
    expect(render("lucene", "{{field}}:({{iocs}})")).toBe(
      'dest:("203.0.113.1" OR "203.0.113.2")'
    )
  })

  it("repeats the field for or-values", () => {
    expect(render("udm", "({{iocs|or-values}})")).toBe(
      '(dest = "203.0.113.1" OR dest = "203.0.113.2")'
    )
  })

  it("honours a per binding suffix", () => {
    expect(render("udm", "({{iocs|or-values}})", { suffix: "nocase" })).toBe(
      '(dest = "203.0.113.1" nocase OR dest = "203.0.113.2" nocase)'
    )
  })

  it("accepts a field override on or-values", () => {
    expect(render("udm", "({{iocs|or-values:principal.ip}})")).toBe(
      '(principal.ip = "203.0.113.1" OR principal.ip = "203.0.113.2")'
    )
  })

  it("builds an escaped alternation for the regex filter", () => {
    expect(render("regex", "grep -E '{{iocs|regex}}'")).toBe(
      "grep -E '(203\\.0\\.113\\.1|203\\.0\\.113\\.2)'"
    )
  })

  it("emits unquoted comma separated meta for NetWitness", () => {
    expect(render("nwql", "ip.dst = {{iocs}}")).toBe(
      "ip.dst = 203.0.113.1,203.0.113.2"
    )
  })

  it("uses SQL quoting for Ariel", () => {
    expect(render("aql", "WHERE sourceip IN ({{iocs}})")).toBe(
      "WHERE sourceip IN ('203.0.113.1', '203.0.113.2')"
    )
  })
})

describe("renderSelection", () => {
  it("only reports a type as uncovered when no template binds it", () => {
    const packA = buildPack()
    const packB = buildPack({
      id: "cve-pack",
      templates: [
        {
          id: "cve",
          name: "CVE",
          byType: { CVE: { field: "CveId", op: "in~" } },
          body: "| where {{field}} {{op}} ({{iocs}})"
        }
      ]
    })

    const outcome = renderSelection({
      templates: [
        { template: packA.templates[0], pack: packA },
        { template: packB.templates[0], pack: packB }
      ],
      dialects,
      indicators: [
        { value: "203.0.113.10", type: "IP" },
        { value: "CVE-2021-44228", type: "CVE" },
        { value: "user@example.com", type: "Email" }
      ]
    })

    expect(outcome.queries).toHaveLength(2)
    expect(outcome.uncoveredTypes).toEqual(["Email"])
  })
})

describe("toBindableType", () => {
  it("resolves the hash algorithm from the length", () => {
    expect(toBindableType("Hash", "d41d8cd98f00b204e9800998ecf8427e")).toBe(
      "MD5"
    )
    expect(toBindableType("Hash", "a".repeat(40))).toBe("SHA1")
    expect(toBindableType("Hash", "a".repeat(64))).toBe("SHA256")
  })

  it("maps private IPs onto the IP binding", () => {
    expect(toBindableType("Private IP", "10.0.0.1")).toBe("IP")
  })

  it("returns null for anything a template cannot bind", () => {
    expect(toBindableType(null, "x")).toBeNull()
    expect(toBindableType("Something", "x")).toBeNull()
  })
})

describe("chunkValues", () => {
  it("never returns an empty chunk", () => {
    expect(chunkValues([], 10)).toEqual([])
    expect(chunkValues(["a", "b", "c"], 2)).toEqual([["a", "b"], ["c"]])
  })
})
