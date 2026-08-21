import { describe, expect, it } from "vitest"

import {
  buildPack,
  deriveGroups,
  importPackIntoLibrary,
  suggestTemplateId,
  type UserQueryTemplate
} from "./builder"
import { buildGroupTree, flattenGroupTree } from "./groups"
import { validatePackIndex, validateQueryPack } from "./packSchema"
import {
  dialectSelectionTag,
  hashPackContent,
  isAllowedPackSourceUrl,
  isPlainHttpPackSourceUrl,
  isSelectedDialect,
  looksLikeHtmlResponse,
  resolveIncludeUrl,
  resolvePackUrl,
  toRawPackUrl
} from "./packSources"
import {
  applyIndexMetadata,
  applyIndexVerification,
  describeFetchFailure
} from "./registry"

const knownDialects = new Set(["kql", "spl"])

const validPack = {
  schema: "socx.querypack/v1",
  id: "demo-ioc",
  kind: "ioc",
  name: "Demo",
  dialect: "kql",
  variables: [{ id: "range", label: "Time range", default: "7d" }],
  groups: [
    {
      id: "network",
      label: "Network",
      order: 10,
      children: [{ id: "egress", label: "Egress" }]
    }
  ],
  templates: [
    {
      id: "network-contact",
      name: "Connections",
      group: "network/egress",
      byType: { IP: { field: "RemoteIP", op: "in~" } },
      body: "DeviceNetworkEvents | where Timestamp > ago({{var:range}}) | where {{field}} {{op}} ({{iocs}})"
    }
  ]
}

describe("validateQueryPack", () => {
  it("accepts a well formed pack", () => {
    const result = validateQueryPack(validPack, { knownDialects })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.templates[0].requiresIocs).toBe(true)
      expect(result.warnings).toHaveLength(0)
    }
  })

  it("rejects an unknown dialect", () => {
    const result = validateQueryPack(
      { ...validPack, dialect: "made-up" },
      { knownDialects }
    )
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.errors[0].message).toContain("made-up")
    }
  })

  it("rejects unknown placeholders and filters", () => {
    const result = validateQueryPack(
      {
        ...validPack,
        templates: [
          {
            ...validPack.templates[0],
            body: "{{iocs|explode}} {{mystery}}"
          }
        ]
      },
      { knownDialects }
    )
    expect(result.ok).toBe(false)
    if (!result.ok) {
      const messages = result.errors.map((error) => error.message).join(" ")
      expect(messages).toContain("explode")
      expect(messages).toContain("mystery")
    }
  })

  it("rejects an undeclared variable", () => {
    const result = validateQueryPack(
      {
        ...validPack,
        variables: [],
        templates: [validPack.templates[0]]
      },
      { knownDialects }
    )
    expect(result.ok).toBe(false)
  })

  it("rejects malformed and duplicate variable ids", () => {
    const malformed = validateQueryPack(
      { ...validPack, variables: [{ id: "Bad id", label: "Bad" }] },
      { knownDialects }
    )
    const duplicate = validateQueryPack(
      {
        ...validPack,
        variables: [
          { id: "range", label: "Range" },
          { id: "range", label: "Range again" }
        ]
      },
      { knownDialects }
    )
    expect(malformed.ok).toBe(false)
    expect(duplicate.ok).toBe(false)
  })

  it("validates checkbox variables as boolean string inputs", () => {
    const checkbox = { id: "range", label: "Summaries only", type: "checkbox" }
    const valid = validateQueryPack(
      {
        ...validPack,
        variables: [{ ...checkbox, default: "true" }]
      },
      { knownDialects }
    )
    const invalidDefault = validateQueryPack(
      {
        ...validPack,
        variables: [{ ...checkbox, default: "yes" }]
      },
      { knownDialects }
    )
    const invalidOptions = validateQueryPack(
      {
        ...validPack,
        variables: [{ ...checkbox, default: "false", options: ["yes", "no"] }]
      },
      { knownDialects }
    )

    expect(valid.ok).toBe(true)
    if (valid.ok) {
      expect(valid.value.variables?.[0]).toMatchObject({
        type: "checkbox",
        default: "true"
      })
    }
    expect(invalidDefault.ok).toBe(false)
    expect(invalidOptions.ok).toBe(false)
  })

  it("rejects an ioc template that never renders its indicators", () => {
    const result = validateQueryPack(
      {
        ...validPack,
        templates: [{ ...validPack.templates[0], body: "DeviceNetworkEvents" }]
      },
      { knownDialects }
    )
    expect(result.ok).toBe(false)
  })

  it("keeps a template whose group is not declared, with a warning", () => {
    const result = validateQueryPack(
      {
        ...validPack,
        templates: [{ ...validPack.templates[0], group: "typo/here" }]
      },
      { knownDialects }
    )
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.warnings).toHaveLength(1)
      expect(result.value.templates).toHaveLength(1)
    }
  })

  it("refuses a standard template inside an ioc pack", () => {
    const result = validateQueryPack(
      {
        ...validPack,
        templates: [
          {
            id: "standing",
            name: "No indicators",
            requiresIocs: false,
            body: "DeviceEvents"
          }
        ]
      },
      { knownDialects }
    )
    expect(result.ok).toBe(false)
  })
})

describe("validatePackIndex", () => {
  it("rejects a pack path that escapes the index location", () => {
    const result = validatePackIndex({
      schema: "socx.packindex/v1",
      packs: [{ id: "evil", kind: "ioc", path: "../../etc/passwd" }]
    })
    expect(result.ok).toBe(false)
  })

  it("accepts a normal index", () => {
    const result = validatePackIndex({
      schema: "socx.packindex/v1",
      dialects: "dialects/dialects.json",
      packs: [
        {
          id: "demo-ioc",
          kind: "ioc",
          name: "Demo",
          dialect: "kql",
          path: "packs/ioc/demo.json"
        }
      ]
    })
    expect(result.ok).toBe(true)
  })
})

describe("catalogues split across files", () => {
  it("accepts an index that only links to other indexes", () => {
    const result = validatePackIndex({
      schema: "socx.packindex/v1",
      includes: ["customers/acme.json", "https://intranet.example/hunting.json"]
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.includes).toHaveLength(2)
    expect(result.value.packs).toEqual([])
  })

  it("accepts an include served over plain HTTP", () => {
    const result = validatePackIndex({
      schema: "socx.packindex/v1",
      includes: ["http://intranet.example/packs.json"]
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.includes).toEqual([
      "http://intranet.example/packs.json"
    ])
  })

  it("refuses a protocol relative path that would change host", () => {
    expect(
      validatePackIndex({
        schema: "socx.packindex/v1",
        includes: ["//attacker.example/index.json"]
      }).ok
    ).toBe(false)
    const entry = validatePackIndex({
      schema: "socx.packindex/v1",
      packs: [
        {
          id: "demo",
          kind: "ioc",
          dialect: "kql",
          path: "//attacker.example/pack.json"
        }
      ]
    })
    expect(entry.ok).toBe(false)
    if (entry.ok) return
    expect(entry.errors[0].message).toMatch(/unsafe pack path/)
  })

  it("refuses an include on another scheme or one climbing out of the tree", () => {
    expect(
      validatePackIndex({
        schema: "socx.packindex/v1",
        includes: ["ftp://intranet.example/packs.json"]
      }).ok
    ).toBe(false)
    expect(
      validatePackIndex({
        schema: "socx.packindex/v1",
        includes: ["../../etc/passwd.json"]
      }).ok
    ).toBe(false)
  })

  it("resolves includes against the index that named them", () => {
    expect(
      resolveIncludeUrl("https://example.test/a/index.json", "b/other.json")
    ).toBe("https://example.test/a/b/other.json")
    expect(
      resolveIncludeUrl(
        "https://example.test/a/index.json",
        "https://other.test/index.json"
      )
    ).toBe("https://other.test/index.json")
    expect(() =>
      resolveIncludeUrl("https://example.test/index.json", "ftp://x/y.json")
    ).toThrow()
  })

  it("carries the facets and labels declared by the index onto the pack", () => {
    const parsed = validateQueryPack(validPack, { knownDialects })
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return

    const pack = applyIndexMetadata(
      {
        id: parsed.value.id,
        kind: parsed.value.kind,
        name: parsed.value.name,
        dialect: parsed.value.dialect,
        path: "packs/demo.json",
        labels: { customer: ["ACME"] }
      },
      validPack,
      parsed.value,
      [[{ id: "customer", label: "Customer" }]]
    )
    expect(pack.labels?.customer).toEqual(["ACME"])
    expect(pack.facets?.[0]).toEqual({ id: "customer", label: "Customer" })
  })
})

describe("technology selection", () => {
  it("imports everything when nothing is selected", () => {
    expect(isSelectedDialect({}, "kql")).toBe(true)
    expect(isSelectedDialect({ dialects: [] }, "kql")).toBe(true)
  })

  it("keeps only the selected languages", () => {
    expect(isSelectedDialect({ dialects: ["kql", "spl"] }, "kql")).toBe(true)
    expect(isSelectedDialect({ dialects: ["kql", "spl"] }, "aql")).toBe(false)
  })

  it("defers the decision when the index does not name the language", () => {
    expect(isSelectedDialect({ dialects: ["kql"] }, "unknown")).toBe(true)
    expect(isSelectedDialect({ dialects: ["kql"] }, undefined)).toBe(true)
  })

  it("fingerprints the selection so a change re-pins the source", () => {
    expect(dialectSelectionTag({ dialects: ["spl", "kql"] })).toBe("kql,spl")
    expect(dialectSelectionTag({})).toBe("all")
  })
})

describe("catalogue verification", () => {
  it("inherits verification from the index when the pack omits it", () => {
    const result = validateQueryPack(validPack, { knownDialects })
    expect(result.ok).toBe(true)
    if (!result.ok) return

    const pack = applyIndexVerification(
      { id: "demo-ioc", verified: true },
      validPack,
      result.value
    )
    expect(pack.verified).toBe(true)
  })

  it("rejects an explicit contradiction between index and pack", () => {
    const rawPack = { ...validPack, verified: false }
    const result = validateQueryPack(rawPack, { knownDialects })
    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(() =>
      applyIndexVerification(
        { id: "demo-ioc", verified: true },
        rawPack,
        result.value
      )
    ).toThrow(/verification status/)
  })
})

describe("source URL handling", () => {
  it("rewrites GitHub blob links to raw", () => {
    expect(
      toRawPackUrl("https://github.com/org/repo/blob/main/packs/ioc/a.json").url
    ).toBe("https://raw.githubusercontent.com/org/repo/main/packs/ioc/a.json")
  })

  it("rewrites GitLab blob links on any host", () => {
    expect(
      toRawPackUrl("https://gitlab.corp.local/team/proj/-/blob/main/pack.json")
        .url
    ).toBe("https://gitlab.corp.local/team/proj/-/raw/main/pack.json")
  })

  it("leaves an already raw URL alone", () => {
    const raw = "https://raw.githubusercontent.com/org/repo/main/index.json"
    expect(toRawPackUrl(raw)).toEqual({ url: raw, rewritten: false })
  })

  it("recognises an HTML response", () => {
    expect(looksLikeHtmlResponse("<!DOCTYPE html><html></html>")).toBe(true)
    expect(looksLikeHtmlResponse('{"schema":"x"}')).toBe(false)
  })

  it("resolves pack paths against the index URL", () => {
    expect(
      resolvePackUrl(
        "https://raw.githubusercontent.com/org/repo/main/index.json",
        "packs/ioc/a.json"
      )
    ).toBe("https://raw.githubusercontent.com/org/repo/main/packs/ioc/a.json")
  })

  it("accepts HTTP and HTTPS sources and refuses every other scheme", () => {
    expect(isAllowedPackSourceUrl("https://example.com/index.json")).toBe(true)
    expect(isAllowedPackSourceUrl("http://intranet.example/index.json")).toBe(
      true
    )
    expect(isAllowedPackSourceUrl("ftp://example.com/index.json")).toBe(false)
    expect(isAllowedPackSourceUrl("file:///etc/passwd")).toBe(false)
    expect(isAllowedPackSourceUrl("javascript:alert(1)")).toBe(false)
    expect(isAllowedPackSourceUrl("not a url")).toBe(false)
  })

  it("flags a source fetched in clear text", () => {
    expect(isPlainHttpPackSourceUrl("http://intranet.example/index.json")).toBe(
      true
    )
    expect(isPlainHttpPackSourceUrl("https://example.com/index.json")).toBe(
      false
    )
    expect(isPlainHttpPackSourceUrl("nonsense")).toBe(false)
  })

  it("keeps pack paths on the origin, scheme included", () => {
    expect(() =>
      resolvePackUrl(
        "https://example.com/index.json",
        "https://attacker.example/pack.json"
      )
    ).toThrow(/source origin/)
    // An HTTPS catalogue cannot be downgraded to plain HTTP, nor the reverse.
    expect(() =>
      resolvePackUrl(
        "https://example.com/index.json",
        "http://example.com/pack.json"
      )
    ).toThrow(/source origin/)
    expect(
      resolvePackUrl("http://intranet.example/index.json", "packs/a.json")
    ).toBe("http://intranet.example/packs/a.json")
  })

  it("resolves an include over plain HTTP", () => {
    expect(
      resolveIncludeUrl("http://intranet.example/index.json", "team/other.json")
    ).toBe("http://intranet.example/team/other.json")
    expect(
      resolveIncludeUrl(
        "https://example.test/index.json",
        "http://intranet.example/index.json"
      )
    ).toBe("http://intranet.example/index.json")
  })

  it("explains a failed plain HTTP fetch", () => {
    expect(
      describeFetchFailure(
        new TypeError("Failed to fetch"),
        "http://intranet.example/index.json"
      )
    ).toMatch(/plain HTTP/)
    // An HTTPS failure keeps the original message, and so does an HTTP error
    // the server itself answered with.
    expect(
      describeFetchFailure(
        new TypeError("Failed to fetch"),
        "https://example.com/index.json"
      )
    ).toBe("Failed to fetch")
    expect(
      describeFetchFailure(
        new Error("HTTP 404"),
        "http://intranet.example/index.json"
      )
    ).toBe("HTTP 404")
  })

  it("pins content with a SHA-256 digest", async () => {
    await expect(hashPackContent("catalogue")).resolves.toMatch(
      /^[a-f0-9]{64}$/
    )
  })
})

describe("group tree", () => {
  it("merges declared groups and synthesises the missing ones", () => {
    const packA = validateQueryPack(validPack, { knownDialects })
    const packB = validateQueryPack(
      {
        ...validPack,
        id: "demo-two",
        templates: [
          {
            id: "orphan",
            name: "Orphan query",
            group: "identity/logons",
            byType: { IP: { field: "IPAddress", op: "in~" } },
            body: "IdentityLogonEvents | where {{field}} {{op}} ({{iocs}})"
          }
        ]
      },
      { knownDialects }
    )

    expect(packA.ok && packB.ok).toBe(true)
    if (!packA.ok || !packB.ok) return

    const tree = buildGroupTree([packA.value, packB.value])
    const network = tree.find((node) => node.id === "network")
    const identity = tree.find((node) => node.id === "identity")

    expect(network?.label).toBe("Network")
    expect(network?.children[0].templates).toHaveLength(1)
    expect(identity?.synthesised).toBe(true)
    expect(identity?.label).toBe("Identity")
    expect(identity?.children[0].label).toBe("Logons")
    expect(flattenGroupTree(tree)).toHaveLength(2)
  })

  it("puts templates with no group into Uncategorised", () => {
    const pack = validateQueryPack(
      {
        ...validPack,
        templates: [{ ...validPack.templates[0], group: undefined }]
      },
      { knownDialects }
    )
    expect(pack.ok).toBe(true)
    if (!pack.ok) return
    const tree = buildGroupTree([pack.value])
    expect(tree.some((node) => node.id === "uncategorised")).toBe(true)
  })
})

describe("rule builder", () => {
  const now = new Date().toISOString()
  const library: UserQueryTemplate[] = [
    {
      id: "internal-egress",
      name: "Internal egress check",
      dialect: "kql",
      kind: "ioc",
      group: "network/egress",
      byType: { IP: { field: "RemoteIP", op: "in~" } },
      body: "DeviceNetworkEvents | where {{field}} {{op}} ({{iocs}})",
      createdAt: now,
      updatedAt: now
    },
    {
      id: "spl-egress",
      name: "Splunk egress check",
      dialect: "spl",
      kind: "ioc",
      group: "network",
      byType: { IP: { field: "dest_ip", op: "IN" } },
      body: "index=* {{field}} {{op}} ({{iocs}})",
      createdAt: now,
      updatedAt: now
    },
    {
      id: "encoded-powershell",
      name: "Encoded PowerShell",
      dialect: "kql",
      kind: "standard",
      group: "execution",
      body: 'DeviceProcessEvents | where ProcessCommandLine has "-enc"',
      createdAt: now,
      updatedAt: now
    }
  ]

  it("exports a valid ioc pack and keeps the minority dialect per template", () => {
    const result = buildPack(
      library,
      "ioc",
      { id: "Team pack", name: "Team pack" },
      { knownDialects }
    )
    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.pack.kind).toBe("ioc")
    expect(result.pack.dialect).toBe("kql")
    expect(result.pack.templates).toHaveLength(2)
    expect(result.pack.templates[0].dialect).toBeUndefined()
    expect(result.pack.templates[1].dialect).toBe("spl")
    expect(result.pack.id).toBe("team-pack")
    expect(JSON.parse(result.json).schema).toBe("socx.querypack/v1")
  })

  it("declares every group the templates reference", () => {
    const result = buildPack(
      library,
      "ioc",
      { id: "team", name: "Team" },
      { knownDialects }
    )
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const network = result.pack.groups?.find((group) => group.id === "network")
    expect(network?.children?.[0].id).toBe("egress")
  })

  it("exports the standard templates separately", () => {
    const result = buildPack(
      library,
      "standard",
      { id: "team", name: "Team" },
      { knownDialects }
    )
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.pack.templates).toHaveLength(1)
    expect(result.pack.templates[0].requiresIocs).toBe(false)
  })

  it("preserves variables when a pack is imported and exported", () => {
    const imported = importPackIntoLibrary(validPack, [], { knownDialects })
    expect(imported.errors).toHaveLength(0)
    expect(imported.templates[0].variables?.[0].id).toBe("range")

    const exported = buildPack(
      imported.templates,
      "ioc",
      { id: "round-trip", name: "Round trip" },
      { knownDialects }
    )
    expect(exported.ok).toBe(true)
    if (exported.ok) {
      expect(exported.pack.variables?.[0].default).toBe("7d")
    }
  })

  it("reports when there is nothing of that kind to export", () => {
    const result = buildPack(
      [],
      "ioc",
      { id: "team", name: "Team" },
      { knownDialects }
    )
    expect(result.ok).toBe(false)
  })

  it("suggests unique template ids", () => {
    expect(suggestTemplateId("Failed logons")).toBe("failed-logons")
    expect(suggestTemplateId("Failed logons", ["failed-logons"])).toBe(
      "failed-logons-2"
    )
  })

  it("derives nested groups from template paths", () => {
    const groups = deriveGroups([
      { group: "identity/logons" },
      { group: "network" }
    ])
    expect(groups.map((group) => group.id).sort()).toEqual([
      "identity",
      "network"
    ])
    expect(
      groups.find((group) => group.id === "identity")?.children?.[0].label
    ).toBe("Logons")
  })
})
