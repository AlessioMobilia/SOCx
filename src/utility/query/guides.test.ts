import { describe, expect, it } from "vitest"

import { filterQueryLanguageGuides, QUERY_LANGUAGE_GUIDES } from "./guides"
import { bundledDialectMap } from "./render"

describe("query language guides", () => {
  it("covers every bundled dialect exactly once", () => {
    const dialectIds = [...bundledDialectMap().keys()].sort()
    const guideIds = QUERY_LANGUAGE_GUIDES.map((guide) => guide.dialectId)

    expect(new Set(guideIds).size).toBe(guideIds.length)
    expect([...guideIds].sort()).toEqual(dialectIds)
  })

  it("provides useful content and an HTTPS documentation link", () => {
    for (const guide of QUERY_LANGUAGE_GUIDES) {
      expect(guide.summary.length).toBeGreaterThan(20)
      expect(guide.fields.length).toBeGreaterThanOrEqual(3)
      expect(guide.commands.length).toBeGreaterThanOrEqual(4)
      expect(new URL(guide.documentationUrl).protocol).toBe("https:")
    }
  })

  it("searches commands and associated product names", () => {
    expect(
      filterQueryLanguageGuides(
        QUERY_LANGUAGE_GUIDES,
        "all",
        "stats",
        () => ""
      ).map((guide) => guide.dialectId)
    ).toContain("spl")

    expect(
      filterQueryLanguageGuides(
        QUERY_LANGUAGE_GUIDES,
        "all",
        "Cortex XSIAM",
        (dialectId) =>
          bundledDialectMap().get(dialectId)?.vendors?.join(" ") ?? ""
      ).map((guide) => guide.dialectId)
    ).toEqual(["xql"])
  })

  it("combines language and command filters", () => {
    expect(
      filterQueryLanguageGuides(
        QUERY_LANGUAGE_GUIDES,
        "regex",
        "alternation",
        () => ""
      ).map((guide) => guide.dialectId)
    ).toEqual(["regex"])

    expect(
      filterQueryLanguageGuides(
        QUERY_LANGUAGE_GUIDES,
        "regex",
        "stats",
        () => ""
      )
    ).toEqual([])
  })
})
