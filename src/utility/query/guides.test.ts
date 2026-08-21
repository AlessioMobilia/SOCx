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
      expect(guide.commands.length).toBeGreaterThanOrEqual(8)
      expect(new Set(guide.commands.map((command) => command.term)).size).toBe(
        guide.commands.length
      )
      for (const command of guide.commands) {
        expect(command.description.length).toBeGreaterThan(20)
        expect(command.syntax.length).toBeGreaterThan(0)
        expect(command.options.length).toBeGreaterThanOrEqual(2)
        expect(command.example.length).toBeGreaterThan(0)
      }
      expect(new URL(guide.documentationUrl).protocol).toBe("https:")
    }
    expect(
      QUERY_LANGUAGE_GUIDES.reduce(
        (count, guide) => count + guide.commands.length,
        0
      )
    ).toBeGreaterThanOrEqual(180)
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
        "null placement",
        () => ""
      ).map((guide) => guide.dialectId)
    ).toContain("kql")

    expect(
      filterQueryLanguageGuides(
        QUERY_LANGUAGE_GUIDES,
        "esql",
        "related.ip",
        () => ""
      ).map((guide) => guide.dialectId)
    ).toEqual(["esql"])

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
