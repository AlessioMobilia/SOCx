import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

import {
  validatePackIndex,
  validateQueryPack,
  type BindableIocType
} from "./packSchema"
import { applyIndexVerification } from "./registry"
import { bundledDialectMap, renderTemplate } from "./render"

// Optional release audit. Point this at a checkout of socx-query-packs to run
// every published template through the extension's own parser and renderer.
const CATALOG_ROOT = process.env.SOCX_QUERY_PACK_AUDIT_DIR

const SAMPLE_BY_TYPE: Record<BindableIocType, string> = {
  IP: "203.0.113.10",
  Domain: "example.test",
  URL: "https://example.test/CaseSensitivePath",
  Email: "analyst@example.test",
  ASN: "AS64496",
  MAC: "00:11:22:33:44:55",
  CVE: "CVE-2021-44228",
  Hash: "b".repeat(64),
  SHA256: "a".repeat(64),
  SHA1: "a".repeat(40),
  MD5: "a".repeat(32)
}

describe.runIf(Boolean(CATALOG_ROOT))("published query catalogue", () => {
  it("validates and renders every declared template", () => {
    const root = resolve(CATALOG_ROOT!)
    const indexRaw = JSON.parse(
      readFileSync(resolve(root, "index.json"), "utf8")
    )
    const index = validatePackIndex(indexRaw)
    expect(
      index.ok,
      index.errors.map((issue) => issue.message).join("; ")
    ).toBe(true)
    if (!index.ok) return

    const dialects = bundledDialectMap()
    let templateCount = 0

    for (const entry of index.value.packs) {
      const packPath = resolve(root, entry.path)
      expect(packPath.startsWith(root)).toBe(true)
      const parsed = JSON.parse(readFileSync(packPath, "utf8"))
      const validated = validateQueryPack(parsed, {
        knownDialects: new Set(dialects.keys())
      })
      expect(
        validated.ok,
        validated.errors
          .map((issue) => `${issue.path}: ${issue.message}`)
          .join("; ")
      ).toBe(true)
      if (!validated.ok) continue

      const pack = applyIndexVerification(entry, parsed, validated.value)
      expect(pack.id).toBe(entry.id)
      expect(pack.kind).toBe(entry.kind)
      if (typeof entry.verified === "boolean") {
        expect(pack.verified).toBe(entry.verified)
      }
      expect(pack.templates).toHaveLength(
        entry.templates ?? pack.templates.length
      )
      expect(validated.warnings).toHaveLength(0)
      templateCount += pack.templates.length

      for (const template of pack.templates) {
        const indicators = Object.keys(template.byType ?? {}).map((type) => ({
          type: type as BindableIocType,
          value: SAMPLE_BY_TYPE[type as BindableIocType]
        }))
        const outcome = renderTemplate({
          template,
          pack,
          dialects,
          indicators
        })
        expect(outcome.errors, `${pack.id}/${template.id}`).toHaveLength(0)
        expect(
          outcome.queries.length,
          `${pack.id}/${template.id}`
        ).toBeGreaterThan(0)
        for (const query of outcome.queries) {
          expect(query.text.trim(), `${pack.id}/${template.id}`).not.toBe("")
          expect(query.text, `${pack.id}/${template.id}`).not.toMatch(
            /\{\{[^}]+\}\}/
          )
          expect(query.text, `${pack.id}/${template.id}`).not.toContain(
            "undefined"
          )
        }
      }
    }

    expect(templateCount).toBe(
      index.value.packs.reduce(
        (total, entry) => total + (entry.templates ?? 0),
        0
      )
    )
  })
})
