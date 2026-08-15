import { describe, expect, it } from "vitest"

import { extractCVEs, extractIOCs, identifyIOC } from "./utils"

describe("CVE IOC detection", () => {
  it("recognizes CVE identifiers case-insensitively", () => {
    expect(identifyIOC("CVE-2021-44228")).toBe("CVE")
    expect(identifyIOC("cve-2024-12345")).toBe("CVE")
    expect(identifyIOC("CVE-24-1234")).toBeNull()
  })

  it("extracts and canonicalizes CVEs in mixed IOC text", () => {
    expect(extractIOCs("Review cve-2021-44228 and 8.8.8.8")).toEqual([
      "CVE-2021-44228",
      "8.8.8.8"
    ])
    expect(extractCVEs("cve-2021-44228, CVE-2024-12345")).toEqual([
      "CVE-2021-44228",
      "CVE-2024-12345"
    ])
  })
})
