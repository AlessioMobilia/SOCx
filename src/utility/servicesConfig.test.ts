import { describe, expect, it } from "vitest"

import { servicesConfig } from "./servicesConfig"

describe("IOC service catalog", () => {
  it("exposes the new public providers for their supported IOC types", () => {
    expect(servicesConfig.availableServices.IP).toEqual(
      expect.arrayContaining([
        "CiscoTalos",
        "URLhaus",
        "Spamhaus",
        "RIPEstat",
        "ThreatMiner"
      ])
    )
    expect(servicesConfig.availableServices.Domain).toEqual(
      expect.arrayContaining(["CloudflareRadar", "CTSearch"])
    )
    expect(servicesConfig.availableServices.Hash).toContain("CIRCLHashlookup")
  })

  it("builds encoded direct lookup URLs", () => {
    expect(
      servicesConfig.services.CiscoTalos.url(
        "URL",
        "https://example.com/path?a=1"
      )
    ).toContain("search=https%3A%2F%2Fexample.com%2Fpath%3Fa%3D1")
    expect(servicesConfig.services.RIPEstat.url("ASN", "AS13335")).toBe(
      "https://stat.ripe.net/resource/AS13335"
    )
    expect(
      servicesConfig.services.CIRCLHashlookup.url("Hash", "a".repeat(40))
    ).toContain("/lookup/sha1/")
  })
})
