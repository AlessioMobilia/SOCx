import { describe, expect, it } from "vitest"

import { buildMagicIocUrls } from "./magic-ioc"

describe("buildMagicIocUrls", () => {
  it("combines built-in and custom services for the IOC type", () => {
    const urls = buildMagicIocUrls(
      "IP",
      "8.8.8.8",
      { IP: ["VirusTotal", "AbuseIPDB"] },
      [
        {
          type: "IP",
          name: "Internal SIEM",
          url: "https://siem/search?q={ioc}"
        },
        { type: "Domain", name: "Ignored", url: "https://x/{ioc}" }
      ]
    )

    expect(urls).toEqual([
      "https://www.virustotal.com/gui/ip-address/8.8.8.8",
      "https://www.abuseipdb.com/check/8.8.8.8",
      "https://siem/search?q=8.8.8.8"
    ])
  })

  it("drops services that cannot handle the type and duplicated URLs", () => {
    const urls = buildMagicIocUrls(
      "CVE",
      "CVE-2021-44228",
      {
        CVE: ["NVD", "AbuseIPDB", "NVD"]
      },
      []
    )

    expect(urls).toEqual(["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"])
  })

  it("returns nothing when no service is configured", () => {
    expect(buildMagicIocUrls("MAC", "00:11:22:33:44:55", {}, [])).toEqual([])
  })
})
